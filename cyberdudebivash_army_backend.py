"""
CYBERDUDEBIVASH AI SECURITY HUB — ARMY Backend v185.1
Production-grade FastAPI backend with CVSS scoring, IOC validation,
report engine, ingestion pipeline, STIX export, rate limiting, and CORS.
"""

from __future__ import annotations
import os
import re
import json
import hashlib
import asyncio
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum
from functools import lru_cache

from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
import uvicorn

# ============================================================================
# CONSTANTS & CONFIG
# ============================================================================

APP_NAME = "CYBERDUDEBIVASH-AI-SECURITY-HUB-ARMY"
VERSION = "185.1"

# Rate limits
FREE_TIER_DAILY = 100
FREE_TIER_PER_MIN = 10
STARTER_TIER_DAILY = 2000
STARTER_TIER_PER_MIN = 30

# IOC validation
_MIN_IOC_LENGTH = 4
_MAX_IOC_LENGTH = 2048

# ============================================================================
# ENUMS
# ============================================================================

class Severity(str, Enum):
    UNKNOWN = "UNKNOWN"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

# ============================================================================
# SEVERITY MAPPER — P0-2 FIX
# ============================================================================

def map_cvss_to_severity(score: Optional[float]) -> Severity:
    """NIST CVSS v3.1 severity mapping. NEVER override CVSS with source heuristics."""
    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 0.1:
        return Severity.LOW
    return Severity.INFO


def compute_composite_risk(
    cvss: Optional[float],
    epss: Optional[float],
    kev: bool,
    ioc_count: int,
) -> dict:
    """
    Composite score that RESPECTS CVSS floor.
    KEV+high EPSS without CVSS gets proper floor.
    """
    # Base from CVSS or EPSS/KEV heuristics
    if cvss is not None:
        base = cvss
    else:
        base = 0.0
        if epss is not None:
            base += epss * 5.0  # EPSS 0-1 -> 0-5
        if kev:
            base += 2.0

    # Modifiers
    epss_boost = 0.0
    if epss is not None:
        if epss > 0.5:
            epss_boost = 1.5
        elif epss > 0.1:
            epss_boost = 0.5

    kev_boost = 1.0 if kev else 0.0
    ioc_boost = 0.5 if ioc_count > 0 else 0.0

    raw = base + epss_boost + kev_boost + ioc_boost
    risk = min(10.0, raw)

    # FLOOR RULES
    if cvss is not None:
        if cvss >= 9.0:
            risk = max(risk, 7.0)
        elif cvss >= 7.0:
            risk = max(risk, 5.0)
        elif cvss >= 4.0:
            risk = max(risk, max(cvss - 1.5, 2.0))
        else:
            risk = max(risk, max(cvss - 2.0, 0.5))
    else:
        # No CVSS: use KEV + EPSS heuristics — FIX #1 applied
        if kev and epss is not None and epss >= 0.5:
            risk = max(risk, 9.0)   # CRITICAL floor for active + high-prob exploitation
        elif kev:
            risk = max(risk, 5.0)   # HIGH floor
        elif epss is not None and epss >= 0.5:
            risk = max(risk, 4.0)   # MEDIUM floor
        elif epss is not None and epss >= 0.1:
            risk = max(risk, 2.0)   # LOW floor
        else:
            risk = max(risk, 0.5)   # INFO floor

    severity = map_cvss_to_severity(risk)

    # Override: if no CVSS and no KEV and no EPSS, force UNKNOWN
    if cvss is None and not kev and epss is None:
        severity = Severity.UNKNOWN

    return {
        "risk_score": round(risk, 1),
        "severity": severity.value,
        "cvss": cvss,
        "epss": epss,
        "kev": kev,
        "components": {
            "cvss_base": cvss,
            "epss_boost": epss_boost,
            "kev_boost": kev_boost,
            "ioc_boost": ioc_boost,
        },
    }


# ============================================================================
# IOC VALIDATOR — P0-3 FIX
# ============================================================================

_IOC_PATTERNS = {
    "ip": re.compile(r"^(\d{1,3}\.){3}\d{1,3}$"),
    "domain": re.compile(r"^(?!CVE-)[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}$"),
    "hash_md5": re.compile(r"^[a-f0-9]{32}$"),
    "hash_sha1": re.compile(r"^[a-f0-9]{40}$"),
    "hash_sha256": re.compile(r"^[a-f0-9]{64}$"),
    "url": re.compile(r"^https?://"),
    "registry": re.compile(r"^HK(LM|CU|CR|U)\\"),
}

_REJECT_PATTERNS = [
    re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE),
]


def _classify_ioc_type(value: str, hint: Optional[str] = None) -> Optional[str]:
    """Classify a string as a known IOC type."""
    if hint and hint.lower() in _IOC_PATTERNS:
        if _IOC_PATTERNS[hint.lower()].match(value):
            return hint.lower()
    for ioc_type, pattern in _IOC_PATTERNS.items():
        if pattern.match(value):
            return ioc_type
    return None


def _is_hard_rejected(value: str) -> bool:
    """Hard-reject known garbage indicators. FIX #2 applied."""
    # Reject ANY CVE identifier regardless of formatting
    if value.upper().startswith("CVE-"):
        return True
    for pat in _REJECT_PATTERNS:
        if pat.match(value):
            return True
    # Reject pure version numbers using explicit character checks
    # e.g., 1.2.3, v2.0.1 — but NOT 192.168.1.1 (has digits > 255 would fail IP regex anyway)
    stripped = value.replace(".", "").replace("v", "").replace("V", "")
    if value.count(".") >= 1 and stripped.isdigit():
        return True
    return False


@dataclass
class ValidatedIOC:
    ioc_type: str
    value: str
    confidence: int
    context: str
    source: str
    first_seen: Optional[str] = None


def validate_ioc(
    value,
    ioc_type: Optional[str] = None,
    confidence: Optional[int] = None,
    context: str = "unknown",
    source: str = "unknown",
    first_seen: Optional[str] = None,
) -> Optional[ValidatedIOC]:
    """Validate and sanitize a single IOC."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if len(value) < _MIN_IOC_LENGTH or len(value) > _MAX_IOC_LENGTH:
        return None

    # FIRST: try to classify as a known IOC type
    classified_type = _classify_ioc_type(value, ioc_type)
    if classified_type is not None:
        safe_confidence = max(0, min(100, int(confidence) if confidence is not None else 0))
        return ValidatedIOC(
            ioc_type=classified_type,
            value=value,
            confidence=safe_confidence,
            context=context,
            source=source,
            first_seen=first_seen,
        )

    # SECOND: hard-reject known garbage (only if not a valid IOC)
    if _is_hard_rejected(value):
        return None

    # THIRD: allow free-text indicators (no whitespace)
    if " " in value or "\t" in value or "\n" in value:
        return None

    safe_confidence = max(0, min(100, int(confidence) if confidence is not None else 0))
    return ValidatedIOC(
        ioc_type="indicator",
        value=value,
        confidence=safe_confidence,
        context=context,
        source=source,
        first_seen=first_seen,
    )


def sanitize_ioc_list(iocs: List[dict]) -> List[ValidatedIOC]:
    """Filter and clean IOC list before report generation."""
    valid = []
    seen = set()
    for ioc in iocs:
        if not isinstance(ioc, dict):
            continue
        value = ioc.get("value") or ioc.get("indicator", "")
        v = validate_ioc(
            value=value,
            ioc_type=ioc.get("type"),
            confidence=ioc.get("confidence"),
            context=ioc.get("context", "unknown"),
            source=ioc.get("source", "unknown"),
            first_seen=ioc.get("first_seen"),
        )
        if v and v.value.lower() not in seen:
            seen.add(v.value.lower())
            valid.append(v)
    return valid


def generate_ioc_section(iocs: List[dict]) -> dict:
    """Returns IOC table or honest 'no data' message."""
    clean = sanitize_ioc_list(iocs)
    if not clean:
        return {
            "has_iocs": False,
            "message": "No active IOCs observed for this advisory. Monitor CISA KEV and exploit databases for exploitation evidence.",
            "recommended_action": "Enable auto-refresh on this CVE; IOCs will populate if active exploitation is confirmed.",
            "iocs": [],
        }
    return {
        "has_iocs": True,
        "message": f"{len(clean)} validated indicator(s) of compromise.",
        "iocs": [asdict(i) for i in clean],
    }


# ============================================================================
# REPORT ENGINE — P0-4 FIX (single source of truth)
# ============================================================================

def generate_ai_insight(
    cvss: Optional[float],
    epss: Optional[float],
    kev: bool,
    ioc_count: int,
    days_since_publish: int,
) -> str:
    """Conditional AI insight — no generic Mad Libs."""
    insights = []
    if kev:
        insights.append("⚠️ CISA KEV CONFIRMED: Active exploitation observed in the wild. Patch immediately.")
    elif epss is not None and epss > 0.5:
        insights.append(f"🔥 High exploitation probability (EPSS: {epss:.0%}). Prioritize patching within 24 hours.")
    elif epss is not None and epss > 0.1:
        insights.append(f"⚡ Moderate exploitation risk (EPSS: {epss:.0%}). Patch within standard SLA.")
    else:
        insights.append("✅ No active exploitation observed. Include in next maintenance window.")

    if ioc_count > 0:
        insights.append(f"🎯 {ioc_count} active IOCs detected. Deploy detection rules now.")

    if days_since_publish < 7 and cvss is not None and cvss >= 9.0:
        insights.append("🆕 Recent critical disclosure. Monitor for PoC release on exploit-db and GitHub.")

    return "\n\n".join(insights) if insights else "Insufficient data for predictive analysis."


def build_dossier(advisory: dict) -> dict:
    """Single source of truth report generation. FIX #3 applied."""
    iocs_raw = advisory.get("iocs", [])
    validated_iocs = sanitize_ioc_list(iocs_raw)
    ioc_count = len(validated_iocs)  # Count actual validated IOCs

    risk = compute_composite_risk(
        advisory.get("cvss"),
        advisory.get("epss"),
        advisory.get("kev", False),
        ioc_count,
    )

    ioc_section = generate_ioc_section(iocs_raw)
    days_since = (datetime.utcnow() - datetime.fromisoformat(advisory.get("published", datetime.utcnow().isoformat()))).days

    return {
        "header": {
            "intel_id": advisory.get("id", "UNKNOWN"),
            "severity": risk["severity"],
            "risk_score": risk["risk_score"],
            "cvss": risk["cvss"],
            "epss": risk["epss"],
            "ioc_count": ioc_count,  # SINGLE SOURCE OF TRUTH
            "kev": risk["kev"],
        },
        "executive_summary": {
            "title": advisory.get("title", "Untitled Advisory"),
            "description": advisory.get("description", "No description available."),
            "affected_versions": advisory.get("affected_versions", "Specific affected versions not parsed from feed"),
        },
        "risk_assessment": risk,
        "ioc_section": ioc_section,
        "ai_insight": generate_ai_insight(
            risk["cvss"], risk["epss"], risk["kev"], ioc_count, days_since
        ),
        "kill_chain": {
            "visible": ioc_count > 0 or risk["kev"],
            "stages": ["reconnaissance", "weaponization", "delivery", "exploitation", "installation", "c2", "actions_on_objectives"]
            if (ioc_count > 0 or risk["kev"]) else [],
        },
        "financial_impact": {
            "visible": risk["risk_score"] >= 5.0,
            "estimated_direct": "$10K – $250K" if risk["risk_score"] >= 5.0 else "<$10K",
            "loss_range_severe": f"${int(1_873_920 * (risk['risk_score'] / 10)):,}" if risk["risk_score"] >= 7.0 else "$50K",
        },
        "compliance": {
            "dpdp_india": risk["risk_score"] >= 5.0,
            "gdpr": risk["risk_score"] >= 5.0,
            "iso27001": risk["risk_score"] >= 4.0,
        },
    }


# ============================================================================
# INGESTION PIPELINE — P1-6, P2-10
# ============================================================================

class IngestionPipeline:
    """Deduplication + quality gates."""

    def __init__(self):
        self._cache: Dict[str, dict] = {}  # In-memory; replace with DB in prod
        self._seen_keys: set = set()

    def _make_key(self, cve_id: str, source_url: str, published: str) -> str:
        return hashlib.sha256(f"{cve_id}:{source_url}:{published}".encode()).hexdigest()

    def ingest(self, advisory: dict) -> Optional[dict]:
        cve_id = advisory.get("cve_id") or advisory.get("id", "")
        source_url = advisory.get("source_url", "")
        published = advisory.get("published", "")
        key = self._make_key(cve_id, source_url, published)

        if key in self._seen_keys:
            return None  # Duplicate

        # Quality gate: reject if critical fields missing
        cvss = advisory.get("cvss")
        epss = advisory.get("epss")
        iocs = advisory.get("iocs", [])
        validated = sanitize_ioc_list(iocs)

        quality_score = 0
        if cvss is not None:
            quality_score += 40
        if epss is not None:
            quality_score += 30
        if validated:
            quality_score += 30

        if quality_score < 20:
            # Stall — queue for manual review instead of generating garbage
            return {
                "status": "stalled",
                "reason": "Insufficient enrichment data",
                "quality_score": quality_score,
                "advisory": advisory,
            }

        self._seen_keys.add(key)
        self._cache[cve_id] = advisory
        return {
            "status": "ingested",
            "quality_score": quality_score,
            "advisory": advisory,
        }

    def get_advisory(self, cve_id: str) -> Optional[dict]:
        return self._cache.get(cve_id)

    def list_advisories(self) -> List[dict]:
        return list(self._cache.values())


# ============================================================================
# API HANDLERS — P1-5, P3-11, P3-12
# ============================================================================

class RateLimiter:
    """Simple in-memory rate limiter. Replace with Redis in prod."""

    def __init__(self):
        self._windows: Dict[str, List[float]] = {}

    def is_allowed(self, key: str, limit: int, window_sec: int) -> bool:
        now = datetime.utcnow().timestamp()
        cutoff = now - window_sec
        entries = self._windows.get(key, [])
        entries = [t for t in entries if t > cutoff]
        if len(entries) >= limit:
            self._windows[key] = entries
            return False
        entries.append(now)
        self._windows[key] = entries
        return True


rate_limiter = RateLimiter()


def check_rate_limit(request: Request, tier: str = "free") -> None:
    """Enforce tiered rate limits."""
    client_ip = request.client.host if request.client else "unknown"
    if tier == "free":
        per_min = FREE_TIER_PER_MIN
    elif tier == "starter":
        per_min = STARTER_TIER_PER_MIN
    else:
        per_min = 60

    key = f"rl:{client_ip}"
    if not rate_limiter.is_allowed(key, per_min, 60):
        raise HTTPException(
            status_code=429,
            detail={"error": "Rate limit exceeded", "retry_after": 60},
        )


# ============================================================================
# STIX EXPORT — P1-5 (pagination + caching)
# ============================================================================

@lru_cache(maxsize=4)
def build_stix_bundle(limit: int = 100, offset: int = 0) -> dict:
    """Build STIX 2.1 bundle from cached advisories."""
    pipeline = IngestionPipeline()  # In prod, inject shared instance
    all_advisories = pipeline.list_advisories()
    slice_ = all_advisories[offset:offset + limit]

    objects_ = []
    for adv in slice_:
        cve_id = adv.get("cve_id") or adv.get("id", "")
        objects_.append({
            "type": "vulnerability",
            "id": f"vulnerability--{hashlib.sha256(cve_id.encode()).hexdigest()[:12]}",
            "name": cve_id,
            "description": adv.get("description", ""),
            "created": adv.get("published", datetime.utcnow().isoformat()),
            "modified": adv.get("updated", datetime.utcnow().isoformat()),
            "labels": [adv.get("severity", "UNKNOWN")],
        })

    return {
        "type": "bundle",
        "id": f"bundle--{hashlib.sha256(str(datetime.utcnow().timestamp()).encode()).hexdigest()[:12]}",
        "spec_version": "2.1",
        "objects": objects_,
    }


# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(
    title=APP_NAME,
    version=VERSION,
    description="Production-grade threat intelligence API for CYBERDUDEBIVASH AI Security Hub",
)

# CORS: Free tier = open; paid tiers should validate Origin in prod
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared pipeline instance (singleton)
_pipeline = IngestionPipeline()


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "version": VERSION, "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/v1/intel/kev.json")
async def get_kev(request: Request):
    check_rate_limit(request, "free")
    advisories = _pipeline.list_advisories()
    return {
        "count": len(advisories),
        "advisories": [
            {
                "cve_id": a.get("cve_id") or a.get("id"),
                "cvss": a.get("cvss"),
                "severity": compute_composite_risk(
                    a.get("cvss"), a.get("epss"), a.get("kev", False), len(sanitize_ioc_list(a.get("iocs", [])))
                )["severity"],
                "risk_score": compute_composite_risk(
                    a.get("cvss"), a.get("epss"), a.get("kev", False), len(sanitize_ioc_list(a.get("iocs", [])))
                )["risk_score"],
            }
            for a in advisories
        ],
    }


@app.get("/api/v1/intel/stix.json")
async def get_stix(request: Request, limit: int = 100, offset: int = 0):
    check_rate_limit(request, "starter")
    limit = min(max(limit, 1), 1000)
    offset = max(offset, 0)
    bundle = build_stix_bundle(limit=limit, offset=offset)
    return JSONResponse(content=bundle)


@app.get("/api/v1/intel/report/{cve_id}")
async def get_report(cve_id: str, request: Request):
    check_rate_limit(request, "free")
    advisory = _pipeline.get_advisory(cve_id)
    if not advisory:
        raise HTTPException(status_code=404, detail="Advisory not found")
    return build_dossier(advisory)


@app.post("/api/v1/ingest")
async def ingest_advisory(advisory: dict, request: Request):
    check_rate_limit(request, "starter")
    result = _pipeline.ingest(advisory)
    if result is None:
        raise HTTPException(status_code=409, detail="Duplicate advisory")
    if result["status"] == "stalled":
        return JSONResponse(status_code=202, content=result)
    return result


@app.get("/api/feed")
async def get_feed(request: Request):
    check_rate_limit(request, "free")
    advisories = _pipeline.list_advisories()
    # Deduplicated by pipeline
    return {
        "feed": [
            {
                "id": a.get("cve_id") or a.get("id"),
                "title": a.get("title", ""),
                "severity": compute_composite_risk(
                    a.get("cvss"), a.get("epss"), a.get("kev", False), len(sanitize_ioc_list(a.get("iocs", [])))
                )["severity"],
                "published": a.get("published", ""),
            }
            for a in advisories
        ],
    }


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
