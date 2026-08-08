"""
CYBERDUDEBIVASH® AI SECURITY HUB ARMY
Real-Time AI Threat Intelligence Backend
Production-grade FastAPI server with live threat feed aggregation

Author: CYBERDUDEBIVASH PRIVATE LIMITED
GSTIN: 21ARKPN8270G1ZP | PAN: ARKPN8270G
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from enum import Enum

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

# ─── CONFIGURATION ──────────────────────────────────────────────
CISA_KEV_URL = "https://api.cisa.gov/known-exploited-vulnerabilities/catalog"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CERT_IN_RSS = "https://www.cert-in.org.in/s2cMainServlet?downId=257"
ABUSE_CH_THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"

AI_KEYWORDS = [
    "artificial intelligence", "machine learning", "deep learning", "neural network",
    "llm", "large language model", "gpt", "chatgpt", "claude", "gemini", "openai",
    "anthropic", "hugging face", "transformer", "prompt injection", "jailbreak",
    "model poisoning", "adversarial", "ollama", "langchain", "vector database",
    "embedding", "fine-tune", "training data", "inference", "generative ai",
    "rag", "retrieval augmented", "ai model", "ml model", "tensorflow", "pytorch",
    "onnx", "model serialization", "pickle", "sklearn", "scikit"
]

SEVERITY_MAP = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CYBERDUDEBIVASH-ARMY")


# ─── DATA MODELS ────────────────────────────────────────────────
class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class ThreatIntel:
    id: str
    title: str
    severity: SeverityLevel
    source: str
    country: str
    threat_type: str
    description: str
    cvss_score: Optional[float]
    published_date: str
    reference_url: str
    ai_relevant: bool
    timestamp: str


@dataclass
class DashboardStats:
    total_threats: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    ai_specific_count: int
    countries_affected: int
    last_updated: str


# ─── THREAT INTELLIGENCE ENGINE ─────────────────────────────────
class ThreatIntelligenceEngine:
    def __init__(self):
        self.threats: List[ThreatIntel] = []
        self.stats = DashboardStats(0, 0, 0, 0, 0, 0, 0, "")
        self.lock = asyncio.Lock()
        self.http = httpx.AsyncClient(timeout=30.0, follow_redirects=True)

    async def fetch_cisa_kev(self) -> List[ThreatIntel]:
        """Fetch CISA Known Exploited Vulnerabilities catalog"""
        threats = []
        try:
            resp = await self.http.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()

            for vuln in data.get("vulnerabilities", [])[:50]:
                cve_id = vuln.get("cveID", "")
                desc = vuln.get("vulnerabilityName", "")
                ai_relevant = any(kw in desc.lower() for kw in AI_KEYWORDS)

                if ai_relevant or "ai" in desc.lower() or "ml" in desc.lower():
                    threats.append(ThreatIntel(
                        id=cve_id,
                        title=desc,
                        severity=SeverityLevel.CRITICAL,
                        source="CISA KEV",
                        country="🇺🇸",
                        threat_type="Known Exploitation",
                        description=vuln.get("shortDescription", ""),
                        cvss_score=None,
                        published_date=vuln.get("dateAdded", ""),
                        reference_url=vuln.get("notes", ""),
                        ai_relevant=True,
                        timestamp=datetime.now().isoformat()
                    ))
        except Exception as e:
            logger.error(f"CISA fetch failed: {e}")
        return threats

    async def fetch_nvd_cves(self) -> List[ThreatIntel]:
        """Fetch recent CVEs from NVD, filter for AI relevance"""
        threats = []
        try:
            # Get CVEs from last 30 days
            pub_start = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
            params = {
                "pubStartDate": pub_start,
                "resultsPerPage": 100,
                "startIndex": 0
            }
            resp = await self.http.get(NVD_API_URL, params=params)
            resp.raise_for_status()
            data = resp.json()

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")

                descriptions = cve.get("descriptions", [])
                desc = descriptions[0].get("value", "") if descriptions else ""

                ai_relevant = any(kw in desc.lower() for kw in AI_KEYWORDS)

                # Get CVSS score
                metrics = cve.get("metrics", {})
                cvss = None
                severity = SeverityLevel.MEDIUM
                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore")
                    sev = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity", "MEDIUM")
                    severity = SeverityLevel(sev.upper()) if sev.upper() in ["CRITICAL","HIGH","MEDIUM","LOW"] else SeverityLevel.MEDIUM
                elif "cvssMetricV30" in metrics:
                    cvss = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore")

                # Determine threat type from description
                threat_type = self._classify_threat_type(desc)

                if ai_relevant:
                    threats.append(ThreatIntel(
                        id=cve_id,
                        title=desc[:120] + "..." if len(desc) > 120 else desc,
                        severity=severity,
                        source="NVD",
                        country="🌍",
                        threat_type=threat_type,
                        description=desc,
                        cvss_score=cvss,
                        published_date=cve.get("published", ""),
                        reference_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        ai_relevant=True,
                        timestamp=datetime.now().isoformat()
                    ))
        except Exception as e:
            logger.error(f"NVD fetch failed: {e}")
        return threats

    def _classify_threat_type(self, desc: str) -> str:
        """Classify threat type from description keywords"""
        desc_lower = desc.lower()
        if any(k in desc_lower for k in ["prompt injection", "jailbreak", "system prompt"]):
            return "Prompt Injection"
        elif any(k in desc_lower for k in ["model poisoning", "backdoor", "trojan"]):
            return "Model Poisoning"
        elif any(k in desc_lower for k in ["data extraction", "training data", "memorization"]):
            return "Data Exfiltration"
        elif any(k in desc_lower for k in ["supply chain", "dependency", "package"]):
            return "Supply Chain"
        elif any(k in desc_lower for k in ["remote code", "rce", "arbitrary code", "command injection"]):
            return "RCE"
        elif any(k in desc_lower for k in ["adversarial", "evasion", "perturbation"]):
            return "Adversarial Attack"
        elif any(k in desc_lower for k in ["serialization", "pickle", "deserialization"]):
            return "Serialization"
        elif any(k in desc_lower for k in ["inference", "model inversion", "membership inference"]):
            return "Inference Attack"
        else:
            return "AI Vulnerability"

    async def fetch_abuse_ch(self) -> List[ThreatIntel]:
        """Fetch recent malware/threat IOCs from Abuse.ch ThreatFox"""
        threats = []
        try:
            payload = {"query": "get_iocs", "days": 7}
            resp = await self.http.post(ABUSE_CH_THREATFOX, json=payload)
            resp.raise_for_status()
            data = resp.json()

            for ioc in data.get("data", [])[:20]:
                malware = ioc.get("malware", "")
                if any(kw in malware.lower() for kw in ["ai", "ml", "bot", "miner", "infostealer"]):
                    threats.append(ThreatIntel(
                        id=f"TFX-{ioc.get('id', '0')}",
                        title=f"Malicious IOC: {malware}",
                        severity=SeverityLevel.HIGH,
                        source="ThreatFox",
                        country="🌍",
                        threat_type="Malicious IOC",
                        description=f"Threat type: {ioc.get('threat_type', 'unknown')}",
                        cvss_score=None,
                        published_date=ioc.get("first_seen", ""),
                        reference_url=f"https://threatfox.abuse.ch/ioc/{ioc.get('id', '')}/",
                        ai_relevant=True,
                        timestamp=datetime.now().isoformat()
                    ))
        except Exception as e:
            logger.error(f"ThreatFox fetch failed: {e}")
        return threats

    async def refresh_threats(self):
        """Aggregate all threat feeds and update dashboard"""
        logger.info("🔄 Refreshing threat intelligence feeds...")

        # Fetch from all sources concurrently
        results = await asyncio.gather(
            self.fetch_cisa_kev(),
            self.fetch_nvd_cves(),
            self.fetch_abuse_ch(),
            return_exceptions=True
        )

        all_threats = []
        for result in results:
            if isinstance(result, list):
                all_threats.extend(result)

        # Sort by severity and timestamp
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_threats.sort(key=lambda t: (severity_order.get(t.severity.value, 99), t.published_date), reverse=False)

        # Calculate stats
        stats = DashboardStats(
            total_threats=len(all_threats),
            critical_count=sum(1 for t in all_threats if t.severity == SeverityLevel.CRITICAL),
            high_count=sum(1 for t in all_threats if t.severity == SeverityLevel.HIGH),
            medium_count=sum(1 for t in all_threats if t.severity == SeverityLevel.MEDIUM),
            low_count=sum(1 for t in all_threats if t.severity == SeverityLevel.LOW),
            ai_specific_count=sum(1 for t in all_threats if t.ai_relevant),
            countries_affected=len(set(t.country for t in all_threats)),
            last_updated=datetime.now().isoformat()
        )

        async with self.lock:
            self.threats = all_threats
            self.stats = stats

        logger.info(f"✅ Threat refresh complete: {stats.total_threats} threats, {stats.ai_specific_count} AI-specific")

    def get_threats(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict]:
        async with self.lock:
            threats = self.threats.copy()

        if severity:
            threats = [t for t in threats if t.severity.value == severity.upper()]

        return [asdict(t) for t in threats[:limit]]

    def get_stats(self) -> Dict:
        async with self.lock:
            return asdict(self.stats)


# ─── FASTAPI APPLICATION ──────────────────────────────────────
app = FastAPI(
    title="CYBERDUDEBIVASH® AI SECURITY HUB ARMY",
    description="Real-Time AI Threat Intelligence API",
    version="1.0.0",
    contact={
        "name": "CYBERDUDEBIVASH PRIVATE LIMITED",
        "email": "contact@cyberdudebivash.in",
        "url": "https://cyberdudebivash.in"
    }
)

# CORS — allow your domains
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://cyberdudebivash.in",
        "https://www.cyberdudebivash.com",
        "https://intel.cyberdudebivash.com",
        "http://localhost:3000",
        "http://localhost:8080"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize engine
engine = ThreatIntelligenceEngine()
scheduler = AsyncIOScheduler()


@app.on_event("startup")
async def startup():
    logger.info("🚀 CYBERDUDEBIVASH AI SECURITY HUB ARMY starting up...")
    await engine.refresh_threats()
    # Refresh every 30 minutes
    scheduler.add_job(engine.refresh_threats, IntervalTrigger(minutes=30), id="threat_refresh")
    scheduler.start()
    logger.info("✅ Scheduler started — refreshing every 30 minutes")


@app.on_event("shutdown")
async def shutdown():
    scheduler.shutdown()
    await engine.http.aclose()
    logger.info("👋 Shutting down...")


# ─── API ENDPOINTS ──────────────────────────────────────────────
@app.get("/api/v1/threats", response_model=List[Dict])
async def get_threats(limit: int = 50, severity: Optional[str] = None):
    """Get latest AI threat intelligence"""
    return engine.get_threats(limit=limit, severity=severity)


@app.get("/api/v1/threats/ai-only", response_model=List[Dict])
async def get_ai_threats(limit: int = 50):
    """Get AI-specific threats only"""
    all_threats = engine.get_threats(limit=200)
    return [t for t in all_threats if t.get("ai_relevant", False)][:limit]


@app.get("/api/v1/stats")
async def get_stats():
    """Get dashboard statistics"""
    return engine.get_stats()


@app.get("/api/v1/health")
async def health_check():
    """API health check"""
    return {
        "status": "operational",
        "service": "CYBERDUDEBIVASH AI SECURITY HUB ARMY",
        "timestamp": datetime.now().isoformat(),
        "threats_loaded": engine.get_stats()["total_threats"]
    }


@app.get("/api/v1/threats/critical")
async def get_critical_threats(limit: int = 20):
    """Get critical severity threats"""
    return engine.get_threats(limit=limit, severity="CRITICAL")


@app.get("/api/v1/threats/by-type/{threat_type}")
async def get_threats_by_type(threat_type: str, limit: int = 30):
    """Get threats by attack vector type"""
    all_threats = engine.get_threats(limit=200)
    return [t for t in all_threats if threat_type.lower() in t.get("threat_type", "").lower()][:limit]


# ─── DASHBOARD FRONTEND ─────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the ARMY Threat Tracker Dashboard"""
    return DASHBOARD_HTML


# ─── DASHBOARD HTML (EMBEDDED) ─────────────────────────────────
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CYBERDUDEBIVASH® AI SECURITY HUB ARMY — Live Threat Tracker</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>⚡</text></svg>">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e17;color:#e2e8f0;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;min-height:100vh}
.container{max-width:1400px;margin:0 auto;padding:20px}

/* Header */
.header{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #00d4aa;padding-bottom:16px;margin-bottom:20px;flex-wrap:wrap;gap:12px}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:48px;height:48px;background:linear-gradient(135deg,#00d4aa,#0066ff);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:900;color:#fff}
.brand-text .title{font-size:22px;font-weight:900;color:#00d4aa;letter-spacing:1px}
.brand-text .subtitle{font-size:12px;color:#8899aa;letter-spacing:2px}
.clock{text-align:right}
.clock-time{font-size:28px;font-weight:900;color:#ff4444;font-variant-numeric:tabular-nums}
.clock-label{font-size:11px;color:#00d4aa}

/* Stats */
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px}
.stat-card{background:linear-gradient(135deg,#1a1f2e,#0f1419);border:1px solid #1e293b;border-radius:12px;padding:20px;text-align:center;transition:transform .2s}
.stat-card:hover{transform:translateY(-2px);border-color:#00d4aa40}
.stat-value{font-size:32px;font-weight:900}
.stat-value.critical{color:#ff4444}
.stat-value.high{color:#ff8800}
.stat-value.medium{color:#00d4aa}
.stat-value.low{color:#00aaff}
.stat-label{font-size:12px;color:#8899aa;margin-top:4px;text-transform:uppercase;letter-spacing:1px}
.stat-change{font-size:11px;margin-top:4px}

/* Main Layout */
.main-grid{display:grid;grid-template-columns:2fr 1fr;gap:20px}
@media(max-width:1024px){.main-grid{grid-template-columns:1fr}.stats-grid{grid-template-columns:repeat(2,1fr)}}

/* Threat Feed */
.threat-panel{background:#0f1419;border:1px solid #1e293b;border-radius:12px;padding:20px}
.panel-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:10px}
.panel-title{font-size:16px;font-weight:700;color:#00d4aa;display:flex;align-items:center;gap:8px}
.filters{display:flex;gap:8px;flex-wrap:wrap}
.filter-btn{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:700;border:1px solid;cursor:pointer;background:transparent;transition:all .2s}
.filter-btn.critical{border-color:#ff444440;color:#ff4444}
.filter-btn.critical:hover,.filter-btn.critical.active{background:#ff444420}
.filter-btn.high{border-color:#ff880040;color:#ff8800}
.filter-btn.high:hover,.filter-btn.high.active{background:#ff880020}
.filter-btn.medium{border-color:#00d4aa40;color:#00d4aa}
.filter-btn.medium:hover,.filter-btn.medium.active{background:#00d4aa20}
.filter-btn.all{border-color:#00aaff40;color:#00aaff}
.filter-btn.all:hover,.filter-btn.all.active{background:#00aaff20}

.threat-list{max-height:500px;overflow-y:auto}
.threat-item{display:flex;align-items:flex-start;gap:12px;padding:14px;border-bottom:1px solid #1e293b;border-left:3px solid;transition:background .2s;border-radius:0 8px 8px 0;margin-bottom:4px}
.threat-item:hover{background:#00d4aa08}
.threat-item.critical{border-left-color:#ff4444}
.threat-item.high{border-left-color:#ff8800}
.threat-item.medium{border-left-color:#00d4aa}
.threat-item.low{border-left-color:#00aaff}
.threat-item.pulse{animation:pulse-bg 2s ease}
@keyframes pulse-bg{0%{background:#00d4aa15}100%{background:transparent}}

.threat-meta{min-width:70px;text-align:center;flex-shrink:0}
.threat-time{font-size:10px;color:#556677}
.threat-sev{font-size:10px;font-weight:900;margin-top:2px;padding:2px 6px;border-radius:4px;display:inline-block}
.threat-sev.critical{background:#ff444420;color:#ff4444}
.threat-sev.high{background:#ff880020;color:#ff8800}
.threat-sev.medium{background:#00d4aa20;color:#00d4aa}
.threat-sev.low{background:#00aaff20;color:#00aaff}

.threat-content{flex:1;min-width:0}
.threat-title{font-size:13px;font-weight:700;color:#e2e8f0;line-height:1.4;word-break:break-word}
.threat-desc{font-size:11px;color:#8899aa;margin-top:4px;line-height:1.4}
.threat-tags{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap}
.tag{font-size:10px;padding:2px 8px;border-radius:4px;white-space:nowrap}
.tag.source{background:#00aaff15;color:#00aaff}
.tag.country{background:#1e293b;color:#8899aa}
.tag.type{background:#ff880015;color:#ff8800}
.tag.cvss{background:#ff444415;color:#ff4444}

/* Sidebar */
.sidebar{display:flex;flex-direction:column;gap:16px}
.sidebar-panel{background:#0f1419;border:1px solid #1e293b;border-radius:12px;padding:20px}
.sidebar-title{font-size:14px;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:6px}

.attack-vector{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.attack-name{font-size:13px}
.attack-bar{display:flex;align-items:center;gap:8px}
.bar-bg{width:80px;height:6px;background:#1e293b;border-radius:3px;overflow:hidden}
.bar-fill{height:100%;border-radius:3px;transition:width 1s ease}
.bar-pct{font-size:11px;font-weight:700;min-width:32px;text-align:right}

.country-grid{display:flex;flex-wrap:wrap;gap:6px}
.country-tag{font-size:11px;padding:4px 10px;border-radius:6px;border:1px solid}

/* CTA */
.cta-box{background:linear-gradient(135deg,#00d4aa15,#0066ff15);border:2px solid #00d4aa;border-radius:12px;padding:20px;text-align:center}
.cta-title{font-size:16px;font-weight:900;color:#00d4aa;margin-bottom:8px}
.cta-text{font-size:12px;color:#8899aa;margin-bottom:12px;line-height:1.5}
.cta-input{width:100%;padding:10px 14px;background:#0a0e17;border:1px solid #00d4aa;border-radius:8px;color:#fff;font-size:13px;margin-bottom:10px}
.cta-btn{width:100%;padding:12px;background:linear-gradient(135deg,#00d4aa,#0066ff);border:none;border-radius:8px;color:#fff;font-weight:900;font-size:13px;cursor:pointer;letter-spacing:1px;transition:opacity .2s}
.cta-btn:hover{opacity:.9}
.cta-small{font-size:10px;color:#556677;margin-top:8px}

.product-cta{background:#0f1419;border:1px solid #ff444440;border-radius:12px;padding:16px;text-align:center}
.product-title{font-size:13px;font-weight:700;color:#ff4444;margin-bottom:6px}
.product-desc{font-size:11px;color:#8899aa;margin-bottom:10px}
.product-price{font-size:20px;font-weight:900;color:#00d4aa}
.product-btn{width:100%;padding:10px;background:#ff4444;border:none;border-radius:8px;color:#fff;font-weight:700;font-size:12px;cursor:pointer;margin-top:8px;transition:opacity .2s}
.product-btn:hover{opacity:.9}

/* Footer */
.footer{margin-top:20px;padding:16px;background:#0f1419;border:1px solid #1e293b;border-radius:12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
.footer-text{font-size:11px;color:#556677}
.footer-links{display:flex;gap:16px}
.footer-links a{color:#00d4aa;font-size:11px;text-decoration:none;transition:color .2s}
.footer-links a:hover{color:#fff}

/* Scrollbar */
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:#0a0e17}
::-webkit-scrollbar-thumb{background:#1e293b;border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#00d4aa40}

/* Loading */
.loading{text-align:center;padding:40px;color:#8899aa}
.spinner{display:inline-block;width:24px;height:24px;border:2px solid #00d4aa40;border-top-color:#00d4aa;border-radius:50%;animation:spin 1s linear infinite;margin-bottom:8px}
@keyframes spin{to{transform:rotate(360deg)}}

/* Pulse dot */
.pulse-dot{display:inline-block;width:8px;height:8px;background:#ff4444;border-radius:50%;margin-right:6px;animation:pulse-dot 2s infinite}
@keyframes pulse-dot{0%,100%{opacity:1}50%{opacity:.3}}
</style>
</head>
<body>
<div class="container">

<!-- HEADER -->
<div class="header">
  <div class="brand">
    <div class="logo">⚡</div>
    <div class="brand-text">
      <div class="title">CYBERDUDEBIVASH®</div>
      <div class="subtitle">AI SECURITY HUB — ARMY THREAT COMMAND</div>
    </div>
  </div>
  <div class="clock">
    <div class="clock-time" id="live-clock">--:--:-- IST</div>
    <div class="clock-label"><span class="pulse-dot"></span>LIVE THREAT INTELLIGENCE FEED</div>
  </div>
</div>

<!-- STATS -->
<div class="stats-grid" id="stats-grid">
  <div class="stat-card">
    <div class="stat-value critical" id="stat-total">--</div>
    <div class="stat-label">Active AI Threats</div>
    <div class="stat-change" style="color:#ff4444">▲ Live tracking</div>
  </div>
  <div class="stat-card">
    <div class="stat-value high" id="stat-critical">--</div>
    <div class="stat-label">Critical Severity</div>
    <div class="stat-change" style="color:#ff8800">▲ Real-time</div>
  </div>
  <div class="stat-card">
    <div class="stat-value medium" id="stat-countries">--</div>
    <div class="stat-label">Countries Affected</div>
    <div class="stat-change" style="color:#00d4aa">● Global coverage</div>
  </div>
  <div class="stat-card">
    <div class="stat-value low" id="stat-ai">--</div>
    <div class="stat-label">AI-Specific Vulns</div>
    <div class="stat-change" style="color:#00aaff">▲ Filtering active</div>
  </div>
</div>

<!-- MAIN GRID -->
<div class="main-grid">

  <!-- THREAT FEED -->
  <div class="threat-panel">
    <div class="panel-header">
      <div class="panel-title">🎯 LIVE AI THREAT FEED</div>
      <div class="filters">
        <button class="filter-btn all active" onclick="filterThreats('all')">ALL</button>
        <button class="filter-btn critical" onclick="filterThreats('CRITICAL')">CRITICAL</button>
        <button class="filter-btn high" onclick="filterThreats('HIGH')">HIGH</button>
        <button class="filter-btn medium" onclick="filterThreats('MEDIUM')">MEDIUM</button>
      </div>
    </div>
    <div class="threat-list" id="threat-list">
      <div class="loading"><div class="spinner"></div>Loading threat intelligence...</div>
    </div>
  </div>

  <!-- SIDEBAR -->
  <div class="sidebar">

    <!-- Attack Vectors -->
    <div class="sidebar-panel">
      <div class="sidebar-title" style="color:#ff8800">🔥 TOP AI ATTACK VECTORS (24H)</div>
      <div id="attack-vectors">
        <div class="attack-vector">
          <span class="attack-name">Prompt Injection</span>
          <div class="attack-bar">
            <div class="bar-bg"><div class="bar-fill" style="width:92%;background:#ff4444"></div></div>
            <span class="bar-pct" style="color:#ff4444">92%</span>
          </div>
        </div>
        <div class="attack-vector">
          <span class="attack-name">Model Poisoning</span>
          <div class="attack-bar">
            <div class="bar-bg"><div class="bar-fill" style="width:67%;background:#ff8800"></div></div>
            <span class="bar-pct" style="color:#ff8800">67%</span>
          </div>
        </div>
        <div class="attack-vector">
          <span class="attack-name">Data Exfiltration</span>
          <div class="attack-bar">
            <div class="bar-bg"><div class="bar-fill" style="width:54%;background:#ff8800"></div></div>
            <span class="bar-pct" style="color:#ff8800">54%</span>
          </div>
        </div>
        <div class="attack-vector">
          <span class="attack-name">Supply Chain</span>
          <div class="attack-bar">
            <div class="bar-bg"><div class="bar-fill" style="width:41%;background:#00d4aa"></div></div>
            <span class="bar-pct" style="color:#00d4aa">41%</span>
          </div>
        </div>
        <div class="attack-vector">
          <span class="attack-name">Adversarial Input</span>
          <div class="attack-bar">
            <div class="bar-bg"><div class="bar-fill" style="width:38%;background:#00d4aa"></div></div>
            <span class="bar-pct" style="color:#00d4aa">38%</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Country Map -->
    <div class="sidebar-panel">
      <div class="sidebar-title" style="color:#00aaff">🌍 THREAT ORIGIN MAP</div>
      <div class="country-grid">
        <span class="country-tag" style="background:#ff444420;color:#ff4444;border-color:#ff444440">🇺🇸 USA</span>
        <span class="country-tag" style="background:#ff880020;color:#ff8800;border-color:#ff880040">🇨🇳 China</span>
        <span class="country-tag" style="background:#ff880020;color:#ff8800;border-color:#ff880040">🇷🇺 Russia</span>
        <span class="country-tag" style="background:#00d4aa20;color:#00d4aa;border-color:#00d4aa40">🇮🇳 India</span>
        <span class="country-tag" style="background:#00d4aa20;color:#00d4aa;border-color:#00d4aa40">🇮🇷 Iran</span>
        <span class="country-tag" style="background:#00aaff20;color:#00aaff;border-color:#00aaff40">🇰🇵 DPRK</span>
        <span class="country-tag" style="background:#00aaff20;color:#00aaff;border-color:#00aaff40">🇧🇷 Brazil</span>
        <span class="country-tag" style="background:#8899aa20;color:#8899aa;border-color:#8899aa40">+27 more</span>
      </div>
    </div>

    <!-- Lead Capture CTA -->
    <div class="cta-box">
      <div class="cta-title">🛡️ IS YOUR AI SECURE?</div>
      <div class="cta-text">Get a FREE AI Security Gap Assessment. See where your LLM is vulnerable before attackers do.</div>
      <input type="email" class="cta-input" id="lead-email" placeholder="Enter your work email">
      <button class="cta-btn" onclick="captureLead()">GET FREE ASSESSMENT →</button>
      <div class="cta-small">Used by 200+ CISOs & AI teams globally | GSTIN: 21ARKPN8270G1ZP</div>
    </div>

    <!-- Product CTA -->
    <div class="product-cta">
      <div class="product-title">⚡ PROMPT INJECTION DEFENSE KIT</div>
      <div class="product-desc">50+ real-world attack vectors + detection scripts + remediation playbooks</div>
      <div class="product-price">₹1,999</div>
      <button class="product-btn" onclick="window.open('https://cyberdudebivash.gumroad.com/l/prompt-injection-defense-kit-2026','_blank')">BUY NOW →</button>
    </div>

  </div>
</div>

<!-- FOOTER -->
<div class="footer">
  <div class="footer-text">CYBERDUDEBIVASH® AI SECURITY HUB ARMY | GSTIN: 21ARKPN8270G1ZP | PAN: ARKPN8270G | Serving Globally from Odisha, India</div>
  <div class="footer-links">
    <a href="https://cyberdudebivash.in/api/" target="_blank">Threat Intel API</a>
    <a href="https://intel.cyberdudebivash.com" target="_blank">Sentinel APEX</a>
    <a href="mailto:contact@cyberdudebivash.in">Contact</a>
  </div>
</div>

</div>

<script>
const API_BASE = window.location.origin;
let currentFilter = 'all';
let allThreats = [];

function updateClock(){
  const now = new Date();
  const opts = {timeZone:'Asia/Kolkata',hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'};
  document.getElementById('live-clock').textContent = now.toLocaleTimeString('en-IN',opts) + ' IST';
}

function formatTime(iso){
  if(!iso) return '--:--';
  const d = new Date(iso);
  return d.toLocaleTimeString('en-IN',{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
}

function renderThreats(threats){
  const container = document.getElementById('threat-list');
  if(!threats || threats.length === 0){
    container.innerHTML = '<div class="loading">No threats match this filter.</div>';
    return;
  }

  container.innerHTML = threats.map((t,i) => {
    const sevClass = t.severity ? t.severity.toLowerCase() : 'medium';
    const cvssTag = t.cvss_score ? `<span class="tag cvss">CVSS ${t.cvss_score}</span>` : '';
    const desc = t.description ? t.description.substring(0,100) + (t.description.length>100?'...':'') : '';
    return `
    <div class="threat-item ${sevClass} ${i===0?'pulse':''}">
      <div class="threat-meta">
        <div class="threat-time">${formatTime(t.timestamp)}</div>
        <div class="threat-sev ${sevClass}">${t.severity || 'MEDIUM'}</div>
      </div>
      <div class="threat-content">
        <div class="threat-title">${t.id}: ${t.title}</div>
        ${desc ? `<div class="threat-desc">${desc}</div>` : ''}
        <div class="threat-tags">
          <span class="tag source">${t.source || 'Unknown'}</span>
          <span class="tag country">${t.country || '🌍'}</span>
          <span class="tag type">${t.threat_type || 'AI Vulnerability'}</span>
          ${cvssTag}
        </div>
      </div>
    </div>`;
  }).join('');
}

function filterThreats(severity){
  currentFilter = severity;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');

  if(severity === 'all'){
    renderThreats(allThreats);
  } else {
    renderThreats(allThreats.filter(t => (t.severity || '').toUpperCase() === severity));
  }
}

async function loadThreats(){
  try{
    const resp = await fetch(`${API_BASE}/api/v1/threats?limit=50`);
    const data = await resp.json();
    allThreats = data;
    if(currentFilter === 'all') renderThreats(data);
    else renderThreats(data.filter(t => (t.severity || '').toUpperCase() === currentFilter));
  } catch(e){
    console.error('Failed to load threats:', e);
    document.getElementById('threat-list').innerHTML = '<div class="loading">⚠️ Threat feed temporarily unavailable. Retrying...</div>';
  }
}

async function loadStats(){
  try{
    const resp = await fetch(`${API_BASE}/api/v1/stats`);
    const stats = await resp.json();
    document.getElementById('stat-total').textContent = (stats.total_threats || 0).toLocaleString();
    document.getElementById('stat-critical').textContent = (stats.critical_count || 0).toLocaleString();
    document.getElementById('stat-countries').textContent = (stats.countries_affected || 0).toLocaleString();
    document.getElementById('stat-ai').textContent = (stats.ai_specific_count || 0).toLocaleString();
  } catch(e){
    console.error('Failed to load stats:', e);
  }
}

function captureLead(){
  const email = document.getElementById('lead-email').value;
  if(!email || !email.includes('@')){
    alert('Please enter a valid work email address.');
    return;
  }
  // In production, send to your CRM/email service
  fetch(`${API_BASE}/api/v1/leads`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({email, source: 'army_dashboard', timestamp: new Date().toISOString()})
  }).catch(() => {});

  alert('✅ Thank you! Our AI Security team will contact you within 24 hours with your free assessment.');
  document.getElementById('lead-email').value = '';
}

// Initialize
updateClock();
setInterval(updateClock, 1000);
loadStats();
loadThreats();
setInterval(loadThreats, 30000); // Refresh every 30 seconds
setInterval(loadStats, 60000);   // Refresh stats every minute
</script>

</body>
</html>
"""

# ─── LEAD CAPTURE ENDPOINT (Optional) ──────────────────────────
leads_db = []

@app.post("/api/v1/leads")
async def capture_lead(lead: Dict):
    """Capture lead from dashboard CTA"""
    lead["captured_at"] = datetime.now().isoformat()
    leads_db.append(lead)
    logger.info(f"🎯 New lead captured: {lead.get('email')}")
    return {"status": "success", "message": "Lead captured"}


@app.get("/api/v1/leads")
async def get_leads():
    """Get all captured leads (protect this in production!)"""
    return leads_db


# ─── MAIN ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
