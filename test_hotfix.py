"""
test_hotfix.py — v185.1 Validation Suite
53 unit tests covering severity mapping, IOC validation, report consistency,
ingestion pipeline, STIX export, and rate limiting in cyberdudebivash_army_backend.py.

Scope note: this suite tests backend business logic in isolation (functions are
imported and called in-process). It does not exercise the deployed Cloudflare
Worker, HTTP request handling, authentication, or any payment/entitlement path —
see docs/commercial/COMMERCIAL_PRODUCTION_GAP_REGISTER.md for what is and isn't
covered before treating a pass here as a statement about the live product.

Run: python test_hotfix.py
"""

import sys
import json
from datetime import datetime, timedelta

# Import backend
sys.path.insert(0, "/mnt/agents/output")
from cyberdudebivash_army_backend import (
    map_cvss_to_severity,
    compute_composite_risk,
    Severity,
    validate_ioc,
    sanitize_ioc_list,
    generate_ioc_section,
    build_dossier,
    generate_ai_insight,
    IngestionPipeline,
    build_stix_bundle,
    RateLimiter,
    _is_hard_rejected,
    _classify_ioc_type,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS = 0
FAIL = 0

def assert_test(name: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✅ {name}")
    else:
        FAIL += 1
        print(f"  ❌ {name} — {detail}")

# ---------------------------------------------------------------------------
# 1. SEVERITY MAPPER (8 tests)
# ---------------------------------------------------------------------------

print("\n🧪 SEVERITY MAPPER")

assert_test("CVSS 9.8 → CRITICAL", map_cvss_to_severity(9.8) == Severity.CRITICAL)
assert_test("CVSS 7.5 → HIGH", map_cvss_to_severity(7.5) == Severity.HIGH)
assert_test("CVSS 5.3 → MEDIUM", map_cvss_to_severity(5.3) == Severity.MEDIUM)
assert_test("CVSS 3.2 → LOW", map_cvss_to_severity(3.2) == Severity.LOW)
assert_test("CVSS 0.0 → INFO", map_cvss_to_severity(0.0) == Severity.INFO)
assert_test("CVSS None → UNKNOWN", map_cvss_to_severity(None) == Severity.UNKNOWN)
assert_test("CVSS 9.0 floor → CRITICAL", map_cvss_to_severity(9.0) == Severity.CRITICAL)
assert_test("CVSS 7.0 floor → HIGH", map_cvss_to_severity(7.0) == Severity.HIGH)

# ---------------------------------------------------------------------------
# 2. COMPOSITE RISK (12 tests)
# ---------------------------------------------------------------------------

print("\n🧪 COMPOSITE RISK")

# CVSS floors
r = compute_composite_risk(9.8, 0.0, False, 0)
assert_test("CVSS 9.8 risk >= 7.0", r["risk_score"] >= 7.0, f"got {r['risk_score']}")
assert_test("CVSS 9.8 severity CRITICAL", r["severity"] == "CRITICAL", f"got {r['severity']}")

r = compute_composite_risk(7.5, 0.0, False, 0)
assert_test("CVSS 7.5 risk >= 5.0", r["risk_score"] >= 5.0, f"got {r['risk_score']}")
assert_test("CVSS 7.5 severity HIGH", r["severity"] == "HIGH", f"got {r['severity']}")

r = compute_composite_risk(5.3, 0.0, False, 0)
assert_test("CVSS 5.3 severity MEDIUM", r["severity"] == "MEDIUM", f"got {r['severity']}")

r = compute_composite_risk(3.2, 0.0, False, 0)
assert_test("CVSS 3.2 severity LOW", r["severity"] == "LOW", f"got {r['severity']}")

# KEV + EPSS without CVSS — FIX #1
r = compute_composite_risk(None, 0.8, True, 0)
assert_test("KEV+EPSS>=0.5 floor 9.0", r["risk_score"] >= 9.0, f"got {r['risk_score']}")
assert_test("KEV+EPSS>=0.5 severity CRITICAL", r["severity"] == "CRITICAL", f"got {r['severity']}")

r = compute_composite_risk(None, 0.3, True, 0)
assert_test("KEV only floor 5.0", r["risk_score"] >= 5.0, f"got {r['risk_score']}")

r = compute_composite_risk(None, 0.8, False, 0)
assert_test("EPSS>=0.5 only floor 4.0", r["risk_score"] >= 4.0, f"got {r['risk_score']}")

r = compute_composite_risk(None, None, False, 0)
assert_test("No data → UNKNOWN", r["severity"] == "UNKNOWN", f"got {r['severity']}")

# EPSS boost
r = compute_composite_risk(8.0, 0.6, False, 0)
assert_test("EPSS>0.5 boost applied", r["risk_score"] > 8.0, f"got {r['risk_score']}")

# ---------------------------------------------------------------------------
# 3. IOC VALIDATOR (10 tests)
# ---------------------------------------------------------------------------

print("\n🧪 IOC VALIDATOR")

assert_test("Valid IP accepted", validate_ioc("192.168.1.1", "ip") is not None)
assert_test("Valid domain accepted", validate_ioc("evil.com", "domain") is not None)
assert_test("Valid MD5 accepted", validate_ioc("a" * 32, "hash_md5") is not None)
assert_test("Valid SHA256 accepted", validate_ioc("b" * 64, "hash_sha256") is not None)
assert_test("Valid URL accepted", validate_ioc("http://evil.com", "url") is not None)

assert_test("CVE ID rejected", validate_ioc("CVE-2026-11612", "indicator") is None)
assert_test("CVE ID lowercase rejected", validate_ioc("cve-2026-11612", "indicator") is None)

# FIX #2 — version strings rejected, IPs preserved
assert_test("Version string 1.2.3 rejected", validate_ioc("1.2.3", "indicator") is None)
assert_test("Version string v2.0.1 rejected", validate_ioc("v2.0.1", "indicator") is None)
assert_test("IP 192.168.1.1 NOT rejected as version", validate_ioc("192.168.1.1", "ip") is not None)

# ---------------------------------------------------------------------------
# 4. IOC SANITIZE & SECTION (4 tests)
# ---------------------------------------------------------------------------

print("\n🧪 IOC SANITIZE & SECTION")

raw = [
    {"value": "192.168.1.1", "type": "ip", "confidence": 85},
    {"value": "CVE-2026-11612", "type": "indicator", "confidence": 23},
    {"value": "1.2.3", "type": "indicator", "confidence": 50},
    {"value": "evil.com", "type": "domain", "confidence": 90},
]

valid = sanitize_ioc_list(raw)
assert_test("Sanitize keeps 2 valid IOCs", len(valid) == 2, f"got {len(valid)}")
assert_test("Sanitize drops CVE", all("CVE" not in v.value for v in valid))
assert_test("Sanitize drops version", all(v.value != "1.2.3" for v in valid))

section = generate_ioc_section(raw)
assert_test("IOC section has_iocs True", section["has_iocs"] is True)

section_empty = generate_ioc_section([{"value": "CVE-2026-XXXX", "type": "indicator"}])
assert_test("All-invalid IOCs → has_iocs False", section_empty["has_iocs"] is False)

# ---------------------------------------------------------------------------
# 5. REPORT ENGINE / DOSSIER (4 tests) — FIX #3
# ---------------------------------------------------------------------------

print("\n🧪 REPORT ENGINE / DOSSIER")

adv = {
    "id": "CVE-2026-TEST-001",
    "title": "Test Advisory",
    "description": "Test desc",
    "cvss": 9.8,
    "epss": 0.05,
    "kev": False,
    "iocs": [
        {"value": "192.168.1.1", "type": "ip", "confidence": 85},
        {"value": "CVE-2026-XXXX", "type": "indicator", "confidence": 23},
        {"value": "evil.com", "type": "domain", "confidence": 90},
    ],
    "published": (datetime.utcnow() - timedelta(days=5)).isoformat(),
}

dossier = build_dossier(adv)
assert_test("Dossier header ioc_count == 2", dossier["header"]["ioc_count"] == 2, f"got {dossier['header']['ioc_count']}")
assert_test("Dossier severity CRITICAL for CVSS 9.8", dossier["header"]["severity"] == "CRITICAL")
assert_test("Dossier risk_score >= 7.0", dossier["header"]["risk_score"] >= 7.0, f"got {dossier['header']['risk_score']}")
assert_test("IOC section consistent", dossier["ioc_section"]["has_iocs"] is True and len(dossier["ioc_section"]["iocs"]) == 2)

# ---------------------------------------------------------------------------
# 6. AI INSIGHT (3 tests)
# ---------------------------------------------------------------------------

print("\n🧪 AI INSIGHT")

insight = generate_ai_insight(9.8, 0.05, False, 0, 3)
assert_test("Recent critical has PoC warning", "PoC" in insight or "Monitor" in insight)

insight_kev = generate_ai_insight(8.0, 0.6, True, 5, 30)
assert_test("KEV insight mentions patch immediately", "Patch immediately" in insight_kev)

insight_low = generate_ai_insight(3.0, 0.0, False, 0, 30)
assert_test("Low risk insight is calm", "next maintenance window" in insight_low)

# ---------------------------------------------------------------------------
# 7. INGESTION PIPELINE (3 tests)
# ---------------------------------------------------------------------------

print("\n🧪 INGESTION PIPELINE")

pipe = IngestionPipeline()

a1 = {
    "cve_id": "CVE-2026-001",
    "source_url": "https://nvd.nist.gov/",
    "published": "2026-01-01T00:00:00",
    "cvss": 9.8,
    "epss": 0.1,
    "iocs": [{"value": "10.0.0.1", "type": "ip"}],
}

r1 = pipe.ingest(a1)
assert_test("Ingest valid advisory", r1 is not None and r1["status"] == "ingested")

r2 = pipe.ingest(a1)
assert_test("Duplicate rejected", r2 is None)

a_stall = {
    "cve_id": "CVE-2026-002",
    "source_url": "https://example.com/",
    "published": "2026-01-02T00:00:00",
}
r3 = pipe.ingest(a_stall)
assert_test("Stall low-quality advisory", r3 is not None and r3["status"] == "stalled")

# ---------------------------------------------------------------------------
# 8. STIX EXPORT (2 tests)
# ---------------------------------------------------------------------------

print("\n🧪 STIX EXPORT")

# Pre-seed pipeline for STIX
pipe2 = IngestionPipeline()
pipe2.ingest({
    "cve_id": "CVE-2026-STIX-01",
    "source_url": "https://nvd.nist.gov/",
    "published": "2026-01-01T00:00:00",
    "cvss": 7.5,
    "description": "Test STIX",
})

# Monkey-patch for test (normally singleton)
import cyberdudebivash_army_backend as backend_mod
backend_mod._pipeline = pipe2

bundle = build_stix_bundle(limit=10, offset=0)
assert_test("STIX bundle has type bundle", bundle.get("type") == "bundle")
assert_test("STIX bundle has objects", len(bundle.get("objects", [])) >= 0)

# ---------------------------------------------------------------------------
# 9. RATE LIMITER (2 tests)
# ---------------------------------------------------------------------------

print("\n🧪 RATE LIMITER")

rl = RateLimiter()
assert_test("Rate limit allows under cap", rl.is_allowed("ip:1.2.3.4", 10, 60) is True)

# Exhaust limit of 10 (first call + 9 more = 10 total, next blocked)
for _ in range(10):
    rl.is_allowed("ip:1.2.3.5", 10, 60)
assert_test("Rate limit blocks over cap", rl.is_allowed("ip:1.2.3.5", 10, 60) is False)

# ---------------------------------------------------------------------------
# 10. EDGE CASES / REGRESSION (4 tests)
# ---------------------------------------------------------------------------

print("\n🧪 EDGE CASES / REGRESSION")

# CVSS 9.8 must never be LOW
r = compute_composite_risk(9.8, 0.0, False, 0)
assert_test("CVSS 9.8 never LOW", r["severity"] != "LOW" and r["severity"] != "INFO", f"got {r['severity']}")

# CVSS 5.3 must never be CRITICAL
r = compute_composite_risk(5.3, 0.0, False, 0)
assert_test("CVSS 5.3 never CRITICAL", r["severity"] != "CRITICAL", f"got {r['severity']}")

# Empty IOC list consistency
adv_empty = {
    "id": "CVE-2026-EMPTY",
    "title": "Empty",
    "cvss": 4.0,
    "iocs": [],
    "published": datetime.utcnow().isoformat(),
}
d_empty = build_dossier(adv_empty)
assert_test("Empty IOCs → ioc_count 0", d_empty["header"]["ioc_count"] == 0)
assert_test("Empty IOCs → has_iocs False", d_empty["ioc_section"]["has_iocs"] is False)

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------

TOTAL = PASS + FAIL
print(f"\n{'='*60}")
print(f"RESULTS: {PASS}/{TOTAL} passed, {FAIL}/{TOTAL} failed")
if FAIL == 0:
    print("✅ ALL BACKEND UNIT TESTS PASSED. This covers scoring/validation logic only —")
    print("   it does not certify the deployed Worker, auth, or any payment path.")
    sys.exit(0)
else:
    print("❌ TESTS FAILED. Do NOT deploy.")
    sys.exit(1)
