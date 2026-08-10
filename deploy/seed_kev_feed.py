"""
seed_kev_feed.py — Populate the backend's ingestion pipeline with real,
public threat-intelligence data.

WHY THIS EXISTS: cyberdudebivash_army_backend.py's IngestionPipeline starts
empty in memory and nothing in the backend automatically fetches CVE data.
Deploying the backend alone gets you {"count": 0, "advisories": []} — a
200 instead of a 503, but still no data. This script closes that gap using
two real, public, no-API-key-required sources:

  1. CISA's Known Exploited Vulnerabilities (KEV) catalog — the same
     authoritative source this codebase's marketing already claims to use.
     https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  2. FIRST.org's EPSS API — real exploitation-probability scores, batched
     per request (no per-CVE rate limit like NVD's).
     https://api.first.org/data/v1/epss

CVSS is intentionally NOT fetched here: NVD's public API is rate-limited to
5 requests/30s without a key, which does not scale to KEV's 1,000+ entries.
Every advisory ingested here has cvss=None; the backend's own, already-tested
compute_composite_risk() floor rules (cyberdudebivash_army_backend.py) handle
KEV+EPSS-only scoring correctly — this script does not compute or guess a
CVSS score anywhere. If NVD access becomes practical later (e.g. with an API
key), add a CVSS lookup step here rather than fabricating one.

This script POSTs to the backend's own /api/v1/ingest endpoint rather than
touching its in-memory store directly, so it exercises the same validation,
dedup, and quality-gate logic any other client would. NOTE: that endpoint
currently has no authentication (see docs/commercial/COMMERCIAL_PRODUCTION_GAP_REGISTER.md,
GAP-003) — if/when auth is added there, this script's ingest() call needs a
credential added alongside it.

Usage:
  python seed_kev_feed.py [--limit N] [--backend-url URL]

Intended to run periodically via the systemd timer in deploy/systemd/.
"""

from __future__ import annotations
import argparse
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100  # FIRST.org accepts a comma-separated cve list per request
DEFAULT_BACKEND_URL = "http://127.0.0.1:8000"
DEFAULT_LIMIT = 150  # recent KEV entries only — matches the product's own
                      # "FREE tier = recent items" framing observed on the
                      # live API during the commercial audit, and keeps this
                      # script's runtime and the EPSS batch count reasonable.


def fetch_kev_catalog() -> list[dict]:
    resp = httpx.get(KEV_URL, timeout=30.0, follow_redirects=True)
    resp.raise_for_status()
    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    # Most recent first
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    return vulns


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    scores: dict[str, float] = {}
    for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        batch = cve_ids[i : i + EPSS_BATCH_SIZE]
        try:
            resp = httpx.get(
                EPSS_URL, params={"cve": ",".join(batch)}, timeout=20.0
            )
            resp.raise_for_status()
            for row in resp.json().get("data", []):
                try:
                    scores[row["cve"]] = float(row["epss"])
                except (KeyError, ValueError, TypeError):
                    continue
        except httpx.HTTPError as e:
            print(f"  WARN: EPSS batch lookup failed ({e}); continuing without it", file=sys.stderr)
        time.sleep(0.5)  # be polite to a free public API
    return scores


def to_advisory(kev_entry: dict, epss: float | None) -> dict:
    cve_id = kev_entry.get("cveID", "")
    date_added = kev_entry.get("dateAdded", "")
    try:
        published = datetime.fromisoformat(date_added).replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        published = datetime.now(timezone.utc).isoformat()

    return {
        "id": cve_id,
        "cve_id": cve_id,
        "title": kev_entry.get("vulnerabilityName", cve_id),
        "description": kev_entry.get("shortDescription", ""),
        "cvss": None,  # deliberately not fabricated — see module docstring
        "epss": epss,
        "kev": True,
        "source_url": KEV_URL,
        "published": published,
        "affected_versions": f"{kev_entry.get('vendorProject', '')} {kev_entry.get('product', '')}".strip(),
        "iocs": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    args = parser.parse_args()

    print(f"Fetching CISA KEV catalog...")
    vulns = fetch_kev_catalog()[: args.limit]
    print(f"  {len(vulns)} recent entries (of catalog total) selected")

    cve_ids = [v["cveID"] for v in vulns if v.get("cveID")]
    print(f"Fetching EPSS scores for {len(cve_ids)} CVEs...")
    epss_map = fetch_epss_scores(cve_ids)
    print(f"  {len(epss_map)} EPSS scores retrieved")

    ingested = duplicates = stalled = failed = 0
    with httpx.Client(base_url=args.backend_url, timeout=10.0) as client:
        for entry in vulns:
            advisory = to_advisory(entry, epss_map.get(entry.get("cveID")))
            try:
                resp = client.post("/api/v1/ingest", json=advisory)
            except httpx.HTTPError as e:
                print(f"  FAIL {advisory['cve_id']}: {e}", file=sys.stderr)
                failed += 1
                continue
            if resp.status_code == 200:
                ingested += 1
            elif resp.status_code == 409:
                duplicates += 1
            elif resp.status_code == 202:
                stalled += 1
            else:
                print(f"  FAIL {advisory['cve_id']}: HTTP {resp.status_code} {resp.text[:200]}", file=sys.stderr)
                failed += 1

    print(f"\nDone. ingested={ingested} duplicates={duplicates} stalled={stalled} failed={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
