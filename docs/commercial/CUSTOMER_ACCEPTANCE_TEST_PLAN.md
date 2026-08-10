# Customer Acceptance Test Plan

**Audit date:** 2026-08-10
**Method:** each step of the standard discover → purchase → use → support → close journey is marked **TESTABLE** (exercised in this session, with results) or **BLOCKED** (the system it depends on is outside this repository). No step below is marked "passed" without an actual test having been run.

## Journey coverage against this repository

| # | Step | In this repo? | Result |
|---|---|---|---|
| 1 | Discover offer | Yes — `ecosystem/ecosystem.html`, `index.html` | **TESTED, PARTIAL FAIL** — see AT-01 |
| 2 | Understand scope/pricing | Yes — marketing page | **TESTED, FAIL** — pricing is internally inconsistent with the live API (GAP-014) |
| 3 | Purchase / checkout | No — external (`intel.cyberdudebivash.com`, WhatsApp) | **BLOCKED — cannot test from this repo** |
| 4 | Authenticate | No — no auth exists in this repo at all | **BLOCKED** |
| 5 | Receive entitlement | No — no entitlement code in this repo | **BLOCKED** |
| 6 | Configure service | No | **BLOCKED** |
| 7 | Submit required information | No | **BLOCKED** |
| 8 | Execute service | Partially — the free feed itself | **TESTED, FAIL** — see AT-01 |
| 9 | Receive output | Yes, for the free tier | **TESTED, FAIL** — see AT-01 |
| 10 | Review output | Yes, for the free tier | Blocked by #9 |
| 11 | Contact support | Yes — `mailto:`/WhatsApp links present | **TESTED, PASS** (link presence only — response quality/SLA not testable) |
| 12 | Complete engagement | No | **BLOCKED** |
| 13 | Access next-step offer (upsell) | Yes — CTA present | **TESTED, PASS** (link presence; destination page not testable from this repo) |

---

## AT-01: Free dashboard discovery-to-output path (SUCCESS PATH)

**Steps:**
1. Visitor navigates to `https://army.cyberdudebivash.in/`
2. Page loads header, status indicator, and four metric tiles
3. Live threat feed populates with ranked advisories
4. Visitor clicks "Upgrade to Full API Access" to proceed toward a paid tier

**Actual result (tested live, 2026-08-10, via direct HTTP requests and a faithful reproduction of the page's client-side logic):**

| Step | Expected | Actual |
|---|---|---|
| 1 | Page loads | **PASS** — HTTP 200, correct HTML served |
| 2 | Skeletons show, then resolve | **PASS** (skeletons render) then **FAIL** (never resolve) |
| 3 | Feed populates with ranked CVEs | **FAIL** — an uncaught `TypeError` is thrown while parsing the live API's response (reproduced deterministically; see Gap Register GAP-000), so the feed never renders and the page is stuck on "Loading intelligence stream..." indefinitely, with the status dot still showing green/"API LIVE" |
| 4 | CTA reachable | **PASS** — the CTA link itself is present and points to `cyberdudebivash.in/#pricing`, but a visitor who never sees real data has little reason to click it |

**Verdict: FAIL.** This is not a theoretical edge case — it is the default behavior for any visitor arriving fresh at the production URL today, because the root cause (the custom domain not routing to the Worker) is not conditional on anything the visitor does. See Gap Register GAP-000 for the full root-cause chain and the fix applied to the client-side half of it in this branch.

**Regression test added:** none of the existing test suites (`test_hotfix.py`) cover the client-side JavaScript at all — this gap in test coverage is why the defect shipped undetected. A lightweight regression check was added as part of the GAP-000 fix (see PR diff) that asserts the advisory-list resolution logic only ever treats an actual array as the advisory list, covering exactly the malformed-response shape this audit found in production.

---

## AT-02: Upstream/API failure path (FAILURE PATH)

**Steps:** simulate the upstream feed being fully unreachable (all three fallback URLs fail or time out).

**Actual result (traced through `fetchWithFallback`, `index.html:82-95`):** `fetchWithFallback` returns `{ maintenance: true, message: '...' }` when every endpoint fails outright (network error/timeout). `renderFeed` correctly detects `data.maintenance` and shows the "Live feed temporarily unavailable" banner with a link to the main hub, sets the status dot to offline/red, and does **not** throw.

**Verdict: PASS.** The genuine full-outage path is handled gracefully. The defect in AT-01 is specifically triggered by a *partial* failure (first endpoint 404s, second endpoint succeeds but with an unexpected shape) — a case the original code didn't anticipate because it assumed any 2xx response would have a usable `advisories` or `feed` array.

---

## AT-03: Paid-tier purchase path

**Status: BLOCKED — cannot be tested from this repository.**

No checkout, login, or entitlement code exists anywhere in this codebase for Pro, Enterprise, or MSSP. The Pro tier's CTA points to `https://intel.cyberdudebivash.com/upgrade.html`; Enterprise and MSSP CTAs open a WhatsApp chat. Testing this path requires access to `intel.cyberdudebivash.com` (a separate system) and, for the WhatsApp-initiated tiers, is inherently a manual human sales process that a source-code audit cannot exercise. **This is a scope limitation, not a claim that these paths don't work.**

---

## AT-04: Report/output delivery for a paid engagement

**Status: BLOCKED — no deliverable-generation system for any paid offering exists in this repository.**

The one report-generation engine that does exist — `build_dossier()` in `cyberdudebivash_army_backend.py` — is not connected to any customer-facing surface (see Master Asset Inventory, Asset 2; Gap Register GAP-006). There is nothing to test end-to-end.

---

## AT-05: Security abuse checks performed (read-only, non-destructive, against this repo's own code paths)

Consistent with the task's instruction to avoid destructive testing, only passive/read-only checks were performed — no credential brute-forcing, no write attempts against production, no denial-of-service testing.

| Check | Method | Result |
|---|---|---|
| Unauthenticated access to "paid-tier" backend routes | Source review of `cyberdudebivash_army_backend.py` | **Confirmed exposed by design** — there is no authentication to bypass; `check_rate_limit(request, "starter")` grants "starter" rate limits to every caller unconditionally (see Gap Register GAP-003). Not exploited against a live target because this backend is not deployed. |
| CORS wildcard on the live Worker | Live response headers, `curl -sI` | **Confirmed** — `access-control-allow-origin: *` observed on live responses (see Gap Register GAP-007). Low severity given the data is public. |
| IDOR on report endpoints | Source review of `/api/v1/intel/report/{cve_id}` | Not applicable in the traditional sense — there is no authorization boundary at all (any ID, if the backend were live, returns data to anyone), which is the same finding as the auth gap above, not a separate access-control bypass between distinct customers. |
| SSRF surface | Source review of all `fetch()`/`httpx` call sites | **None found** — the Worker's only outbound fetch target is a hardcoded constant (`MAIN_API`, `worker/src/index.js:7`), not user-controlled input. No SSRF surface exists in this codebase. |
| Injection (SQL/NoSQL/command) | Source review | **None found** — there is no database in this repository; the only persistence is in-memory Python dicts. No query-construction code exists to inject into. |
| XSS on rendered feed data | Source review of DOM-insertion code | Advisory titles are inserted via `escapeHtml()` (`index.html:143-147`) / the equivalent `esc()` helper (`worker/src/index.js:190`) before being placed in `innerHTML` — both use `textContent` assignment then read `innerHTML` back, which is a correct escaping pattern. **No XSS found in the reviewed rendering paths.** |
| Webhook replay / payment idempotency | Source review | **N/A — no webhook or payment code exists anywhere in this repository** to test. |
| Rate-limit bypass | Source review of `RateLimiter` (backend) | Keyed only by client IP with no identity binding — trivially bypassed by IP rotation, but since there's no working tier distinction to bypass into (see above), this doesn't currently grant access to anything additional. Documented as a latent weakness for whenever real entitlement is added. |

**No destructive or exploitative action was taken against any live system.** All live-system checks in this audit were unauthenticated `GET`/`HEAD` requests to publicly documented, public-facing URLs already linked from the repository's own marketing page — the same requests any browser makes when a visitor loads the site.

---

## Net acceptance verdict

**Today, a synthetic customer cannot complete the full journey using only what exists in this repository**, and — more urgently — **cannot even reliably complete step 1-3 (discover → view free output) at the primary marketed URL**, due to the live defect documented as GAP-000. Steps 3-7 and 12 are blocked by systems outside this repository's visibility, not proven broken; steps 11 and 13 pass at the link-presence level. This plan should be re-run after GAP-000's domain-routing half is resolved, and extended to cover `intel.cyberdudebivash.com` directly if/when that repository is made available for audit.
