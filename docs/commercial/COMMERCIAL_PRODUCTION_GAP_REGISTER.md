# Commercial Production Gap Register

**Audit date:** 2026-08-10
**Severity legend:** P0 = cannot safely sell · P1 = major customer/business failure · P2 = material friction · P3 = optimization

Each entry lists exactly what was found, where, and why it matters. Entries marked **[ESCALATE]** are business, staffing, or architecture decisions this audit will not make unilaterally, per the task's own stop-condition list ("price fundamentally inconsistent with actual deliverable," "critical authentication/authorization bypass"). Entries marked **[FIXED]** were resolved directly in this branch — see `COMMERCIAL_PRODUCTION_READINESS_AUDIT_2026-08-10.md` for the diff summary. Entries marked **[DOCUMENTED ONLY]** are real but were judged unsafe to fix blind (touch live deploy credentials/infra, or need a product decision this audit can't make).

**Read GAP-018 first, then GAP-000.** GAP-018 (near the end of this document, added last) is a live production-correctness incident affecting `cyberdudebivash.in`'s real API, discovered on 2026-08-10 via a founder-provided Cloudflare dashboard screenshot — it supersedes GAP-000 as the single most urgent item here. GAP-000 was found by directly testing the live production site during this audit (not inferred from source alone) and remains the most urgent *ARMY-specific* item.

---

### GAP-000 — The live production dashboard at army.cyberdudebivash.in is broken for real visitors right now, and the Cloudflare Worker is not actually serving that domain
**Severity:** P0 · **Status: partially [FIXED in this branch] (client-side defect) / partially [ESCALATE] (domain routing — outside repo)**
**Offering:** Threat Command ARMY dashboard — the free lead-generation tool every paid-tier CTA depends on
**How this was found:** Live HTTP requests to the production domain during this audit (2026-08-10, ~10:04 UTC), then a faithful Node.js reproduction of `index.html`'s exact client-side logic against the real responses. This is directly observed evidence, not inference from source code.

**Finding, precisely:**
1. `https://army.cyberdudebivash.in/` returns HTTP 200, but response headers (`x-github-request-id`, `x-github-edge-region`, Fastly `via`/`x-served-by`) prove it is served by **GitHub Pages**, serving this repository's static root `index.html` byte-for-byte (`diff` confirmed identical) — **not** by the Cloudflare Worker in `worker/src/index.js`, even though `worker/wrangler.toml:6` configures `CORS_ORIGIN = "https://army.cyberdudebivash.in"` as if the Worker owns that domain.
2. `https://army.cyberdudebivash.in/api/feed` and `https://army.cyberdudebivash.in/api/<anything>` both return **HTTP 404** with GitHub Pages' own 404 page (same header signature). GitHub Pages is a static host with no server-side routing, so the Worker's entire `/api/*` proxy — CORS handling, upstream transform, everything in `worker/src/index.js:40-79` — is unreachable at this domain today, regardless of whether the Worker deploys successfully to Cloudflare.
3. Root `index.html`'s own client-side code (`index.html:76-95`) therefore always fails its first fallback URL (`army.cyberdudebivash.in/api/feed`, 404) and falls through to calling `https://cyberdudebivash.in/api/v1/intel/kev.json` **directly**, bypassing the Worker's transform entirely. That live upstream response was fetched and inspected during this audit: it has no `advisories` key, and its `feed` key is the **string** `"cisa-kev"` (a data-source label), not an array — the real advisory list is under `items`.
4. `index.html:115` computes `const advisories = data.advisories || data.feed || [];`, which resolves to the string `"cisa-kev"`. `index.html:123` then calls `advisories.slice().sort(...)`. This was reproduced directly in this session and throws:
   ```
   TypeError: advisories.slice(...).sort is not a function
   ```
   uncaught, inside `async function init()`, with no `try/catch` around the call site.

**Customer impact (verified, not hypothetical):** A real visitor to `https://army.cyberdudebivash.in/` right now sees the header and metric skeletons load, "Loading intelligence stream..." never resolves, the four metric tiles never populate, and no error is shown (the error banner only fires on an explicit `maintenance` flag, which this path never sets — the status dot stays green/"API LIVE" throughout). **The free product that every paid-tier "Upgrade to Full API Access" CTA depends on cannot currently be evaluated by a prospective customer landing on the primary marketed URL.**
**Revenue impact:** Direct — this is the top of the entire funnel described in `ecosystem/ecosystem.html`, and it is not converting anyone today because it never finishes loading.
**Root cause:** Two independent, compounding issues — (a) DNS/custom-domain routing for `army.cyberdudebivash.in` currently points at GitHub Pages rather than the Cloudflare Worker (a dashboard/DNS-level configuration not represented in this repository — `worker/wrangler.toml` has no `routes` block, so this binding, if it ever existed, lives entirely outside source control), and (b) `index.html`'s fallback parsing does not defend against a non-array `feed` field, which the real upstream API returns.
**Evidence:** Live `curl -sI` header captures and a full Node.js reproduction performed in this session (see commit for the fix); `worker/wrangler.toml:6`; `index.html:76-124`.
**Recommended fix:**
- **(b), the client-side defect — [FIXED in this branch]:** hardened the advisory-list resolution in both `index.html` and the Worker's embedded dashboard template to require an actual array (`Array.isArray(...)` check) before treating a field as the advisory list, falling back to the "no active advisories" empty state instead of crashing when the shape doesn't match. This is a pure defensive fix — it cannot make a working case behave differently, only makes a malformed response degrade gracefully instead of throwing.
- **(a), the domain routing — [ESCALATE, outside this repository]:** this audit has no access to GitHub Pages custom-domain settings or the Cloudflare account's Workers Routes/custom-domain bindings, and no committed file controls either. Someone with dashboard access needs to decide, urgently: either bind `army.cyberdudebivash.in` to the Cloudflare Worker (so the `/api/*` proxy and its transform actually run) and remove the competing GitHub Pages custom-domain claim, or make a deliberate decision that the static `index.html` is now the canonical ARMY surface and retire the Worker's proxy ambitions for this domain. Right now the system is in an unintended hybrid state.
**Dependencies:** Cloudflare account access and GitHub repository Pages settings — both outside this session's access.
**Test requirement:** After any routing change, repeat the exact live test performed in this audit: `curl -sI https://army.cyberdudebivash.in/api/feed` must return JSON with `content-type: application/json` from a Cloudflare-Worker-signed response (no `x-github-request-id` header), not a 404.
**Rollback requirement:** Domain/DNS changes should be made with the previous configuration recorded before changing it, since this audit cannot see or restore the current dashboard-level settings.
**Update (2026-08-10, founder-provided dashboard screenshot):** the routing question is now three-way, not two-way — see GAP-005's update. There's a second, misconfigured Cloudflare Worker (`cyberdudebivash-army-api`, serving static assets only, zero bindings) that could plausibly be what the custom domain is bound to instead of GitHub Pages or the correct `cyberdudebivash-security-hub`. Whoever resolves this needs to check which of the three `army.cyberdudebivash.in` is actually pointed at before changing anything. Separately: the client-side dependency on `cyberdudebivash.in` this gap originally described has now been removed entirely (see GAP-015) — once routing is fixed to reach a real Worker running this repo's code, ARMY no longer needs `cyberdudebivash.in` to be healthy at all.

---

### GAP-001 — Enterprise tier "24/7 SOC Monitoring" is priced below Indian market cost-of-delivery, with no supporting tooling or staffing evidence
**Severity:** P0 · **Status: [ESCALATE]**
**Offering:** Enterprise subscription (₹49,999/month)
**Customer impact:** A paying customer may believe they have continuous security monitoring when they do not — the worst-case outcome is an undetected breach during a period the customer believed was covered.
**Revenue impact:** Chargeback/refund/reputational risk if a customer discovers the gap after an incident; potential legal exposure if "24/7 SOC Monitoring" is read as a contractual commitment.
**Security impact:** Indirect but severe — customers may under-invest in their own monitoring because they believe this is covered.
**Operational impact:** Sustaining genuine 24/7 human coverage requires shift staffing or mature automation; neither exists in this repository, and market data suggests the price itself is below what monitoring-only coverage costs in the Indian MSSP market.
**Root cause:** Marketing copy (`ecosystem/ecosystem.html:511-524`) was written ahead of either the automation or the staffing needed to deliver it.
**Evidence:** `ecosystem/ecosystem.html:511-524`; zero SOC/monitoring/alerting tooling anywhere in this repository; external market data in `CUSTOMER_VALUE_AND_PRICING_AUDIT.md`.
**Recommended fix:** Founder must confirm, in writing, what "24/7 SOC Monitoring" actually means operationally today (staffed team, on-call rotation, automated alerting reviewed on a schedule, or aspirational). Either the delivery model needs to be built to match the claim, or the claim needs to be narrowed to what is actually delivered (e.g., "business-hours monitoring with automated after-hours alerting").
**Dependencies:** Business decision; not a code change.
**Test requirement:** N/A until a delivery model is chosen.
**Rollback requirement:** N/A.

---

### GAP-002 — MSSP tier sells a multi-tenant white-label dashboard that does not exist in any form
**Severity:** P0 · **Status: [ESCALATE]**
**Offering:** MSSP (custom pricing)
**Customer impact:** An MSSP prospect could be quoted and sold a product (white-label, multi-tenant dashboard, reseller API rights) that has to be built from scratch after the sale.
**Revenue impact:** Risk of an unfulfillable contract if sold as "available now" rather than as a custom-build engagement.
**Security impact:** N/A directly, though building multi-tenancy later without a tenant-isolation design from day one is a common source of cross-tenant data leaks.
**Operational impact:** None today (nothing to operate) — but any signed MSSP deal creates an unbuilt-product delivery obligation.
**Root cause:** Same pattern as GAP-001 — the marketing page describes the target ecosystem state, not the current one.
**Evidence:** `ecosystem/ecosystem.html:525-537`; the live dashboard (`worker/src/index.js`) has no tenant/account concept of any kind — confirmed by full source review.
**Recommended fix:** Sell MSSP as a scoped custom-build/partnership engagement explicitly, not as an available product, until multi-tenancy exists.
**Dependencies:** Business decision.
**Test requirement:** N/A.
**Rollback requirement:** N/A.

---

### GAP-003 — The only paid-tier-aware backend in the repo has no authentication, and its unauthenticated ingestion endpoint reintroduces a previously-fixed issue
**Severity:** P1 (would be P0 the moment this file is deployed as-is) · **Status: [ESCALATE — architecture decision required before deployment]**
**Offering:** Underlies Pro/Enterprise API access claims
**Customer impact:** None today (not deployed). If deployed as CI's own `deploy-backend` job describes, any anonymous caller gets identical access to a "starter"-tier subscriber, and anyone can `POST` fabricated advisories into the threat feed customers see.
**Revenue impact:** Total — there is no mechanism by which a paying customer would get anything a non-paying visitor doesn't.
**Security impact:** Data-integrity: unauthenticated write access to `/api/v1/ingest` would let anyone inject fake CVE/severity data into a feed customers are meant to trust for prioritization decisions.
**Operational impact:** None today (dormant code).
**Root cause:** `check_rate_limit(request, "starter")` (`cyberdudebivash_army_backend.py:585, 567`) hardcodes a tier literal instead of deriving it from any authenticated identity; no auth mechanism (API key, JWT, secret header) exists anywhere in the file. **Historical regression context:** commit `d53e92f` ("P0 fix: use Cloudflare INGEST_SECRET binding for ingestion auth", 2026-08-09) previously added secret-gated ingestion to the *old* Worker-based ingestion path. That entire feature (ingestion + the fix) was removed in the subsequent full rewrite to the current Worker (`worker/src/index.js`, which has no ingest route at all), and the *new* Python backend that replaced it (`v185.1`, commit `0b2c307`) was written with an ingest endpoint but without carrying forward the secret-gating pattern. This is not an active regression (the vulnerable code was never deployed), but it is a repeated pattern: the same class of fix has now had to be "discovered" twice.
**Evidence:** `cyberdudebivash_army_backend.py:465-480, 543-591`; `git show d53e92f`; `.github/workflows/deploy.yml:36-49` (the "still runs OLD code" admission).
**Recommended fix:** Before any deployment of this backend: (1) add real authentication (API key issuance tied to the actual payment/entitlement system, wherever that lives), (2) derive tier from that identity rather than a hardcoded literal, (3) require a secret/signature on `/api/v1/ingest` specifically. This needs to be designed against whatever payment/entitlement system actually exists (likely on `intel.cyberdudebivash.com`, outside this repo) — this audit does not have visibility into that system and will not guess at its shape.
**Dependencies:** Visibility into the real entitlement/payment system.
**Test requirement:** Auth-bypass regression tests before deployment (attempt unauthenticated access to every tier-gated route; must fail closed).
**Rollback requirement:** N/A — not deployed.

---

### GAP-004 — GitHub Pages CI publishes the entire repository root, including backend source, deploy scripts, the test suite, and a committed Cloudflare account-cache file, to a public URL on every push to main
**Severity:** P1 · **Status: [FIXED in this branch]**
**Offering:** Cross-cutting (affects repo hygiene, not a specific SKU)
**Customer impact:** None directly — this is an internal exposure issue, not a customer-facing defect.
**Revenue impact:** Low direct impact; reputational/competitive risk from publishing backend source and internal deploy tooling publicly.
**Security impact:** `worker/.wrangler/cache/wrangler-account.json` (containing the live Cloudflare account ID and the owner's Google account email) was tracked in git with no `.gitignore` anywhere in the repository, and two separate workflows (`deploy-frontend.yml`, `static.yml`) published the entire repo root (`path: '.'`) to GitHub Pages on every push to `main`. Nothing catastrophic was exposed (no API keys or credentials were found in any tracked file), but this is live, current, unintended public exposure of internal-only material, and the complete absence of a `.gitignore` means the *next* file someone commits (a `.env`, a real key) would be published the same way.
**Operational impact:** Two workflows racing to deploy the same static content to the same GitHub Pages target is pure redundancy with no benefit.
**Root cause:** No `.gitignore` was ever added; the Pages workflows were written to publish the whole repo rather than a scoped public directory; `static.yml` and `deploy-frontend.yml` were both kept after apparently being created at different times (git history shows `static.yml` predates `deploy-frontend.yml`) without removing the older duplicate.
**Evidence:** `.github/workflows/deploy-frontend.yml`, `.github/workflows/static.yml` (both: `path: '.'`, same `pages` concurrency group); `worker/.wrangler/cache/wrangler-account.json` tracked in git; `git ls-files` confirms no `.gitignore` existed.
**Recommended fix (applied):** Added a `.gitignore` covering build caches and untracked the wrangler account-cache file; removed the duplicate `static.yml` workflow; narrowed `deploy-frontend.yml`'s published path to only the public marketing assets (`index.html`, `ecosystem/`).
**Dependencies:** None — purely additive, does not touch the Cloudflare Worker deploy path.
**Test requirement:** Confirm the narrowed Pages workflow still publishes `index.html` and `ecosystem/ecosystem.html` correctly (structural review done; live verification requires a merge to `main`, which this audit does not perform).
**Rollback requirement:** Revert the workflow file change; no data migration involved.

---

### GAP-005 — THREE independent, uncoordinated Cloudflare Worker deploy mechanisms, at least one of which is actively failing
**Severity:** P1 · **Status: [DOCUMENTED ONLY — do not blind-fix live deploy credentials/infra]**
**Update (2026-08-10, discovered via this PR's own CI activity):** this is worse than originally scoped. There is a **third** deploy mechanism beyond the two GitHub Actions workflows below: Cloudflare's native "Workers Builds" Git integration, configured entirely in the Cloudflare dashboard (no corresponding file in this repository) and connected directly to this GitHub repo. It builds on pushes independently of the GitHub Actions workflows. **It failed on this PR's own commit** (`6c844961`, check run "Workers Builds: cyberdudebivash-army-api", conclusion `failure`, `dash.cloudflare.com` build logs not accessible without dashboard credentials). Two concrete, evidence-based observations about why:
- The failing check and its Cloudflare dashboard URL both reference a Worker script named **`cyberdudebivash-army-api`**.
- `worker/wrangler.toml:1` declares `name = "cyberdudebivash-security-hub"` — a **different name** — while `worker/package.json:2` declares `"name": "cyberdudebivash-army-api"`, matching the dashboard project instead.
- This mismatch was not introduced by this PR (neither name field was touched by any commit in this branch) and, since both files are otherwise unchanged from `main`, almost certainly predates it and would reproduce on `main` too. It is the leading candidate root cause: if Cloudflare's Git-integration build step validates or relies on the `wrangler.toml` name matching the connected dashboard service, a mismatch here would explain a build failure with no code-level bug involved.
- **Update (2026-08-10, founder-provided dashboard screenshot):** confirmed directly. `cyberdudebivash-army-api`'s dashboard page shows **Bindings: 0** ("No workers bound to this worker") and the message **"Metrics is unavailable for Workers with only static assets."** That second line means Cloudflare is serving this deployment as a static-file host, not running any Worker script at all — no `fetch()`/`scheduled()` handler, nothing dynamic. This is consistent with the Git integration's build settings pointing at the repo root instead of the `worker/` subdirectory: without finding `worker/wrangler.toml` there, it has nothing telling it to run a Worker script, so it silently falls back to publishing static files (`index.html` happens to be sitting right there at the root). This is almost certainly why hitting this service's routes returns static-page-like content with no working `/api/*`.
- **Not fixed in this branch.** Renaming a field or reconfiguring a Git-integration build setting are both dashboard-side actions this audit cannot perform. **Recommended resolution (given to the founder directly):** don't try to repair `cyberdudebivash-army-api` — disconnect/delete it and confirm `army.cyberdudebivash.in`'s custom domain is bound to `cyberdudebivash-security-hub` (the service `wrangler.toml` actually declares, with the correct KV binding, already published successfully by the working `deploy-worker.yml` GitHub Actions job). That collapses three competing deploy paths down to one correct one instead of trying to fix a redundant, misconfigured second/third path.

### GAP-005a — Two Cloudflare Worker deploy *workflows* (GitHub Actions side) with different secret names, both triggered by the same pushes
**Severity:** P1 · **Status: [DOCUMENTED ONLY — do not blind-fix live deploy credentials]**
**Offering:** Cross-cutting (deployment of the one live product, the ARMY Worker)
**Customer impact:** Deploy failures/delays to the only live customer-facing surface in this repository.
**Revenue impact:** Indirect — downtime or stale threat-feed data during firefighting windows reduces the credibility of the free tool that drives upgrade CTAs.
**Security impact:** None directly.
**Operational impact:** High, already demonstrated: 6 of the repository's 21 total commits (29%) are CI/deploy firefighting — three "EMERGENCY: fix worker" commits, two "ci: fix wrangler..." commits, and the branch's own tip commits ("toml fix", "deploy fix") — evidence this pipeline has been unstable very recently.
**Root cause:** `deploy-worker.yml` triggers on push to `main` touching `worker/**` and expects a secret named `CLOUDFLARE_API_TOKEN`; `deploy.yml`'s `deploy-worker` job triggers on *any* push to `main`/`hotfix/*` and expects `CF_API_TOKEN` + `CF_ACCOUNT_ID`. Any push touching `worker/**` fires both. If only one secret pair is actually configured in the repository, the other workflow fails loudly every time, which matches the observed emergency-fix pattern.
**Evidence:** `.github/workflows/deploy-worker.yml:1-30`, `.github/workflows/deploy.yml:16-35`; `git log --oneline` showing the firefighting commit sequence.
**Recommended fix:** Consolidate to a single worker-deploy workflow with one secret pair. **Not done in this branch** — this audit cannot verify which secret pair is actually populated in the repository's settings, and picking wrong would risk breaking the one live product surface immediately after a very recent stabilization ("deploy fix" is the current branch tip). This needs to be resolved by whoever has access to the repository's Actions secrets, with a real deploy verification step.
**Dependencies:** Access to GitHub repository secrets (outside this audit's access).
**Test requirement:** A successful `wrangler deploy` run against the real Cloudflare account after consolidation.
**Rollback requirement:** Keep the currently-working workflow untouched until the replacement is verified once.

---

### GAP-006 — Tested code and deployed code are different systems
**Severity:** P1 · **Status: [DOCUMENTED ONLY — business decision on scope]**
**Offering:** Underlies all "AI-powered" / "production-grade" scoring claims
**Customer impact:** None today — the well-tested logic (CVSS/EPSS/KEV floors, IOC validation, STIX export) is not reachable by any customer.
**Revenue impact:** The genuinely good work in `cyberdudebivash_army_backend.py` (53 passing tests, sound severity-floor logic) currently produces zero customer or revenue value because nothing customer-facing calls it.
**Security impact:** None directly, but see GAP-003 for what happens if it's connected without first closing the auth gap.
**Operational impact:** `.github/workflows/deploy.yml`'s `deploy-backend` job is a manual reminder, not an automated deploy — promoting this backend to production requires someone to SSH in and restart a service by hand, a founder-only manual dependency with no rollback automation.
**Root cause:** The backend was rewritten (v185.1) faster than the deployment path for it was built.
**Evidence:** `.github/workflows/deploy.yml:36-49`; `test_hotfix.py` (53/53 passing, verified by running in this session) importing and testing the backend module directly, with zero coverage of the deployed `worker/src/index.js`.
**Recommended fix:** Decide, explicitly, whether this backend is (a) worth finishing and connecting (requires auth per GAP-003, persistence, and an automated deploy path), or (b) retired in favor of whatever `cyberdudebivash.in`'s real upstream API already does. Either is a legitimate answer; leaving it in limbo is not, because the test suite's own closing line ("Platform is production-ready") gives a false impression to anyone reading CI output that this system is live. See GAP-009 for the immediate documentation-accuracy fix applied to that line.
**Dependencies:** Product decision.
**Test requirement:** N/A until a direction is chosen.
**Rollback requirement:** N/A.

---

### GAP-007 — Configured CORS restriction is never enforced
**Severity:** P2 · **Status: [DOCUMENTED ONLY]**
**Offering:** ARMY dashboard/API
**Customer impact:** None currently — the proxied data is public, non-sensitive threat-feed content.
**Root cause:** `wrangler.toml:6` declares `CORS_ORIGIN = "https://army.cyberdudebivash.in"`, but `worker/src/index.js` never reads `env.CORS_ORIGIN` (confirmed by grep) — it hardcodes `Access-Control-Allow-Origin: *` at three separate response sites (lines 19, 61, 74).
**Evidence:** `worker/wrangler.toml:6`; `worker/src/index.js:19,61,74`.
**Recommended fix:** Either read `env.CORS_ORIGIN` and enforce it, or delete the unused variable so config matches behavior. **Not fixed in this branch** — tightening CORS blind risks breaking the root `index.html` copy of the dashboard (served from a different origin, e.g. the GitHub Pages URL) that also calls these same endpoints cross-origin (`index.html:76-80`). This needs an explicit list of legitimate calling origins from the founder before enforcement is safe.
**Dependencies:** Confirmation of all legitimate calling origins.
**Test requirement:** Cross-origin fetch test from each legitimate origin after any change.
**Rollback requirement:** Revert to wildcard if a legitimate origin is broken.

---

### GAP-008 — Cron trigger and KV/Queue bindings were configured but unused (infra-as-code drift)
**Severity:** P2 · **Status: [FIXED in this branch]**
**Offering:** ARMY dashboard
**Root cause:** `wrangler.toml:12-13` configures a 6-hour cron trigger; `worker/src/index.js` exported no `scheduled()` handler, so each firing did nothing. `wrangler.toml:8-10` declares a `THREAT_INTEL_KV` binding that was never referenced in code.
**Evidence:** Original: `worker/wrangler.toml:1-13`; `worker/src/index.js` (no `scheduled` export, no `env.THREAT_INTEL_KV` reference).
**Fix applied:** the worker rewrite for GAP-015/standalone-ARMY (below) added a real `scheduled()` handler that proactively refreshes the KV cache every 6h, and `THREAT_INTEL_KV` is now genuinely used for response caching (verified: cold-cache fetch ~1s, warm-cache fetch ~16ms in this session's testing). The Queue binding referenced by `worker/src/index.js`'s `queue()` handler remains dashboard-provisioned, outside source control — that part of this gap is unchanged and still worth capturing in `wrangler.toml` if/when convenient, but is genuinely low priority (the handler is a harmless no-op either way).
**Test requirement:** Met — see GAP-015 for the live verification.
**Rollback requirement:** N/A — purely additive.

---

### GAP-009 — Test suite overclaims its own scope
**Severity:** P3 · **Status: [FIXED in this branch]**
**Offering:** Cross-cutting (engineering/QA honesty)
**Root cause:** `test_hotfix.py`'s docstring claims "42 tests"; running it produces 53 passing assertions. Its final line prints "✅ ALL TESTS PASSED. Platform is production-ready." — an overclaim, since the suite exercises pure Python scoring/validation functions only and touches none of: the deployed Worker, any auth, any payment path, or any entitlement logic.
**Evidence:** `test_hotfix.py:1-6, 286-293`; verified by running (`53/53 passed, 0/53 failed`).
**Recommended fix (applied):** Corrected the docstring's test count and reworded the closing message to describe what was actually verified (backend business-logic correctness) rather than asserting platform-wide production readiness.
**Dependencies:** None.
**Test requirement:** Re-run suite after edit; must still show 53/53 passing with updated messaging.
**Rollback requirement:** Trivial text revert.

---

### GAP-010 — `deploy.sh` has an incorrect path and prints false success for no-op steps
**Severity:** P3 · **Status: [FIXED in this branch]**
**Offering:** Cross-cutting (local tooling; not wired into CI)
**Root cause:** `deploy.sh:28` calls `wrangler deploy worker/index.js --name cyberdudebivash-army`, but the actual entry file is `worker/src/index.js` and `worker/wrangler.toml` already declares `main = "src/index.js"` — running this script as-is from the repo root would not deploy correctly. Its `backend` and `frontend` cases (lines 20-23, 35-38) print a green "✅ ... placeholder executed" success message while doing nothing.
**Evidence:** `deploy.sh:17-40`; confirmed this script is not referenced by any GitHub Actions workflow (CI has its own inline deploy steps).
**Recommended fix (applied):** Corrected the worker deploy invocation to run from the `worker/` directory (matching what the working CI workflows already do), and changed the placeholder messages to explicitly state "NOT IMPLEMENTED" instead of a false success checkmark.
**Dependencies:** None — this script is not invoked by CI, so the change carries no deployment risk.
**Test requirement:** Manual dry-run review (no live Cloudflare credentials available in this session to execute an actual deploy).
**Rollback requirement:** Trivial text/path revert.

---

### GAP-011 — No methodology evidence for consulting-style offers
**Severity:** P2 · **Status: [DOCUMENTED ONLY]**
**Offering:** DPDP Compliance Audit, AI Security Assessment
**Root cause:** These are plausibly human-delivered professional services, which don't require code — but nothing in the repository (template, checklist, sample redacted report) substantiates methodology or consistency of delivery.
**Evidence:** No matching files found anywhere in the repository.
**Recommended fix:** Produce a redacted sample deliverable or a documented methodology outline for each consulting offer. This is content work for the founder, not a code change.
**Dependencies:** Founder's subject-matter input.
**Test requirement:** N/A.
**Rollback requirement:** N/A.

---

### GAP-012 — "Email Support" and "Dedicated Account Manager" claims have no supporting infrastructure
**Severity:** P2 · **Status: [DOCUMENTED ONLY]**
**Offering:** Pro, Enterprise
**Root cause:** No ticketing, helpdesk, or automated-notification code exists anywhere in this repository. This may be entirely adequate today if support is handled manually via the listed `contact@cyberdudebivash.in` / WhatsApp channel at current volume — that is a legitimate small-business support model, not inherently a defect.
**Evidence:** `ecosystem/ecosystem.html:503-521`; no support-related code found repo-wide.
**Recommended fix:** No code fix needed at current scale. Flagged as a scaling risk: if paid-tier volume grows, manual WhatsApp/email support will not sustain an SLA-bearing "Dedicated Account Manager" claim without a real ticketing/ownership system.
**Dependencies:** None currently.
**Test requirement:** N/A.
**Rollback requirement:** N/A.

---

### GAP-013 — Duplicate, drifting dashboard implementations
**Severity:** P3 · **Status: [DOCUMENTED ONLY]**
**Offering:** ARMY dashboard
**Root cause:** `index.html` (repo root) and the HTML template embedded in `worker/src/index.js:93-195` are two independently maintained copies of the same dashboard UI. They have already diverged: the root copy fetches three hardcoded endpoints with client-side fallback (`index.html:76-95`); the Worker's embedded copy fetches only `/api/feed` and includes a "degraded data" banner the root copy lacks (`worker/src/index.js:159-189`).
**Evidence:** Full comparison of both files.
**Recommended fix:** Establish one source of truth (most likely the Worker-embedded copy, since that's what's actually served at the production domain per `wrangler.toml`) and either delete or clearly label the other as legacy. **Not fixed in this branch** — deleting `index.html` would change what GitHub Pages serves at the repo's Pages URL, which is a product/routing decision, not a pure bug fix.
**Dependencies:** Confirmation of which URL(s) each file is meant to serve.
**Test requirement:** Visual/functional parity check after consolidation.
**Rollback requirement:** Restore the deleted copy from git history.

---

### GAP-014 — The live production API quotes a different price list than this repository's marketing page
**Severity:** P1 · **Status: [ESCALATE — pricing decision, not a code bug]**
**Offering:** Pro / Enterprise / MSSP subscriptions
**How this was found:** Live HTTP request to `https://cyberdudebivash.in/api/v1/intel/kev.json` during this audit (2026-08-10). The response body includes an `upgrade.plans` array — real, structured, machine-readable pricing metadata returned by the production API itself, not marketing copy:

| Tier (live API) | Price (live API) | Daily limit | STIX | EPSS |
|---|---|---|---|---|
| STARTER | ₹999/mo | 2,000 | No | Yes |
| PRO | ₹1,499/mo | 20,000 | Yes | Yes |
| ENTERPRISE | ₹4,999/mo | Unlimited | Yes | Yes |
| MSSP | ₹9,999/mo | Unlimited | Yes | Yes |

Compare this repository's `ecosystem/ecosystem.html:498-537`:

| Tier (this repo's marketing page) | Price |
|---|---|
| Pro | ₹4,999/mo |
| Enterprise | ₹49,999/mo |
| MSSP | Custom |

**These do not reconcile.** The live API's "ENTERPRISE" tier price (₹4,999) is identical to the marketing page's "Pro" tier price — and the marketing page's "Enterprise" price (₹49,999) is exactly 10× the live API's top named tier (₹4,999). Either the marketing page describes a different, higher, human-sold bundle that legitimately layers on top of the API tiers (plausible, given the marketing "Enterprise" tier includes non-API items like a compliance audit and account manager), or the two price lists have simply drifted apart over time and nobody has reconciled them. This audit cannot tell which from source alone.
**Customer impact:** A prospective customer comparing the marketing page against the API's own self-reported pricing (which a technically curious buyer could easily find, since the endpoint is public and unauthenticated) would see two inconsistent numbers for what looks like the same product.
**Revenue impact:** Pricing confusion at the point of decision is a direct conversion risk.
**Root cause:** Unknown — these two pricing sources are maintained independently (one in this repo's static HTML, one server-side on `cyberdudebivash.in`, outside this repo) with no evidence of a shared source of truth.
**Evidence:** Live API response captured in this session; `ecosystem/ecosystem.html:498-537`.
**Recommended fix:** Founder should confirm whether the marketing "Pro/Enterprise/MSSP" tiers are meant to be the same product as the API's "STARTER/PRO/ENTERPRISE/MSSP" tiers or a deliberately distinct, higher human-sold bundle. If they're meant to be the same, one of the two price lists is stale and needs updating; if deliberately distinct, the marketing page should say so explicitly (e.g., "API tiers start at ₹999 — see API docs; the packages below bundle API access with human-delivered services").
**Dependencies:** Access to whatever maintains the live API's pricing metadata (outside this repo).
**Test requirement:** N/A — pricing/content decision.
**Rollback requirement:** N/A.

---

### GAP-015 — ARMY's data source depended entirely on cyberdudebivash.in's health; now fetches CISA KEV + FIRST.org EPSS directly
**Severity:** P1 · **Status: [FIXED in this branch]**
**Offering:** Threat Command ARMY dashboard/API
**Customer impact (before):** Whenever `cyberdudebivash.in`'s backend went down (confirmed happening during this same engagement — see the VPS deployment work), ARMY went down with it, despite being marketed and usable as if it were an independent product.
**Root cause:** `worker/src/index.js` proxied every request through `https://cyberdudebivash.in/api/v1/intel/kev.json`, and `index.html`'s fallback chain also called that domain directly. Neither had any data source that didn't ultimately depend on the main hub's backend being up.
**Fix applied:** `worker/src/index.js` now fetches directly from CISA's public KEV catalog (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) and FIRST.org's public EPSS API, both free and keyless, with no reference to `cyberdudebivash.in` anywhere in the fetch path. Results are cached in `THREAT_INTEL_KV` (1h freshness window) and proactively refreshed every 6h via a new `scheduled()` handler (closes GAP-008). `index.html`'s fallback chain was reduced to the one endpoint that matters (`army.cyberdudebivash.in/api/feed`) — its two `cyberdudebivash.in` fallback URLs were removed, since keeping them would have silently reintroduced the exact dependency being removed.
**Verification performed in this session (live, real data, not mocked):** cold-cache fetch returned 150 real advisories in ~1s; warm-cache fetch returned the same data in ~16ms; failure-path test (all outbound fetches forced to throw) correctly returned the existing honest `{maintenance:true, items:[]}` 503 response rather than crashing or fabricating data; `/api/health` and `/api/v1/intel/report/:cve_id` both verified against real CVE data.
**What did not change:** severity for these entries is derived from KEV+EPSS only (CISA's feed carries no CVSS field) using the same floor logic as `cyberdudebivash_army_backend.py`'s `compute_composite_risk()` — see GAP-016, which fixes a mismatch found in that exact logic while doing this work. CORS remains wildcard (unchanged reasoning from GAP-007 — multiple legitimate origins still need to read this, and the data is public/non-sensitive).
**Test requirement:** Met — see verification above. A live post-deploy check (`curl https://army.cyberdudebivash.in/api/feed`) is still needed once GAP-000/GAP-005's domain-routing question is resolved, since this fix cannot be observed at the production domain until traffic actually reaches this Worker.
**Rollback requirement:** Revert this commit; the previous proxy-based `worker/src/index.js` is in git history.

### GAP-016 — Backend severity floor for KEV-only advisories computed MEDIUM despite code/comment both saying HIGH
**Severity:** P2 · **Status: [FIXED in this branch]**
**Offering:** Underlies all CVSS/KEV/EPSS severity labeling, in both the Python backend and (as of GAP-015) the Worker
**How this was found:** Cross-checking `cyberdudebivash_army_backend.py`'s `compute_composite_risk()` against `map_cvss_to_severity()`'s own thresholds while porting the same logic into the new Worker code for GAP-015, to keep both systems consistent.
**Root cause:** For a KEV-listed advisory with no CVSS and no high-EPSS boost, `compute_composite_risk()` set `risk = max(risk, 5.0)` with an inline comment reading `# HIGH floor`. But `map_cvss_to_severity()` requires a score `>= 7.0` to return HIGH — `5.0` falls in its `>= 4.0` band, which is MEDIUM. The existing test for this branch (`test_hotfix.py`, "KEV only floor 5.0") only asserted `risk_score >= 5.0`, never checking the resulting `severity`, so this never surfaced as a failure despite 53/53 tests passing.
**Customer impact:** None today — this backend is still undeployed (GAP-006). Would have under-labeled confirmed-actively-exploited (KEV-listed) vulnerabilities as MEDIUM instead of HIGH the moment it went live, understating real risk to anyone relying on the severity label to prioritize patching.
**Fix applied:** Changed the floor to `7.0`, which actually lands in the HIGH band. Strengthened the test to assert `severity == "HIGH"` directly (not just the numeric floor), so this specific class of mismatch can't silently reappear. Also corrected a second, lower-stakes comment on the same block (an "INFO floor" of `0.5` that map_cvss_to_severity actually resolves to LOW, since INFO requires `< 0.1`) — left the value unchanged there since LOW is the more defensible label for "a real but low EPSS score exists" anyway, and changing it would have been a behavior change with no clear benefit.
**Evidence:** `cyberdudebivash_army_backend.py` (severity-floor block); `test_hotfix.py` ("KEV only" test, now asserts severity).
**Test requirement:** Met — `python3 test_hotfix.py` now 54/54 passing, including the new severity assertion.
**Rollback requirement:** Revert the two changed lines; trivial.

### GAP-017 — Evaluated and rejected a proposed "standalone ARMY worker" implementation that fabricated vulnerability data
**Severity:** N/A (nothing shipped) · **Status: evaluated, not deployed**
**Context:** Mid-engagement, a separately-generated `worker_standalone_army.js` (produced by a different AI tool, uploaded by the founder for review) proposed the same architectural direction as GAP-015 — decouple ARMY from `cyberdudebivash.in` by fetching CISA/EPSS directly. The direction was correct. The specific file was not usable as-is, for reasons worth recording so the same mistake isn't repeated:
- Its CISA URL (`https://api.cisa.gov/known-exploited-vulnerabilities/catalog`) and EPSS URL (`https://api.first.org/epss/v1/cve/{id}`) were tested live in this session and do not work — the CISA one doesn't connect at all, the EPSS one returns a 404 HTML page. The correct URLs are the ones now in `worker/src/index.js` (see GAP-015).
- Because both real fetches were wired to nonexistent endpoints, its `try/catch` fallback would fire on every single request, permanently serving 15 hardcoded fake advisories while labeling them "LIVE — Fresh from CISA." One of those fake entries reused a real CVE ID (`CVE-2026-8037`) with an entirely invented vendor/product/description that contradicts the real CISA record for that ID (verified against the real feed in this session).
- Its `wrangler_standalone.toml` scoped the KV binding under `[env.production]`, but the given deploy instructions (`wrangler deploy`, no `--env` flag) would deploy to the default environment, which has no KV binding — caching would have silently never activated.
- The proposed deployment method (copy files locally on Windows, run `wrangler deploy` directly) bypasses git and CI entirely, which would have reintroduced GAP-006 (deployed code diverging from repo code) immediately.
**Why this matters enough to record:** fabricating vulnerability data under a real CVE identifier and presenting it as live CISA intelligence is a direct violation of this whole engagement's evidence/no-fabrication mandate, not a minor bug. It's documented here specifically so a future contributor (human or AI) doesn't re-introduce a "fallback data" pattern that fabricates rather than honestly degrading — the correct pattern, used throughout this repo since GAP-000, is an honest `maintenance: true` / empty state on failure.
**Disposition:** Not merged, not deployed. GAP-015 implements the same underlying idea correctly.

### GAP-018 — This repo's Worker deploy target was a shared/entangled Worker also serving the main hub's real API; PR #5's deploy replaced its live behavior
**Severity:** P0 · **Status: [FIXED in this branch — code-side; live-side mitigation is the founder's action, not this audit's]**
**How this was found:** A founder-provided screenshot of the full Cloudflare "Workers & Pages" account listing, showing `cyberdudebivash-security-hub`'s bound routes as `cyberdudebivash.in/api` + 1 other route, with 10.8k recorded requests — i.e., actively serving the main hub's own API, not a route this ARMY project owns. Live-tested immediately after: `https://cyberdudebivash.in/api/health` and `https://cyberdudebivash.in/api/v1/intel/kev.json` were confirmed, at the time of this finding, to be returning this repository's ARMY worker payloads verbatim (`"version":"200.0-standalone"`, the same CISA LoadMaster entry ARMY's own feed returns) rather than whatever the main hub's real `/api` handler is supposed to serve.
**Root cause:** `worker/wrangler.toml` declared `name = "cyberdudebivash-security-hub"` — a name that (per this same screenshot) is bound in the Cloudflare dashboard to `cyberdudebivash.in/api`, a route this ARMY codebase has no business owning. No file in this repository ever declared that route binding (`wrangler.toml` has no `[routes]` block, confirmed by full-file review both before and after this fix) — it was configured directly in the Cloudflare dashboard, entirely outside this repository's visibility, at some point before this audit began. Every prior `wrangler deploy` from this repo's CI (`deploy-worker.yml`, `deploy.yml`) — not just PR #5's — has been replacing that shared Worker's script content with whatever this repo's `worker/src/index.js` happened to contain at the time. PR #5 made this newly visible because it changed the Worker's *behavior* (direct CISA/EPSS fetch instead of proxying to `cyberdudebivash.in`), producing an obviously-ARMY-shaped response on a route that should be main-hub-specific.
**Evidence this repo's `wrangler.toml` was the actual anomaly, not `cyberdudebivash-army-api`:** `worker/package.json:2` already declared `"name": "cyberdudebivash-army-api"`, and `worker/fix-wrangler.cmd` — a script already present in this repository before this audit touched anything — regenerates `wrangler.toml` with `name = "cyberdudebivash-army-api"` verbatim. Both predate this fix. `cyberdudebivash-security-hub` appears to have been a stale or mismerged value that ended up in the committed `wrangler.toml` despite two other artifacts in the same repo agreeing on the correct name.
**Customer/business impact:** For however long between PR #5's deploy and whenever this is caught and rolled back, any real caller of `cyberdudebivash.in/api/*` — the main hub's own frontend, any integration, any paying customer's API usage — received ARMY's threat-feed data instead of the main hub's actual API responses. Given the main hub's live frontend (confirmed via founder screenshot: Razorpay checkout present in its CSP, "Sentinel APEX ONLINE," live threat counters, "Book Demo" / "Sign In" flows) appears to be an actively-used, revenue-relevant platform, this is a real production-correctness incident, not a cosmetic one.
**Fix applied (code side):** `worker/wrangler.toml`'s `name` changed to `cyberdudebivash-army-api` — a pre-existing Worker in the same Cloudflare account confirmed (via the same screenshot) to have no custom routes bound, only its own `workers.dev` subdomain. This repo's CI will no longer deploy anything to `cyberdudebivash-security-hub` going forward. The KV namespace binding (`THREAT_INTEL_KV`) was left unchanged — it has only ever been used for ARMY's own feed cache (verified in this session's testing), so it's safe to keep bound under the new name.
**NOT fixed by this branch, and requires the founder's direct action:** the Worker `cyberdudebivash-security-hub` currently still has ARMY's code loaded live, still bound to `cyberdudebivash.in/api`. This audit has no way to know what the *correct* code for that route is — it was never in this repository — so it cannot be restored from here. **Recommended immediate action: Cloudflare dashboard → Workers & Pages → `cyberdudebivash-security-hub` → View deployments → roll back to whatever was deployed before this incident.** Separately, once `cyberdudebivash-army-api`'s build/route configuration is corrected (see GAP-005) and `army.cyberdudebivash.in` is bound to it, `cyberdudebivash-security-hub` should have no further connection to this repository or this codebase at all — treat the two as fully separate systems going forward, ideally owned by separate Cloudflare Worker names with no shared history.
**Dependencies:** Cloudflare dashboard access to roll back the live deployment; confirmation from whoever owns the main hub's real API of what should actually be running there.
**Test requirement:** After rollback, re-run the exact checks used to find this: `curl https://cyberdudebivash.in/api/health` should NOT return `"200.0-standalone"` or any ARMY-shaped payload.
**Rollback requirement (for this repo's own change):** Revert `worker/wrangler.toml`'s `name` field — trivial — though there is no reason to, since `cyberdudebivash-security-hub` should not be this project's deploy target under any circumstance now uncovered.

## Register summary

| ID | Title | Severity | Status |
|---|---|---|---|
| GAP-000 | **Live production dashboard broken for real visitors (verified by direct reproduction)** | **P0** | **PARTIALLY FIXED (client bug) / ESCALATE (domain routing)** |
| GAP-001 | Enterprise "24/7 SOC" price/claim mismatch | P0 | ESCALATE |
| GAP-002 | MSSP sells nonexistent multi-tenancy | P0 | ESCALATE |
| GAP-003 | No auth on paid-tier backend; ingestion auth regression pattern | P1 (P0 if deployed as-is) | ESCALATE |
| GAP-004 | Public exposure via GitHub Pages (whole repo + account cache) | P1 | **FIXED** |
| GAP-005 | Three independent Cloudflare deploy mechanisms; native Workers Builds confirmed serving static-assets-only, zero bindings | P1 | DOCUMENTED (confirmed via founder dashboard screenshot) |
| GAP-005a | Two GitHub-Actions-side deploy workflows also conflict | P1 | DOCUMENTED |
| GAP-006 | Tested code ≠ deployed code | P1 | DOCUMENTED |
| GAP-007 | CORS config not enforced | P2 | DOCUMENTED |
| GAP-008 | Dead cron/KV/Queue config | P2 | **FIXED** |
| GAP-009 | Test suite overclaims scope | P3 | **FIXED** |
| GAP-010 | `deploy.sh` wrong path + false success messages | P3 | **FIXED** |
| GAP-011 | No methodology evidence for consulting offers | P2 | DOCUMENTED |
| GAP-012 | Support claims lack infrastructure | P2 | DOCUMENTED |
| GAP-013 | Duplicate drifting dashboard copies | P3 | DOCUMENTED |
| GAP-014 | Live API pricing contradicts in-repo marketing pricing | P1 | ESCALATE |
| GAP-015 | ARMY depended entirely on cyberdudebivash.in's health | P1 | **FIXED** |
| GAP-016 | Backend severity-floor mislabeling (KEV-only → MEDIUM, not HIGH) | P2 | **FIXED** |
| GAP-017 | Rejected a proposed worker with fabricated fallback vulnerability data | N/A | Evaluated, not deployed |
| GAP-018 | **This repo's Worker deploy target was shared with the main hub's real API — PR #5 replaced its live behavior** | **P0** | **FIXED (code) / founder must roll back the live deployment** |

**Zero P0/P1 findings were resolved by silently editing customer-facing pricing or claims.** Per the task's governance rules, GAP-000 (domain-routing half), GAP-001, GAP-002, GAP-003, GAP-005, and GAP-006 require a business, staffing, or credentials-access decision this audit is not positioned to make, and are escalated explicitly rather than guessed at. **GAP-000/GAP-005 together are the founder's first action item regardless of read order** — a dashboard-side fix (delete or reconfigure `cyberdudebivash-army-api`, confirm `army.cyberdudebivash.in` is bound to `cyberdudebivash-security-hub`) that everything else, including the now-fully-independent ARMY data pipeline shipped as GAP-015, is waiting on to actually reach production.
