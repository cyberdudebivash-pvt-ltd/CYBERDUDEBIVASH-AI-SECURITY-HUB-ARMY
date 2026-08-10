# Commercial Production Gap Register

**Audit date:** 2026-08-10
**Severity legend:** P0 = cannot safely sell · P1 = major customer/business failure · P2 = material friction · P3 = optimization

Each entry lists exactly what was found, where, and why it matters. Entries marked **[ESCALATE]** are business, staffing, or architecture decisions this audit will not make unilaterally, per the task's own stop-condition list ("price fundamentally inconsistent with actual deliverable," "critical authentication/authorization bypass"). Entries marked **[FIXED]** were resolved directly in this branch — see `COMMERCIAL_PRODUCTION_READINESS_AUDIT_2026-08-10.md` for the diff summary. Entries marked **[DOCUMENTED ONLY]** are real but were judged unsafe to fix blind (touch live deploy credentials/infra, or need a product decision this audit can't make).

**Read GAP-000 first.** It was found by directly testing the live production site during this audit (not inferred from source alone) and is the single most urgent item in this register, ahead of every P0 pricing/claim finding below.

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
- **Not fixed in this branch.** Renaming either field is a guess without Cloudflare dashboard access to confirm which name the live, DNS-bound Worker service actually is — get it wrong and a currently-working deploy path could break instead. This needs someone with dashboard access to check the actual build log and confirm before either name is changed.

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

### GAP-008 — Cron trigger and KV/Queue bindings are configured but unused (infra-as-code drift)
**Severity:** P2 · **Status: [DOCUMENTED ONLY]**
**Offering:** ARMY dashboard
**Root cause:** `wrangler.toml:12-13` configures a 6-hour cron trigger; `worker/src/index.js` exports no `scheduled()` handler, so each firing does nothing. `wrangler.toml:8-10` declares a `THREAT_INTEL_KV` binding never referenced in code. A Cloudflare Queue exists (per the code comment at `worker/src/index.js:84`) that isn't declared in `wrangler.toml` at all — dashboard-provisioned infrastructure not captured in source control.
**Evidence:** `worker/wrangler.toml:1-13`; `worker/src/index.js:9-92` (full file reviewed, no `scheduled` export, no `env.THREAT_INTEL_KV` reference).
**Currently harmless because:** the Worker fetches the upstream feed fresh on every HTTP request rather than depending on a cron-refreshed cache, so the dead cron trigger doesn't cause stale data today.
**Recommended fix:** Either implement real scheduled ingestion (matching the "updated every 6 hours" marketing claim on `ecosystem/ecosystem.html`) or remove the unused cron trigger and KV binding so configuration reflects reality. **Not fixed in this branch** — this is a live-infrastructure config change (`wrangler.toml`) that deploys automatically via CI on merge to `main`; changing it should be a deliberate, watched deploy, not a blind edit in an audit branch.
**Dependencies:** Product decision on whether scheduled ingestion is actually wanted.
**Test requirement:** If implemented, verify the `scheduled()` handler fires and updates the customer-visible feed.
**Rollback requirement:** Revert `wrangler.toml` cron entry.

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

## Register summary

| ID | Title | Severity | Status |
|---|---|---|---|
| GAP-000 | **Live production dashboard broken for real visitors (verified by direct reproduction)** | **P0** | **PARTIALLY FIXED (client bug) / ESCALATE (domain routing)** |
| GAP-001 | Enterprise "24/7 SOC" price/claim mismatch | P0 | ESCALATE |
| GAP-002 | MSSP sells nonexistent multi-tenancy | P0 | ESCALATE |
| GAP-003 | No auth on paid-tier backend; ingestion auth regression pattern | P1 (P0 if deployed as-is) | ESCALATE |
| GAP-004 | Public exposure via GitHub Pages (whole repo + account cache) | P1 | **FIXED** |
| GAP-005 | Three independent Cloudflare deploy mechanisms; native Workers Builds actively failing on a name mismatch | P1 | DOCUMENTED (evidence: live CI failure on this PR) |
| GAP-005a | Two GitHub-Actions-side deploy workflows also conflict | P1 | DOCUMENTED |
| GAP-006 | Tested code ≠ deployed code | P1 | DOCUMENTED |
| GAP-007 | CORS config not enforced | P2 | DOCUMENTED |
| GAP-008 | Dead cron/KV/Queue config | P2 | DOCUMENTED |
| GAP-009 | Test suite overclaims scope | P3 | **FIXED** |
| GAP-010 | `deploy.sh` wrong path + false success messages | P3 | **FIXED** |
| GAP-011 | No methodology evidence for consulting offers | P2 | DOCUMENTED |
| GAP-012 | Support claims lack infrastructure | P2 | DOCUMENTED |
| GAP-013 | Duplicate drifting dashboard copies | P3 | DOCUMENTED |
| GAP-014 | Live API pricing contradicts in-repo marketing pricing | P1 | ESCALATE |

**Zero P0/P1 findings were resolved by silently editing customer-facing pricing or claims.** Per the task's governance rules, GAP-000 (domain-routing half), GAP-001, GAP-002, GAP-003, GAP-005, and GAP-006 require a business, staffing, or credentials-access decision this audit is not positioned to make, and are escalated explicitly rather than guessed at. **GAP-000 is the one finding in this register verified by directly exercising the live production system rather than by source review alone, and it should be the founder's first action item regardless of read order.**
