# Master Commercial Asset Inventory

**Audit date:** 2026-08-10
**Repository:** `cyberdudebivash-pvt-ltd/CYBERDUDEBIVASH-AI-SECURITY-HUB-ARMY`
**Branch audited:** `claude/cyberdudebivash-readiness-audit-xc98ma` (HEAD `65a1e3d`)
**Method:** every claim below was checked against source in this repository. Nothing here is inferred from README prose, prior audit documents, or marketing copy alone — where marketing copy is the only source, that is stated explicitly and the item is marked `UNVERIFIED / EXTERNAL`.

## Scope disclosure (read first)

This repository contains **one** deployable product surface: the "Threat Command ARMY" live threat-feed dashboard and its API proxy. The repository's own marketing page (`ecosystem/ecosystem.html`) advertises a six-platform ecosystem plus three paid subscription tiers and six enterprise service lines. **Five of the six platforms, and the entire purchase/payment/entitlement path for every paid tier, live outside this repository** (on `cyberdudebivash.in`, `intel.cyberdudebivash.com`, `tools.cyberdudebivash.com`, `blog.cyberdudebivash.in`, `academy.cyberdudebivash.com`, and `api.cyberdudebivash.in`). This session had no access to those systems. Every finding about them below is marked `UNKNOWN` or `EXTERNAL / UNVERIFIABLE`, per the governance rule against assuming unverified capability.

Also confirmed absent from this repository: `CLAUDE.md`, `README.md`, `DOCUMENTATION_INDEX.md`, `KPI_DASHBOARD.md`, `GENERAL_AVAILABILITY_REPORT.md`, and any prior audit or `docs/` tree. There was no historical documentation to use as investigative leads — this inventory was built from source code alone.

---

## Asset 1: Threat Command ARMY — live dashboard + API proxy

| Field | Value |
|---|---|
| Category | Free lead-generation product (live CVE/threat feed viewer) |
| Customer | Security practitioners, CISOs, SOC analysts browsing for threat intel |
| Buyer | Same (self-serve, no purchase in this asset) |
| Problem it addresses | "What critical CVEs / threat advisories are active right now?" |
| Customer outcome | A ranked list (top 20, sorted by severity) of advisories with CVE ID, title, severity badge |
| Current price | **Free.** No paywall exists in the code path. |
| Pricing source | N/A — CTA button links out to `https://cyberdudebivash.in/#pricing` (external, unverifiable) |
| Payment SKU | None |
| Frontend entry point | `index.html` (root) and the HTML template embedded in `worker/src/index.js:93-195` — these are two independently-maintained near-duplicate copies of the same dashboard |
| Backend handler | `worker/src/index.js` `fetch()` handler, `/api/*` branch (lines 40-79) |
| API | Proxies to `https://cyberdudebivash.in/api/v1/intel/kev.json` (external system, not in this repo) |
| Database | None used. `wrangler.toml` declares a KV namespace (`THREAT_INTEL_KV`, id `4778dfcff095404c9ba4eec59e658c3e`) but `worker/src/index.js` never references `env.THREAT_INTEL_KV` — confirmed by grep, zero hits. The binding is dead configuration. |
| Authentication | None |
| Authorization | None (nothing to authorize — all data is public) |
| Tenant isolation | N/A — single global feed, no per-customer data |
| Dependencies | Live availability of `cyberdudebivash.in`'s API (external, unverifiable). On failure, Worker returns a 503 with a `maintenance: true` JSON payload and the frontend renders a "temporarily unavailable" banner (`worker/src/index.js:65-78`, `index.html:107-112`) — this fallback path is real and does work. |
| Output | HTML table of advisories; no downloadable report, no PDF, no email |
| Report | None |
| Email | None — no email sending code exists anywhere in the repository |
| Support | None in-product. Marketing page lists a contact email and WhatsApp number (`ecosystem/ecosystem.html:552-572`) — this is a generic company contact channel, not a ticketing or support system tied to this product |
| Documentation | None (no user-facing docs found) |
| Current status | **LIVE (asset exists and is deployed)**, but functions purely as a free demo/lead-gen surface, not a transactable product |
| Evidence | `worker/src/index.js:1-92`, `index.html:1-158`, `worker/wrangler.toml:1-13` |
| Known limitations | (1) CORS is hardcoded to `*` in code (`worker/src/index.js:19,61,74`) even though `wrangler.toml:6` declares `CORS_ORIGIN = "https://army.cyberdudebivash.in"` — the configured restriction is never read or enforced (grep confirms zero references to `env.CORS_ORIGIN`). (2) `wrangler.toml:12-13` configures a 6-hour cron trigger, but `worker/src/index.js` exports no `scheduled()` handler — the trigger fires against nothing. This happens to be harmless today because the Worker fetches the upstream feed fresh on every HTTP request rather than relying on a cron-refreshed cache, but the config is misleading about how the system actually works. (3) The Worker also exports a no-op `queue()` handler (lines 84-90) with a comment stating it exists only "because worker has Queue binding in dashboard" — i.e., there is Cloudflare infrastructure (a Queue) provisioned out-of-band in the Cloudflare dashboard that is not represented anywhere in this repository's `wrangler.toml`. Infra-as-code is incomplete. |

---

## Asset 2: CYBERDUDEBIVASH AI Security Hub ARMY — FastAPI backend

| Field | Value |
|---|---|
| Category | Internal / undeployed backend service |
| Customer | N/A — not reachable by any customer today |
| Buyer | N/A |
| Problem it (would) address | CVE/EPSS/KEV-based composite risk scoring, IOC validation, STIX 2.1 export, per-CVE "dossier" report generation |
| Customer outcome | N/A — not connected to any customer-facing surface |
| Current price | N/A |
| Frontend entry point | **None.** No frontend in this repo calls this backend. |
| Backend handler | `cyberdudebivash_army_backend.py` (620 lines), FastAPI app, 5 routes: `/api/health`, `/api/v1/intel/kev.json`, `/api/v1/intel/stix.json`, `/api/v1/intel/report/{cve_id}`, `/api/v1/ingest`, `/api/feed` |
| Database | **None.** `IngestionPipeline` (line 382) stores everything in a plain Python `dict`/`set` in process memory — restarting the process silently discards all ingested data. Comment at line 386 reads `# In-memory; replace with DB in prod`. |
| Authentication | **None.** No API key, JWT, session, or credential check exists anywhere in this file (confirmed by repo-wide grep for `auth`, `jwt`, `api_key`, `token` — zero matches in Python or JS source). |
| Authorization / tier enforcement | **Not functional.** `check_rate_limit()` (line 465) takes a `tier` string, but every call site passes a **hardcoded literal** — `"free"` or `"starter"` — rather than deriving tier from any authenticated identity (lines 545, 567, 576, 585, 596). Concretely: `/api/v1/ingest` and `/api/v1/intel/stix.json` are written as if gated to paying "starter" customers, but any anonymous caller gets exactly the same "starter" rate limit as a real subscriber, because there is no mechanism anywhere that distinguishes a payer from a stranger. |
| Rate limiting | In-memory, per-process, keyed by client IP (`RateLimiter` class, line 443). Comment at line 444: `# Replace with Redis in prod`. Resets on restart; does not work across multiple instances/replicas. |
| Tenant isolation | N/A — no tenant concept exists |
| Dependencies | `requirements.txt`: `fastapi`, `uvicorn`, `pydantic` only. No payment SDK, no auth library, no DB driver, no email SDK, no queue client. |
| Output | JSON "dossier" via `build_dossier()` (line 324) — CVSS/EPSS/KEV risk score, IOC table, templated "AI insight" text, and a **formulaic financial-impact estimate** (`"$10K – $250K"` fixed string, or `$1,873,920 × risk/10` for severe cases — line 365-369) that is not derived from any real loss data, telemetry, or customer environment. This is scenario framing, not a measured financial-impact calculation, and should not be presented to a customer as one. |
| Report | The dossier is the report. No PDF/export renderer exists — output is raw JSON. |
| Email | None |
| Support | None |
| Documentation | Module docstring only (lines 1-5) |
| Current status | **INTERNAL / NOT DEPLOYED.** This is the load-bearing piece of evidence for the whole audit: `.github/workflows/deploy.yml`'s `deploy-backend` job (lines 40-49) does not deploy anything — it only prints: *"⚠️ MANUAL BACKEND DEPLOY REQUIRED — Your live API (cyberdudebivash.in) still runs OLD code. SSH into your server and restart with the new backend file."* The project's own CI pipeline states, in committed source, that the tested backend is not what's running in production. |
| Evidence | `cyberdudebivash_army_backend.py:1-620`, `.github/workflows/deploy.yml:36-49`, `requirements.txt:1-3` |
| Known limitations | Well-structured business logic (severity floors, IOC dedup, STIX export) with a genuinely useful 53-assertion unit-test suite (`test_hotfix.py`) — but the logic is disconnected from any deployed, customer-reachable system, has no persistence, no auth, and no working tier enforcement. "Production-grade" (its own docstring, line 3) is not supported by evidence. |

---

## Asset 3: Ecosystem Hub marketing page

| Field | Value |
|---|---|
| Category | Marketing / lead-generation page |
| Customer | Prospective enterprise buyers, SOC teams, CISOs |
| Frontend entry point | `ecosystem/ecosystem.html` (single static file, no backend) |
| Current price | N/A — not itself a product; advertises prices for products/services hosted elsewhere |
| Payment SKU | None. All CTAs are either `mailto:`, `wa.me` (WhatsApp deep links), or outbound links to other subdomains — **zero in-page checkout of any kind.** |
| Backend handler | None — pure static HTML/CSS/JS, no server logic, no form submission target |
| Authentication | N/A |
| Current status | Static asset, presumed live (identical content is duplicated into `worker/src/index.js`'s dashboard template for the ARMY-specific portion, but `ecosystem.html` itself is the fuller hub page) |
| Evidence | `ecosystem/ecosystem.html:1-649` |
| Known limitations | Every commercial claim on this page (pricing, "Powered by Razorpay," compliance badges, platform statuses) is asserted in HTML with no supporting backend in this repository. See `CUSTOMER_VALUE_AND_PRICING_AUDIT.md` and the Marketing Truth Audit section of the CEO report for the claim-by-claim breakdown. |

---

## Claimed offerings with no implementation evidence in this repository

The table below lists every priced or service offering named in `ecosystem/ecosystem.html`. For each, "Evidence in repo" states exactly what exists; where the answer is "none," that is a factual statement about this repository, **not** a claim that the offering doesn't exist elsewhere.

| Offering | Claimed price | Claimed delivery | Evidence in this repo |
|---|---|---|---|
| Pro subscription | ₹4,999/mo | "Threat Intelligence API Access, Real-time CVE Alerts, Basic AI Security Scan, Email Support, Community Access" | CTA links to `https://intel.cyberdudebivash.com/upgrade.html` (external). No checkout, entitlement, or API-key issuance code exists here. |
| Enterprise subscription | ₹49,999/mo | "DPDP Compliance Audit, AI Security Assessment, 24/7 SOC Monitoring, Dedicated Account Manager, Custom API Integration" | CTA is a WhatsApp chat link (`wa.me/918179881447`). Manual sales conversation, not a self-serve purchase. No SOC tooling, no account-management system, no compliance-audit tooling exists in this repo. |
| MSSP | Custom | "White-label Threat Intel, Multi-tenant Dashboard, SOC-as-a-Service, Custom SLA & Reporting, API Reseller Rights" | CTA is a WhatsApp chat link. No multi-tenant code exists anywhere in this repo — the dashboard has no tenant concept at all. |
| DPDP Compliance Audit | "Starting at ₹49,999" | Data governance framework, privacy impact assessment, compliance roadmap | No audit tooling, templates, or workflow of any kind in this repo. This reads as a professional-services (human-delivered) offer. |
| AI Security service | Not priced on page | "Prompt injection defense, LLM vulnerability assessment, AI model security auditing, adversarial AI testing" | No scanning tooling, no LLM test harness, no prompt-injection test suite exists in this repo. The one "AI" component that does exist (`generate_ai_insight()` in the unused backend) is template string concatenation over CVSS/EPSS/KEV values — not a model, not adversarial testing, and not deployed. |
| Threat Intelligence service | Not priced separately | "Real-time CVE monitoring, dark web intelligence, IOC feeds, predictive threat analytics" | CVE/IOC logic exists (Asset 2) but is undeployed. "Dark web intelligence" and "predictive threat analytics" have zero corresponding code anywhere in the repository. |
| SOC / MSSP service | Bundled into Enterprise/MSSP tiers | "24/7 Security Operations Center, managed security services, incident response" | No monitoring, alerting, ticketing, or on-call tooling exists in this repo. |
| Cloud Security service | Not priced | "Cloud infrastructure security assessment, container security, Kubernetes hardening" | No tooling evidence in this repo. |
| Zero Trust service | Not priced | "Zero Trust architecture design, identity-centric security, micro-segmentation" | No tooling evidence in this repo. |

## Ecosystem properties referenced but outside this repository's scope

| Property | Claimed role | Status per this audit |
|---|---|---|
| `cyberdudebivash.in` | Main hub; source of the KEV feed the ARMY Worker proxies | Not in this repo, but **live HTTP checks performed during this audit** (2026-08-10) provide real positive evidence: its Content-Security-Policy header explicitly allow-lists `checkout.razorpay.com`, `api.razorpay.com`, `rzp.io`, and sets `form-action` / `frame-src` for Razorpay — a genuine, currently-live Razorpay checkout integration, not just a marketing claim. The same domain's `/api/v1/intel/kev.json` endpoint is live, returns real-looking CISA KEV-sourced CVE data, and its response body includes an explicit `upgrade` object listing STARTER/PRO/ENTERPRISE/MSSP tiers with INR prices (₹999/₹1,499/₹4,999/₹9,999) and per-tier rate/result limits — **these numbers differ from the ₹4,999/₹49,999 tiers shown on this repo's `ecosystem/ecosystem.html`**, which is itself a finding (see Gap Register GAP-000 area / pricing audit) worth the founder's attention: the live API and the in-repo marketing page do not quote the same price list. |
| `intel.cyberdudebivash.com` ("Sentinel APEX") | The actual Pro-tier product with its own upgrade/checkout page | UNKNOWN — external |
| `tools.cyberdudebivash.com` | Security tools/scripts | UNKNOWN — external |
| `blog.cyberdudebivash.in` | Threat research content | UNKNOWN — external |
| `academy.cyberdudebivash.com` | Training programs | UNKNOWN — external; marketing page itself labels it "Beta" |
| `api.cyberdudebivash.in` | Referenced only in `worker/package.json:10`'s manual `ingest` npm script | UNKNOWN — external, third hostname distinct from the two above |

**Recommendation:** if a genuine ecosystem-wide commercial audit is required, the repositories backing these five properties need to be identified and added to this session's scope. Absent that, any readiness statement about them is speculation and is not made in this audit.
