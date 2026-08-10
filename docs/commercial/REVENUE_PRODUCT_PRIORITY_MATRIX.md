# Revenue Product Priority Matrix

**Audit date:** 2026-08-10

**Tier legend:** T1 = sell immediately · T2 = sell after specific fixes · T3 = keep available but don't actively push · T4 = internal/demo only · T5 = retire/reposition

| Offering | Tier | Why |
|---|---|---|
| DPDP Compliance Audit ("starting at ₹49,999") | **T1** | Human-delivered, price plausible against Indian market rates for an entry-level engagement, doesn't depend on any of this repository's broken infrastructure. Only gap: no documented methodology/sample deliverable exists yet (GAP-011) — worth producing, but not a blocker to selling today if the founder can deliver competently. |
| Threat Command ARMY free dashboard | **T2** | Currently broken for real visitors (GAP-000). The client-side half is fixed in this branch; the domain-routing half needs the founder's action outside this repo. Once both are resolved, this is a solid, low-risk free lead-gen tool — it already has a working failure-mode fallback (AT-02 passed) and no sensitive data at risk. |
| Pro subscription (₹4,999/mo, per marketing page) | **T2** | The offer itself is plausible, but sell it only after: (1) reconciling GAP-014's price-list contradiction between this page and the live API's own `₹1,499` "PRO" tier, and (2) confirming the actual checkout at `intel.cyberdudebivash.com/upgrade.html` works — neither is verifiable from this repository. |
| Enterprise subscription (₹49,999/mo) | **T3** | Do not actively push until GAP-001 is resolved. The sales conversation (WhatsApp) works fine as a channel, but actively marketing "24/7 SOC Monitoring" at a price below Indian market cost-of-delivery risks selling something that can't be sustained, which is worse for the business than pausing active promotion while the claim is tightened or the delivery model is built out. |
| AI Security / Threat Intelligence / Cloud Security / Zero Trust consulting | **T3** | Plausible as founder-delivered expert services. Keep available, but tighten the marketing language to match actual delivery (e.g., don't imply automated/AI-model-based scanning if the delivery is manual expert review) before pushing hard on these. |
| MSSP (white-label, multi-tenant, custom pricing) | **T5 — reposition** | The product as described (multi-tenant white-label dashboard, reseller API rights) does not exist. Retire the "available now" framing and reposition as a custom-build partnership conversation until multi-tenancy is real — otherwise this is selling a roadmap as a product. |
| CVE/EPSS/KEV scoring engine + STIX export (`cyberdudebivash_army_backend.py`) | **T4** | Genuinely good, tested logic with real potential (STIX export in particular is a real SOC-integration differentiator) — but internal/undeployed today, with no auth (GAP-003) that must be closed before it ever faces a customer. Worth finishing, not worth selling yet. |

## Rationale summary

The single highest-leverage action available is **not** building anything new — it's (1) fixing GAP-000 so the free funnel actually works, which this branch does the code-fixable half of, and (2) reconciling GAP-014's pricing contradiction, which is a same-day content fix once the founder decides which price list is authoritative. Both are cheap relative to their effect on conversion. The DPDP audit is the cleanest immediate revenue line because it's the only paid offering in this inventory that doesn't depend on any of this repository's broken or unverified infrastructure.
