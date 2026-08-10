/**
 * CYBERDUDEBIVASH AI Security Hub — Cloudflare Worker (ARMY, standalone) v200.0
 * Entry: worker/src/index.js
 *
 * ARMY is a standalone threat-intelligence feed. It fetches directly from
 * CISA's Known Exploited Vulnerabilities catalog and FIRST.org's EPSS API —
 * both public, no key required — and has NO dependency on cyberdudebivash.in.
 * A prior version proxied through cyberdudebivash.in; that meant ARMY went
 * down whenever the main hub's backend did, which is the wrong architecture
 * for what's meant to be an independently sellable product.
 *
 * On any fetch failure this returns an honest "temporarily unavailable"
 * state — never fabricated advisories. See docs/commercial/COMMERCIAL_PRODUCTION_GAP_REGISTER.md
 * (GAP-015) for why that matters: an earlier draft of this rewrite hardcoded
 * 15 fake vulnerabilities as a "fallback," including one that reused a real
 * CVE ID with an entirely invented description. That was caught before
 * shipping and is not what this file does.
 */

const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss';
const CACHE_KEY = 'army_feed_v2';
const CACHE_FRESH_MS = 60 * 60 * 1000; // 1h — served straight from KV within this window
const RECENT_LIMIT = 150; // most recent KEV entries only — keeps EPSS batch calls and
                           // Worker subrequest count small; matches the "recent items on
                           // the free tier" framing already used elsewhere in this project
const EPSS_BATCH_SIZE = 100; // FIRST.org accepts a comma-separated cve list per request

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    if (path === '/' || path === '/index.html') {
      return new Response(ARMY_HTML, {
        headers: {
          'Content-Type': 'text/html',
          'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        },
      });
    }

    if (path === '/api/health') {
      return jsonResponse({
        status: 'healthy',
        version: '200.0-standalone',
        source: 'CISA KEV + FIRST.org EPSS (direct, no cyberdudebivash.in dependency)',
        timestamp: new Date().toISOString(),
      });
    }

    if (path === '/api/feed' || path === '/api/v1/intel/kev.json') {
      const result = await getFeed(env, ctx);
      if (!result) {
        return jsonResponse(
          { maintenance: true, message: 'Live feed temporarily unavailable.', feed: [], items: [] },
          503,
        );
      }
      return jsonResponse({
        feed: result.items,
        items: result.items,
        count: result.items.length,
        cached: result.cached,
        source: 'CISA KEV + FIRST.org EPSS',
        updated_at: new Date(result.generatedAt).toISOString(),
      });
    }

    if (path.startsWith('/api/v1/intel/report/')) {
      const cveId = decodeURIComponent(path.split('/').pop() || '');
      const result = await getFeed(env, ctx);
      const advisory = result && result.items.find((a) => a.cve_id === cveId);
      if (!advisory) {
        return jsonResponse({ error: 'Advisory not found', cve_id: cveId }, 404);
      }
      return jsonResponse({ ...advisory, report_generated: new Date().toISOString() });
    }

    return new Response('Not Found', { status: 404, headers: corsHeaders() });
  },

  // Proactively refreshes the KV cache every 6h (wrangler.toml's existing
  // cron trigger). Previously this trigger fired against a Worker with no
  // scheduled() export at all — dead config that did nothing on every
  // invocation. This is what actually makes it do something: most real
  // requests now hit a warm cache instead of paying the CISA/EPSS fetch
  // cost inline.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(refreshFeed(env));
  },

  // Required because a Queue binding exists on this Worker in the Cloudflare
  // dashboard (not represented in wrangler.toml — see GAP-008 in the gap
  // register). Nothing in this codebase publishes to it; this only exists
  // so the Worker doesn't error on an unhandled queue consumer.
  async queue(batch) {
    for (const message of batch.messages) message.ack();
  },
};

// ---- Feed fetch + cache -----------------------------------------------

async function getFeed(env, ctx) {
  try {
    const cached = await env.THREAT_INTEL_KV.get(CACHE_KEY, 'json');
    if (cached && Array.isArray(cached.items) && Date.now() - cached.generatedAt < CACHE_FRESH_MS) {
      return { items: cached.items, generatedAt: cached.generatedAt, cached: true };
    }
  } catch (e) {
    // KV unavailable — fall through to a live fetch rather than failing outright
  }

  const fresh = await refreshFeed(env);
  if (fresh) return { items: fresh.items, generatedAt: fresh.generatedAt, cached: false };

  // Live fetch failed. Serve stale cache if we have any — better than
  // nothing, and still real, previously-fetched data, not a fabrication.
  try {
    const stale = await env.THREAT_INTEL_KV.get(CACHE_KEY, 'json');
    if (stale && Array.isArray(stale.items) && stale.items.length) {
      return { items: stale.items, generatedAt: stale.generatedAt, cached: true };
    }
  } catch (e) {
    // no cache to fall back to either
  }
  return null;
}

async function refreshFeed(env) {
  try {
    const items = await fetchLiveThreatData();
    if (!items || !items.length) return null;
    const record = { items, generatedAt: Date.now() };
    try {
      await env.THREAT_INTEL_KV.put(CACHE_KEY, JSON.stringify(record), { expirationTtl: 6 * 3600 });
    } catch (e) {
      // Cache write failed — still return the freshly-fetched data to the caller
    }
    return record;
  } catch (e) {
    console.error('refreshFeed failed:', e.message);
    return null;
  }
}

async function fetchLiveThreatData() {
  const kevRes = await fetch(CISA_KEV_URL, { cf: { cacheTtl: 1800, cacheEverything: true } });
  if (!kevRes.ok) throw new Error('CISA KEV HTTP ' + kevRes.status);
  const kevData = await kevRes.json();
  const vulns = (kevData.vulnerabilities || [])
    .slice()
    .sort((a, b) => (b.dateAdded || '').localeCompare(a.dateAdded || ''))
    .slice(0, RECENT_LIMIT);

  const cveIds = vulns.map((v) => v.cveID).filter(Boolean);
  const epssMap = await fetchEpssScores(cveIds);

  return vulns.map((v) => toAdvisory(v, epssMap.get(v.cveID) ?? null));
}

async function fetchEpssScores(cveIds) {
  const scores = new Map();
  for (let i = 0; i < cveIds.length; i += EPSS_BATCH_SIZE) {
    const batch = cveIds.slice(i, i + EPSS_BATCH_SIZE);
    try {
      const res = await fetch(`${EPSS_URL}?cve=${batch.join(',')}`, { cf: { cacheTtl: 3600, cacheEverything: true } });
      if (!res.ok) continue;
      const data = await res.json();
      for (const row of data.data || []) {
        const v = parseFloat(row.epss);
        if (!Number.isNaN(v)) scores.set(row.cve, v);
      }
    } catch (e) {
      // EPSS enrichment is best-effort — a failed batch just leaves those
      // CVEs with epss=null, never a guessed value
    }
  }
  return scores;
}

function toAdvisory(kevEntry, epss) {
  return {
    cve_id: kevEntry.cveID || 'UNKNOWN',
    title: kevEntry.vulnerabilityName || kevEntry.cveID || 'Untitled Advisory',
    summary: kevEntry.shortDescription || '',
    // CISA's KEV feed does not include a CVSS score — never invent one.
    cvss: null,
    epss,
    kev: true,
    severity: severityFromKevEpss(epss),
    published: kevEntry.dateAdded ? `${kevEntry.dateAdded}T00:00:00Z` : new Date().toISOString(),
    vendor: kevEntry.vendorProject || 'Unknown',
    product: kevEntry.product || 'Unknown',
    required_action: kevEntry.requiredAction || 'See CISA KEV catalog for remediation guidance.',
    due_date: kevEntry.dueDate || null,
    iocs: [],
    source: 'CISA KEV',
  };
}

// Mirrors the (corrected) KEV/EPSS floor logic in
// cyberdudebivash_army_backend.py's compute_composite_risk(): every entry
// here is KEV=true by construction (it came from the KEV catalog), which is
// itself a floor at HIGH (confirmed active exploitation); high EPSS on top
// of that floors at CRITICAL. No CVSS is ever available from this source,
// so there is no CVSS-based branch to mirror.
function severityFromKevEpss(epss) {
  if (epss !== null && epss >= 0.5) return 'CRITICAL';
  return 'HIGH';
}

// ---- HTTP helpers -------------------------------------------------------

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

// ---- Dashboard ------------------------------------------------------------

const ARMY_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
<title>CYBERDUDEBIVASH ARMY — Standalone AI Threat Intel Feed</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0a0a0f;color:#e0e0e0;font-family:'Segoe UI',Roboto,sans-serif;line-height:1.6}
  .container{max-width:1200px;margin:0 auto;padding:20px}
  header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #1f1f2e;padding-bottom:16px;margin-bottom:24px;flex-wrap:wrap;gap:12px}
  .brand{font-size:1.5rem;font-weight:700;color:#00f0ff;text-transform:uppercase;letter-spacing:1px}
  .brand span{color:#888;font-size:0.7rem;display:block;font-weight:400;text-transform:none;letter-spacing:0;margin-top:2px}
  .status{display:flex;align-items:center;gap:8px;font-size:0.85rem}
  .dot{width:10px;height:10px;border-radius:50%;background:#00ff88;animation:pulse 2s infinite}
  .dot.offline{background:#ff4444;animation:none}
  @keyframes pulse{0%{opacity:1}50%{opacity:.4}100%{opacity:1}}
  .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px}
  .metric-card{background:#12121f;border:1px solid #1f1f2e;border-radius:8px;padding:20px;text-align:center}
  .metric-value{font-size:2rem;font-weight:700;color:#00f0ff}
  .metric-label{font-size:0.8rem;color:#888;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px}
  .skeleton{background:#1f1f2e;border-radius:4px;height:2rem;width:60%;margin:0 auto;animation:shimmer 1.5s infinite}
  @keyframes shimmer{0%{opacity:.4}50%{opacity:.8}100%{opacity:.4}}
  .feed{background:#12121f;border:1px solid #1f1f2e;border-radius:8px;overflow:hidden}
  .feed-header{background:#1a1a2e;padding:16px 20px;font-weight:600;border-bottom:1px solid #1f1f2e;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
  .feed-header .source{color:#00f0ff;font-size:0.75rem;font-weight:400}
  .feed-item{padding:14px 20px;border-bottom:1px solid #1f1f2e;display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap}
  .feed-item:hover{background:#1a1a2e}
  .feed-item:last-child{border-bottom:none}
  .cve-id{font-family:monospace;color:#00f0ff;font-weight:600}
  .cve-meta{color:#666;font-size:0.75rem;margin-top:4px}
  .severity-badge{padding:4px 10px;border-radius:4px;font-size:0.75rem;font-weight:700;text-transform:uppercase;white-space:nowrap}
  .CRITICAL{background:#ff4444;color:#fff}
  .HIGH{background:#ff8800;color:#000}
  .MEDIUM{background:#ffcc00;color:#000}
  .LOW{background:#00ff88;color:#000}
  .UNKNOWN{background:#888;color:#fff}
  .error-banner{background:#ff44441a;border:1px solid #ff4444;color:#ff8888;padding:16px;border-radius:8px;margin-bottom:20px;display:none}
  .cta{margin-top:24px;text-align:center}
  .cta a{display:inline-block;background:#00f0ff;color:#0a0a0f;padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:700;text-transform:uppercase;letter-spacing:0.5px}
  .cta a:hover{background:#00c0cc}
  footer{margin-top:40px;text-align:center;color:#555;font-size:0.8rem;border-top:1px solid #1f1f2e;padding-top:20px}
  @media(max-width:640px){.feed-item{flex-direction:column}}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">🔒 CYBERDUDEBIVASH ARMY<br><span>Standalone AI Threat Intelligence Feed</span></div>
    <div class="status"><span class="dot" id="statusDot"></span><span id="statusText">LOADING</span></div>
  </header>

  <div class="error-banner" id="errorBanner">
    ⚠️ Live feed temporarily unavailable. <a href="https://cyberdudebivash.in" style="color:#00f0ff">Visit main hub →</a>
  </div>

  <div class="metrics">
    <div class="metric-card"><div class="metric-value" id="advCount"><div class="skeleton"></div></div><div class="metric-label">Threat Advisories</div></div>
    <div class="metric-card"><div class="metric-value" id="critCount"><div class="skeleton"></div></div><div class="metric-label">Critical</div></div>
    <div class="metric-card"><div class="metric-value" id="highCount"><div class="skeleton"></div></div><div class="metric-label">High</div></div>
    <div class="metric-card"><div class="metric-value" id="kevCount"><div class="skeleton"></div></div><div class="metric-label">Known Exploited</div></div>
  </div>

  <div class="feed">
    <div class="feed-header">
      <span>📡 Live Threat Feed — Known Exploited Vulnerabilities</span>
      <span class="source">Source: CISA KEV Catalog + FIRST.org EPSS</span>
    </div>
    <div id="feedBody"><div style="padding:20px;text-align:center;color:#555">Loading intelligence stream...</div></div>
  </div>

  <div class="cta">
    <a href="https://cyberdudebivash.in/#pricing">Explore CYBERDUDEBIVASH Enterprise Services →</a>
  </div>

  <footer>
    CYBERDUDEBIVASH® ARMY — Standalone Threat Intelligence Feed<br>
    Data sourced directly from the CISA Known Exploited Vulnerabilities catalog and FIRST.org EPSS<br>
    © 2026 CYBERDUDEBIVASH Pvt Ltd. All rights reserved.
  </footer>
</div>

<script>
const API_URL = '/api/feed';

function normalizeAdvisories(data) {
  if (Array.isArray(data.feed)) return data.feed;
  if (Array.isArray(data.items)) return data.items;
  return [];
}

async function loadFeed() {
  const body = document.getElementById('feedBody');
  const banner = document.getElementById('errorBanner');
  const dot = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  try {
    const res = await fetch(API_URL, { cache: 'no-store' });
    const data = await res.json();

    if (data.maintenance) {
      banner.style.display = 'block';
      dot.classList.add('offline');
      statusText.textContent = 'DEGRADED';
      body.innerHTML = '<div style="padding:20px;text-align:center;color:#888">Feed temporarily unavailable. Check back shortly.</div>';
      return;
    }

    const items = normalizeAdvisories(data);
    if (!items.length) {
      body.innerHTML = '<div style="padding:20px;text-align:center;color:#888">No active threat advisories at this time.</div>';
      return;
    }

    const weight = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, UNKNOWN: 1 };
    const sorted = items.slice().sort((a, b) => (weight[b.severity]||0) - (weight[a.severity]||0));
    const top = sorted.slice(0, 20);

    body.innerHTML = top.map(it => {
      const epssStr = it.epss !== null && it.epss !== undefined ? \`EPSS \${(it.epss * 100).toFixed(1)}%\` : 'EPSS N/A';
      const meta = [epssStr, it.vendor, it.product].filter(Boolean).join(' · ');
      return \`<div class="feed-item">
        <div>
          <div><span class="cve-id">\${esc(it.cve_id)}</span> — \${esc(it.title)}</div>
          <div class="cve-meta">\${esc(meta)}</div>
        </div>
        <span class="severity-badge \${it.severity}">\${it.severity}</span>
      </div>\`;
    }).join('');

    document.getElementById('advCount').textContent = items.length;
    document.getElementById('critCount').textContent = items.filter(i => i.severity === 'CRITICAL').length;
    document.getElementById('highCount').textContent = items.filter(i => i.severity === 'HIGH').length;
    document.getElementById('kevCount').textContent = items.filter(i => i.kev).length;
    statusText.textContent = data.cached ? 'LIVE — CACHED' : 'LIVE — FRESH';
  } catch (err) {
    dot.classList.add('offline');
    statusText.textContent = 'OFFLINE';
    body.innerHTML = '<div style="padding:20px;text-align:center;color:#ff8888">⚠️ Unable to load threat feed.</div>';
  }
}
function esc(s) { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }
loadFeed();
setInterval(loadFeed, 300000);
</script>
</body>
</html>`;
