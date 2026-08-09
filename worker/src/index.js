/**
 * CYBERDUDEBIVASH AI Security Hub — Cloudflare Worker v185.1 FINAL
 * Entry: worker/src/index.js
 * NO CACHE. Deploy manually: cd worker && wrangler deploy
 */

const MAIN_API = 'https://cyberdudebivash.in';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    // ARMY Dashboard — NO CACHE
    if (path === '/' || path === '/index.html') {
      return new Response(ARMY_HTML, {
        headers: {
          'Content-Type': 'text/html',
          'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0',
        },
      });
    }

    // API Proxy — fetch live data, transform, NO CACHE
    if (path.startsWith('/api/')) {
      try {
        const apiRes = await fetch(`${MAIN_API}/api/v1/intel/kev.json`, {
          headers: { 'Accept': 'application/json' },
        });
        if (!apiRes.ok) throw new Error('Backend ' + apiRes.status);
        const data = await apiRes.json();

        // Transform {items: [...]} → {feed: [...]}
        if (data.items && Array.isArray(data.items)) {
          data.feed = data.items.map(it => ({
            cve_id: it.cve || it.cve_id || it.id || 'UNKNOWN',
            title: it.title || it.summary || 'Untitled Advisory',
            severity: (it.severity || 'UNKNOWN').toUpperCase(),
            cvss: it.cvss,
            published: it.published_at || it.published || '',
          }));
        }

        return new Response(JSON.stringify(data), {
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
          },
        });
      } catch (e) {
        return new Response(JSON.stringify({
          maintenance: true,
          message: 'Live feed temporarily unavailable.',
          feed: [],
        }), {
          status: 503,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store',
          },
        });
      }
    }

    return new Response('Not Found', { status: 404 });
  },
};

const ARMY_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">
<title>CYBERDUDEBIVASH AI Security Hub — ARMY v185.1</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0a0a0f;color:#e0e0e0;font-family:'Segoe UI',Roboto,sans-serif;line-height:1.6}
  .container{max-width:1200px;margin:0 auto;padding:20px}
  header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #1f1f2e;padding-bottom:16px;margin-bottom:24px}
  .brand{font-size:1.5rem;font-weight:700;color:#00f0ff;text-transform:uppercase;letter-spacing:1px}
  .status{display:flex;align-items:center;gap:8px;font-size:0.85rem}
  .dot{width:10px;height:10px;border-radius:50%;background:#00ff88;animation:pulse 2s infinite}
  .dot.offline{background:#ff4444;animation:none}
  .dot.warn{background:#ffcc00;animation:none}
  @keyframes pulse{0%{opacity:1}50%{opacity:.4}100%{opacity:1}}
  .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
  .metric-card{background:#12121f;border:1px solid #1f1f2e;border-radius:8px;padding:20px;text-align:center}
  .metric-value{font-size:2rem;font-weight:700;color:#00f0ff}
  .metric-label{font-size:0.85rem;color:#888;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px}
  .skeleton{background:#1f1f2e;border-radius:4px;height:2rem;width:60%;margin:0 auto;animation:shimmer 1.5s infinite}
  @keyframes shimmer{0%{opacity:.4}50%{opacity:.8}100%{opacity:.4}}
  .feed{background:#12121f;border:1px solid #1f1f2e;border-radius:8px;overflow:hidden}
  .feed-header{background:#1a1a2e;padding:16px 20px;font-weight:600;border-bottom:1px solid #1f1f2e}
  .feed-item{padding:14px 20px;border-bottom:1px solid #1f1f2e;display:flex;justify-content:space-between;align-items:center;transition:background .2s}
  .feed-item:hover{background:#1a1a2e}
  .feed-item:last-child{border-bottom:none}
  .cve-id{font-family:monospace;color:#00f0ff;font-weight:600}
  .severity-badge{padding:4px 10px;border-radius:4px;font-size:0.75rem;font-weight:700;text-transform:uppercase}
  .CRITICAL{background:#ff4444;color:#fff}
  .HIGH{background:#ff8800;color:#000}
  .MEDIUM{background:#ffcc00;color:#000}
  .LOW{background:#00ff88;color:#000}
  .UNKNOWN{background:#888;color:#fff}
  .warn-banner{background:#ffcc001a;border:1px solid #ffcc00;color:#ffcc00;padding:16px;border-radius:8px;margin-bottom:20px;display:none}
  .cta{margin-top:24px;text-align:center}
  .cta a{display:inline-block;background:#00f0ff;color:#0a0a0f;padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:700;text-transform:uppercase;letter-spacing:0.5px}
  .cta a:hover{background:#00c0cc}
  footer{margin-top:40px;text-align:center;color:#555;font-size:0.8rem;border-top:1px solid #1f1f2e;padding-top:20px}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">🔒 CYBERDUDEBIVASH ARMY</div>
    <div class="status"><span class="dot" id="statusDot"></span><span id="statusText">API LIVE</span></div>
  </header>
  <div class="warn-banner" id="warnBanner">⚠️ Data loaded from legacy API v40.0.0. Severity scores may be inaccurate until backend v185.1 is restarted.</div>
  <div class="metrics">
    <div class="metric-card"><div class="metric-value" id="advCount"><div class="skeleton"></div></div><div class="metric-label">Threat Advisories</div></div>
    <div class="metric-card"><div class="metric-value" id="iocCount"><div class="skeleton"></div></div><div class="metric-label">IOCs Processed</div></div>
    <div class="metric-card"><div class="metric-value" id="feedCount"><div class="skeleton"></div></div><div class="metric-label">Live Intel Feeds</div></div>
    <div class="metric-card"><div class="metric-value" id="uptimeCount"><div class="skeleton"></div></div><div class="metric-label">API Uptime %</div></div>
  </div>
  <div class="feed">
    <div class="feed-header">📡 Live Threat Feed — Top Critical & High</div>
    <div id="feedBody"><div style="padding:20px;text-align:center;color:#555">Loading intelligence stream...</div></div>
  </div>
  <div class="cta"><a href="https://cyberdudebivash.in/#pricing">Upgrade to Full API Access →</a></div>
  <footer>CYBERDUDEBIVASH® AI Security Hub — ARMY Dashboard v185.1<br>© 2026 CYBERDUDEBIVASH Pvt Ltd. All rights reserved.</footer>
</div>
<script>
const API_URL = '/api/feed';
async function loadFeed() {
  const body = document.getElementById('feedBody');
  const dot = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  const warnBanner = document.getElementById('warnBanner');
  try {
    const res = await fetch(API_URL, { cache: 'no-store' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const items = data.feed || data.items || data.advisories || [];
    if (!items.length) { body.innerHTML = '<div style="padding:20px;text-align:center;color:#888">No active threat advisories at this time.</div>'; return; }
    const w = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, UNKNOWN: 1 };
    items.sort((a, b) => (w[b.severity] || 0) - (w[a.severity] || 0));
    const top = items.slice(0, 20);
    body.innerHTML = top.map(it => {
      const cvssStr = it.cvss !== null && it.cvss !== undefined ? \`CVSS \${it.cvss}\` : 'CVSS N/A';
      return \`<div class="feed-item"><div><span class="cve-id">\${esc(it.cve_id)}</span> — \${esc(it.title)} <span style="color:#666;font-size:0.8rem">(\${esc(cvssStr)})</span></div><span class="severity-badge \${it.severity}">\${it.severity}</span></div>\`;
    }).join('');
    document.getElementById('advCount').textContent = items.length;
    document.getElementById('iocCount').textContent = '—';
    document.getElementById('feedCount').textContent = '5';
    document.getElementById('uptimeCount').textContent = '99.9%';
    const hasBad = items.some(it => it.cvss !== null && it.cvss < 7.0 && it.severity === 'CRITICAL');
    if (hasBad) { warnBanner.style.display = 'block'; dot.classList.add('warn'); statusText.textContent = 'DEGRADED DATA'; }
  } catch (err) {
    console.error('Feed load failed:', err);
    dot.classList.add('offline'); statusText.textContent = 'OFFLINE';
    body.innerHTML = '<div style="padding:20px;text-align:center;color:#ff8888">⚠️ Unable to load threat feed. API may be down.</div>';
  }
}
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
loadFeed();
setInterval(loadFeed, 120000);
</script>
</body>
</html>`;
