/**
 * CYBERDUDEBIVASH AI Security Hub — Cloudflare Worker v185.1
 * ARMY subdomain fallback + edge caching + rate limiting
 */

const MAIN_API = 'https://cyberdudebivash.in';
const CACHE_KEY = 'army:feed:latest';
const CACHE_TTL = 7200; // 2 hours

async function fetchWithFallback(request) {
  const endpoints = [
    `${MAIN_API}/api/feed`,
    `${MAIN_API}/api/v1/intel/kev.json`,
  ];

  for (const url of endpoints) {
    try {
      const res = await fetch(url, {
        cf: { cacheTtl: 300 },
        headers: { 'Accept': 'application/json' },
      });
      if (res.ok) return res;
    } catch (e) {
      console.warn('Worker fallback failed:', url, e);
    }
  }
  return new Response(JSON.stringify({ maintenance: true, message: 'Live feed temporarily unavailable.' }), {
    status: 503,
    headers: { 'Content-Type': 'application/json', 'Retry-After': '120' },
  });
}

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // CORS preflight
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

  // Rate limit by IP
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rlKey = `rl:${ip}`;
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - 60;

  // Simple in-KV rate limit (replace with Durable Objects for strictness)
  let rlData = await env.THREAT_CACHE?.get(rlKey, { type: 'json' }) || { count: 0, window: now };
  if (rlData.window < windowStart) {
    rlData = { count: 0, window: now };
  }
  rlData.count += 1;
  if (rlData.count > 30) { // Starter tier per-minute
    return new Response(JSON.stringify({ error: 'Rate limit exceeded', retry_after: 60 }), {
      status: 429,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  }
  await env.THREAT_CACHE?.put(rlKey, JSON.stringify(rlData), { expirationTtl: 60 });

  // Serve static ARMY dashboard
  if (path === '/' || path === '/index.html') {
    return new Response(ARMY_HTML, {
      headers: { 'Content-Type': 'text/html', 'Cache-Control': 'public, max-age=60' },
    });
  }

  // API proxy with caching
  if (path.startsWith('/api/')) {
    const cache = caches.default;
    const cacheKey = new Request(`${CACHE_KEY}:${path}`, request);
    let response = await cache.match(cacheKey);

    if (!response) {
      response = await fetchWithFallback(request);
      if (response.status === 200) {
        response = new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: {
            ...Object.fromEntries(response.headers),
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': `public, max-age=${CACHE_TTL}`,
          },
        });
        await cache.put(cacheKey, response.clone());
      }
    }
    return response;
  }

  return new Response('Not Found', { status: 404 });
}

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  },
};

const ARMY_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
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
  .error-banner{background:#ff44441a;border:1px solid #ff4444;color:#ff8888;padding:16px;border-radius:8px;margin-bottom:20px;display:none}
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
  <div class="error-banner" id="errorBanner">⚠️ Live feed temporarily unavailable. Data refreshes every 2 hours. <a href="https://cyberdudebivash.in" style="color:#00f0ff">Visit main hub →</a></div>
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
const API_ENDPOINTS = ['https://army.cyberdudebivash.in/api/feed','https://cyberdudebivash.in/api/v1/intel/kev.json','https://cyberdudebivash.in/api/feed'];
async function fetchWithFallback(endpoints) {
  for (const url of endpoints) {
    try { const c = new AbortController(); const t = setTimeout(()=>c.abort(),8000); const r = await fetch(url,{signal:c.signal}); clearTimeout(t); if(r.ok) return await r.json(); } catch(e){ console.warn('ARMY fallback:',url,e.message); }
  }
  return { maintenance: true, message: 'Live feed temporarily unavailable.' };
}
function renderFeed(data) {
  const body = document.getElementById('feedBody'); const banner = document.getElementById('errorBanner'); const dot = document.getElementById('statusDot'); const statusText = document.getElementById('statusText');
  if(data.maintenance){ banner.style.display='block'; dot.classList.add('offline'); statusText.textContent='DEGRADED'; body.innerHTML='<div style="padding:20px;text-align:center;color:#888">Feed temporarily unavailable. Check back shortly.</div>'; return; }
  const advisories = data.advisories || data.feed || [];
  if(!advisories.length){ body.innerHTML='<div style="padding:20px;text-align:center;color:#888">No active threat advisories at this time.</div>'; return; }
  const weight={CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,UNKNOWN:1};
  const sorted=advisories.slice().sort((a,b)=>(weight[b.severity]||0)-(weight[a.severity]||0));
  const top=sorted.slice(0,20);
  body.innerHTML=top.map(item=>{ const sev=(item.severity||'UNKNOWN').toUpperCase(); const id=item.cve_id||item.id||'UNKNOWN'; const title=item.title||'Untitled Advisory'; return \`<div class="feed-item"><div><span class="cve-id">\${id}</span> — \${title.replace(/</g,'&lt;')}</div><span class="severity-badge \${sev}">\${sev}</span></div>\`; }).join('');
  document.getElementById('advCount').textContent=advisories.length; document.getElementById('iocCount').textContent='—'; document.getElementById('feedCount').textContent='5'; document.getElementById('uptimeCount').textContent='99.9%';
}
async function init(){ const data=await fetchWithFallback(API_ENDPOINTS); renderFeed(data); }
init(); setInterval(init,120000);
</script>
</body>
</html>`;
