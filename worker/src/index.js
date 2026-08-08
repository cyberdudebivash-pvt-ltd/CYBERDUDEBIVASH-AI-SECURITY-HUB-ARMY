// CYBERDUDEBIVASH® Threat Intel Worker v6.2 — P0 PRODUCTION FIX
// Security: INGEST_SECRET consumed from Cloudflare Worker Secret binding ONLY
// Deploy: wrangler deploy

const VERSION = '6.2.0-p0prod';
const CORS_ORIGIN = 'https://army.cyberdudebivash.in';
const FALLBACK_ORIGIN = 'https://cyberdudebivash-army-api.iambivash-bn.workers.dev';

// --- Source Registry ---
const SOURCES = [
  { id: 'nvd', name: 'NVD', fullName: 'National Vulnerability Database', url: 'https://nvd.nist.gov', apiUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100&noRejected', enabled: true, tier: 1, color: '#3b82f6', category: 'vulnerability' },
  { id: 'cisa_kev', name: 'CISA KEV', fullName: 'CISA Known Exploited Vulnerabilities', url: 'https://cisa.gov/known-exploited-vulnerabilities', apiUrl: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', enabled: true, tier: 1, color: '#ef4444', category: 'vulnerability' },
  { id: 'github', name: 'GitHub Advisories', fullName: 'GitHub Security Advisories', url: 'https://github.com/advisories', apiUrl: 'https://api.github.com/advisories?per_page=100&sort=published&direction=desc', enabled: true, tier: 1, color: '#8b5cf6', category: 'vulnerability' },
  { id: 'circl', name: 'CIRCL', fullName: 'CIRCL Vulnerability-Lookup', url: 'https://vulnerability.circl.lu', apiUrl: 'https://vulnerability.circl.lu/api/last', enabled: true, tier: 1, color: '#10b981', category: 'vulnerability' },
  { id: 'trident', name: 'TridentStack', fullName: 'TridentStack CVE API', url: 'https://tridentstack.com', apiUrl: 'https://tridentstack.com/api/v1/cve?sort=published&limit=50', enabled: true, tier: 1, color: '#f59e0b', category: 'vulnerability' },
  { id: 'osv', name: 'OSV.dev', fullName: 'Open Source Vulnerabilities', url: 'https://osv.dev', apiUrl: 'https://api.osv.dev/v1/querybatch', enabled: true, tier: 1, color: '#06b6d4', category: 'vulnerability' },
  { id: 'threatfox', name: 'ThreatFox', fullName: 'Abuse.ch ThreatFox', url: 'https://threatfox.abuse.ch', apiUrl: 'https://threatfox.abuse.ch/api/v1/', enabled: false, tier: 2, color: '#ec4899', category: 'ioc', apiKeyRequired: true },
  { id: 'urlhaus', name: 'URLhaus', fullName: 'Abuse.ch URLhaus', url: 'https://urlhaus.abuse.ch', apiUrl: 'https://urlhaus-api.abuse.ch/v1/', enabled: false, tier: 2, color: '#f97316', category: 'ioc', apiKeyRequired: true },
  { id: 'virustotal', name: 'VirusTotal', fullName: 'VirusTotal Intelligence', url: 'https://virustotal.com', apiUrl: 'https://www.virustotal.com/api/v3/', enabled: false, tier: 2, color: '#22c55e', category: 'reputation', apiKeyRequired: true },
  { id: 'shodan', name: 'Shodan', fullName: 'Shodan Search Engine', url: 'https://shodan.io', apiUrl: 'https://api.shodan.io/', enabled: false, tier: 2, color: '#6366f1', category: 'attack-surface', apiKeyRequired: true }
];

// --- Helpers ---
function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || CORS_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
    'Access-Control-Max-Age': '86400',
    'Content-Type': 'application/json',
    'X-Worker-Version': VERSION,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Cache-Control': 'public, max-age=300'
  };
}

function json(data, status, origin) {
  return new Response(JSON.stringify(data, null, 2), { status, headers: corsHeaders(origin) });
}

function err(msg, status, origin) {
  return json({ error: true, message: msg, version: VERSION }, status, origin);
}

async function fetchTimeout(url, opts, ms) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms || 10000);
  try {
    const r = await fetch(url, { ...opts, signal: c.signal });
    clearTimeout(t);
    return r;
  } catch (e) {
    clearTimeout(t);
    throw e;
  }
}

function normSev(s) {
  if (!s) return 'MEDIUM';
  const u = String(s).toUpperCase();
  if (u.includes('CRIT')) return 'CRITICAL';
  if (u.includes('HIGH')) return 'HIGH';
  if (u.includes('MED')) return 'MEDIUM';
  if (u.includes('LOW')) return 'LOW';
  return 'MEDIUM';
}

function scoreToSev(n) {
  if (n >= 9.0) return 'CRITICAL';
  if (n >= 7.0) return 'HIGH';
  if (n >= 4.0) return 'MEDIUM';
  return 'LOW';
}

function buildT({ id, title, description, severity, score, source, sourceUrl, published, modified, tags, references }) {
  const sev = normSev(severity);
  const sc = typeof score === 'number' ? score : (sev === 'CRITICAL' ? 9.5 : sev === 'HIGH' ? 7.5 : sev === 'MEDIUM' ? 5.5 : 3.0);
  return {
    id: (id || 'UNKNOWN-' + Date.now()).toUpperCase().trim(),
    title: title || 'Untitled Threat',
    description: description || 'No description available.',
    severity: sev,
    score: Math.min(Math.max(sc, 0), 10),
    source: source || 'unknown',
    sourceUrl: sourceUrl || '',
    published: published || new Date().toISOString(),
    modified: modified || new Date().toISOString(),
    tags: [...new Set((tags || []).filter(Boolean))],
    references: [...new Set((references || []).filter(Boolean))].slice(0, 10)
  };
}

// --- Constant-time comparison to prevent timing attacks ---
function constantTimeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// --- Fetchers ---
async function fetchNVD() {
  const d = new Date();
  d.setDate(d.getDate() - 30);
  const pubStart = d.toISOString().split('T')[0] + 'T00:00:00.000';
  const r = await fetchTimeout(`https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100&noRejected&pubStartDate=${pubStart}`, {}, 12000);
  if (!r.ok) throw new Error('NVD HTTP ' + r.status);
  const j = await r.json();
  const out = [];
  for (const item of (j.vulnerabilities || []).slice(0, 60)) {
    const cve = item.cve;
    if (!cve) continue;
    const cvss = (cve.metrics?.cvssMetricV31?.[0]) || (cve.metrics?.cvssMetricV30?.[0]);
    let score = 0, severity = 'MEDIUM';
    if (cvss) { score = cvss.cvssData?.baseScore || 0; severity = cvss.cvssData?.baseSeverity || scoreToSev(score); }
    const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || cve.descriptions?.[0]?.value || '';
    out.push(buildT({
      id: cve.id, title: cve.id + ': ' + desc.slice(0, 80) + '...', description: desc,
      severity, score, source: 'nvd', sourceUrl: 'https://nvd.nist.gov/vuln/detail/' + cve.id,
      published: cve.published, modified: cve.lastModified, tags: ['cve','nvd'],
      references: (cve.references || []).map(r => r.url).filter(Boolean)
    }));
  }
  return out;
}

async function fetchCISA() {
  const r = await fetchTimeout('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {}, 10000);
  if (!r.ok) throw new Error('CISA HTTP ' + r.status);
  const j = await r.json();
  const out = [];
  for (const item of (j.vulnerabilities || []).slice(0, 60)) {
    const tags = ['kev','cisa','exploited'];
    if (item.knownRansomwareCampaignUse === 'Known') tags.push('ransomware');
    out.push(buildT({
      id: item.cveID, title: item.cveID + ': ' + item.vulnerabilityName,
      description: `Vendor: ${item.vendorProject} | Product: ${item.product} | ${item.shortDescription || item.vulnerabilityName}`,
      severity: 'CRITICAL', score: 9.5, source: 'cisa_kev',
      sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=' + item.cveID,
      published: item.dateAdded ? new Date(item.dateAdded).toISOString() : new Date().toISOString(),
      modified: item.dueDate ? new Date(item.dueDate).toISOString() : new Date().toISOString(),
      tags, references: [item.notes || '']
    }));
  }
  return out;
}

async function fetchGitHub() {
  const r = await fetchTimeout('https://api.github.com/advisories?per_page=100&sort=published&direction=desc', {
    headers: { 'Accept': 'application/vnd.github+json', 'User-Agent': 'CYBERDUDEBIVASH-Worker/6.2' }
  }, 10000);
  if (!r.ok) throw new Error('GitHub HTTP ' + r.status);
  const j = await r.json();
  const out = [];
  for (const adv of (Array.isArray(j) ? j : []).slice(0, 60)) {
    const id = adv.cve_id || adv.ghsa_id;
    if (!id) continue;
    const ecosystems = (adv.vulnerabilities || []).map(v => v.package?.ecosystem).filter(Boolean);
    out.push(buildT({
      id, title: id + ': ' + (adv.summary || 'GitHub Advisory'), description: adv.description || adv.summary || 'No description',
      severity: adv.severity, score: adv.cvss?.score, source: 'github',
      sourceUrl: adv.html_url || 'https://github.com/advisories/' + adv.ghsa_id,
      published: adv.published_at, modified: adv.updated_at,
      tags: ['github-advisory','opensource', ...new Set(ecosystems)],
      references: [adv.html_url, ...(adv.references || [])].filter(Boolean)
    }));
  }
  return out;
}

async function fetchCIRCL() {
  const r = await fetchTimeout('https://vulnerability.circl.lu/api/last', {}, 10000);
  if (!r.ok) throw new Error('CIRCL HTTP ' + r.status);
  const j = await r.json();
  const out = [];
  for (const cve of (Array.isArray(j) ? j : []).slice(0, 60)) {
    let score = 0, severity = 'MEDIUM';
    if (cve.cvss3) { score = cve.cvss3; severity = scoreToSev(score); }
    else if (cve.cvss) { score = cve.cvss; severity = scoreToSev(score); }
    out.push(buildT({
      id: cve.id, title: cve.id + ': ' + (cve.summary?.slice(0, 80) || 'CIRCL Entry'),
      description: cve.summary || 'No summary', severity, score, source: 'circl',
      sourceUrl: 'https://vulnerability.circl.lu/vuln/' + cve.id,
      published: cve.Published, modified: cve.Modified,
      tags: ['cve','circl'], references: (cve.references || []).map(r => typeof r === 'string' ? r : r?.url).filter(Boolean)
    }));
  }
  return out;
}

async function fetchTrident() {
  const r = await fetchTimeout('https://tridentstack.com/api/v1/cve?sort=published&limit=50', {}, 10000);
  if (!r.ok) throw new Error('TridentStack HTTP ' + r.status);
  const j = await r.json();
  const out = [];
  for (const item of (j.data || []).slice(0, 60)) {
    const tags = ['cve','tridentstack'];
    if (item.kev) tags.push('kev');
    if (item.epss > 0.5) tags.push('high-epss');
    out.push(buildT({
      id: item.cve, title: item.cve + ': ' + (item.summary?.slice(0, 80) || 'TridentStack Entry'),
      description: item.summary || 'No summary', severity: item.severity, score: item.cvss,
      source: 'trident', sourceUrl: 'https://tridentstack.com/cve/' + item.cve,
      published: item.published, modified: item.modified, tags: [...new Set(tags)],
      references: item.references || []
    }));
  }
  return out;
}

async function fetchOSV() {
  const queries = [
    { package: { name: 'linux', ecosystem: 'Linux' } },
    { package: { name: 'openssl', ecosystem: 'Alpine' } },
    { package: { name: 'apache-httpd', ecosystem: 'Alpine' } },
    { package: { name: 'nginx', ecosystem: 'Alpine' } },
    { package: { name: 'openssh', ecosystem: 'Alpine' } }
  ];
  const r = await fetchTimeout('https://api.osv.dev/v1/querybatch', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ queries })
  }, 10000);
  if (!r.ok) throw new Error('OSV HTTP ' + r.status);
  const j = await r.json();
  const out = [];
  const seen = new Set();
  for (const result of (j.results || [])) {
    for (const vuln of (result.vulns || [])) {
      if (seen.has(vuln.id)) continue;
      seen.add(vuln.id);
      const cveId = (vuln.aliases || []).find(a => a.startsWith('CVE-')) || vuln.id;
      let score = 0, severity = 'MEDIUM';
      if (vuln.severity) {
        const sev = Array.isArray(vuln.severity) ? vuln.severity[0] : vuln.severity;
        if (sev?.score) { score = parseFloat(sev.score); severity = scoreToSev(score); }
      }
      out.push(buildT({
        id: cveId, title: cveId + ': ' + (vuln.summary?.slice(0, 80) || 'OSV Entry'),
        description: vuln.details || vuln.summary || 'No details', severity, score,
        source: 'osv', sourceUrl: 'https://osv.dev/vulnerability/' + vuln.id,
        published: vuln.published, modified: vuln.modified,
        tags: ['osv','opensource', ...(vuln.ecosystem ? [vuln.ecosystem] : [])],
        references: (vuln.references || []).map(r => r.url).filter(Boolean)
      }));
      if (out.length >= 60) break;
    }
    if (out.length >= 60) break;
  }
  return out;
}

const FETCHERS = {
  nvd: fetchNVD, cisa_kev: fetchCISA, github: fetchGitHub,
  circl: fetchCIRCL, trident: fetchTrident, osv: fetchOSV
};

// --- Ingestion Engine ---
async function ingestAll(env) {
  const results = {};
  const health = {};
  const all = [];
  const enabled = SOURCES.filter(s => s.enabled && FETCHERS[s.id]);

  await Promise.allSettled(enabled.map(async (src) => {
    const start = Date.now();
    try {
      const threats = await FETCHERS[src.id](env);
      await env.THREAT_INTEL_KV.put('source:' + src.id + ':data', JSON.stringify(threats.slice(0, 60)), { expirationTtl: 21600 });
      health[src.id] = { status: 'healthy', lastSync: new Date().toISOString(), count: threats.length, responseTime: Date.now() - start, error: null };
      results[src.id] = { success: true, count: threats.length };
      all.push(...threats);
    } catch (e) {
      health[src.id] = { status: 'degraded', lastSync: new Date().toISOString(), count: 0, responseTime: Date.now() - start, error: e.message };
      results[src.id] = { success: false, error: e.message };
    }
  }));

  await env.THREAT_INTEL_KV.put('sources:config', JSON.stringify({ sources: SOURCES, health, updatedAt: new Date().toISOString() }), { expirationTtl: 21600 });

  const dedup = new Map();
  for (const t of all) {
    const key = (t.id || '').toUpperCase().trim() || t.title?.slice(0, 60).replace(/\s+/g, '-');
    if (!dedup.has(key) || dedup.get(key).score < t.score) dedup.set(key, t);
  }
  const aggregated = Array.from(dedup.values()).sort((a, b) => new Date(b.published) - new Date(a.published)).slice(0, 200);

  await env.THREAT_INTEL_KV.put('threats:all:data', JSON.stringify(aggregated), { expirationTtl: 21600 });

  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const srcCounts = {};
  for (const t of aggregated) {
    sevCounts[t.severity] = (sevCounts[t.severity] || 0) + 1;
    srcCounts[t.source] = (srcCounts[t.source] || 0) + 1;
  }
  await env.THREAT_INTEL_KV.put('threats:meta', JSON.stringify({
    lastSync: new Date().toISOString(), threatCount: aggregated.length,
    sourceCount: Object.keys(srcCounts).length, severityCounts: sevCounts, sourceCounts: srcCounts, version: VERSION
  }), { expirationTtl: 21600 });

  return { success: true, aggregated: aggregated.length, sources: results };
}

// --- API Handlers ---
async function handleHealth(request, env, origin) {
  const metaRaw = await env.THREAT_INTEL_KV.get('threats:meta');
  const meta = metaRaw ? JSON.parse(metaRaw) : null;
  const cfgRaw = await env.THREAT_INTEL_KV.get('sources:config');
  const cfg = cfgRaw ? JSON.parse(cfgRaw) : { health: {} };

  const out = {};
  for (const s of SOURCES) {
    const h = cfg.health?.[s.id] || {};
    out[s.id] = { name: s.name, fullName: s.fullName, enabled: s.enabled, status: h.status || 'unknown',
      lastSync: h.lastSync || null, count: h.count || 0, responseTime: h.responseTime || 0,
      error: h.error || null, color: s.color, category: s.category, apiKeyRequired: s.apiKeyRequired || false };
  }
  return json({ status: meta ? 'healthy' : 'degraded', version: VERSION, timestamp: new Date().toISOString(),
    overall: { totalThreats: meta?.threatCount || 0, activeSources: Object.values(out).filter(s => s.status === 'healthy').length,
      totalSources: SOURCES.length, lastSync: meta?.lastSync || null }, sources: out }, 200, origin);
}

async function handleSources(request, env, origin) {
  const cfgRaw = await env.THREAT_INTEL_KV.get('sources:config');
  const cfg = cfgRaw ? JSON.parse(cfgRaw) : { health: {} };
  return json({ sources: SOURCES.map(s => ({ id: s.id, name: s.name, fullName: s.fullName, enabled: s.enabled,
    tier: s.tier, color: s.color, description: s.description || '', category: s.category, url: s.url,
    apiKeyRequired: s.apiKeyRequired || false, health: cfg.health?.[s.id] || { status: 'unknown', count: 0 } })),
    updatedAt: cfg.updatedAt || new Date().toISOString() }, 200, origin);
}

async function handleSummary(request, env, origin) {
  const metaRaw = await env.THREAT_INTEL_KV.get('threats:meta');
  const meta = metaRaw ? JSON.parse(metaRaw) : null;
  if (!meta) return json({ total: 0, critical: 0, high: 0, medium: 0, low: 0, sources: {}, sourceCount: 0, lastSync: null, aiThreats: 0, knownExploited: 0, version: VERSION }, 200, origin);
  return json({ total: meta.threatCount || 0, critical: meta.severityCounts?.CRITICAL || 0, high: meta.severityCounts?.HIGH || 0,
    medium: meta.severityCounts?.MEDIUM || 0, low: meta.severityCounts?.LOW || 0, sources: meta.sourceCounts || {},
    sourceCount: meta.sourceCount || 0, lastSync: meta.lastSync, aiThreats: meta.threatCount || 0,
    knownExploited: meta.severityCounts?.CRITICAL || 0, version: VERSION }, 200, origin);
}

async function handleThreats(request, env, origin) {
  const url = new URL(request.url);
  const srcFilter = url.searchParams.get('source');
  const sevFilter = url.searchParams.get('severity');
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
  const offset = parseInt(url.searchParams.get('offset') || '0');
  const search = url.searchParams.get('search')?.toLowerCase();

  let data = [];
  if (srcFilter) {
    const raw = await env.THREAT_INTEL_KV.get('source:' + srcFilter + ':data');
    if (raw) data = JSON.parse(raw);
  } else {
    const raw = await env.THREAT_INTEL_KV.get('threats:all:data');
    if (raw) data = JSON.parse(raw);
  }

  if (sevFilter) data = data.filter(t => t.severity === sevFilter.toUpperCase());
  if (search) data = data.filter(t => t.id.toLowerCase().includes(search) || t.title.toLowerCase().includes(search) || t.description.toLowerCase().includes(search) || t.tags.some(tag => tag.toLowerCase().includes(search)));

  const total = data.length;
  return json({ threats: data.slice(offset, offset + limit), pagination: { total, limit, offset, hasMore: offset + limit < total }, filters: { source: srcFilter, severity: sevFilter, search } }, 200, origin);
}

// P0 FIX: Use env.INGEST_SECRET from Cloudflare Worker Secret binding
// Fail-closed: if binding is missing, reject ALL requests
async function handleIngest(request, env, origin) {
  const secret = new URL(request.url).searchParams.get('secret');

  // Fail closed: reject if binding is missing
  if (!env.INGEST_SECRET) {
    return err('Unauthorized — server configuration error', 401, origin);
  }

  // Reject if no secret provided
  if (!secret) {
    return err('Unauthorized — missing ingest secret', 401, origin);
  }

  // Constant-time comparison to prevent timing attacks
  if (!constantTimeCompare(secret, env.INGEST_SECRET)) {
    return err('Unauthorized — invalid ingest secret', 401, origin);
  }

  const result = await ingestAll(env);
  return json(result, 200, origin);
}

// --- Main Router ---
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || CORS_ORIGIN;

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // Rate limit
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rateKey = 'rate:' + ip + ':' + Math.floor(Date.now() / 60000);
    const rateCount = parseInt(await env.THREAT_INTEL_KV.get(rateKey) || '0');
    if (rateCount > 100) return err('Rate limit exceeded', 429, origin);
    await env.THREAT_INTEL_KV.put(rateKey, String(rateCount + 1), { expirationTtl: 120 });

    try {
      if (url.pathname === '/api/v1/health') return await handleHealth(request, env, origin);
      if (url.pathname === '/api/v1/sources') return await handleSources(request, env, origin);
      if (url.pathname === '/api/v1/summary') return await handleSummary(request, env, origin);
      if (url.pathname === '/api/v1/threats') return await handleThreats(request, env, origin);
      if (url.pathname === '/api/v1/ingest') return await handleIngest(request, env, origin);
      return err('Not Found', 404, origin);
    } catch (e) {
      return err('Internal error: ' + e.message, 500, origin);
    }
  },

  // Scheduled ingestion does NOT require URL secret — direct env access
  async scheduled(event, env, ctx) {
    await ingestAll(env);
  }
};
