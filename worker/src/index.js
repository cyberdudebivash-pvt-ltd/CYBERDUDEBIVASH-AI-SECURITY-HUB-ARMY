// ============================================
// CYBERDUDEBIVASH® Multi-Source Threat Intel Worker
// Version: 6.0 — CYBERBEAST Engine
// Supports: NVD, CISA KEV, GitHub Advisories, CIRCL, TridentStack, OSV.dev
// Tier 2 Ready: ThreatFox, URLhaus, VirusTotal, Shodan (key-required)
// ============================================

const CONFIG = {
  VERSION: '6.0.0-cyberbeast',
  INGEST_SECRET: 'CYBERDUDEBIVASH_INGEST_SECRET_CHANGE_ME',
  CORS_ORIGIN: 'https://army.cyberdudebivash.in',
  FALLBACK_ORIGIN: 'https://cyberdudebivash-army-api.iambivash-bn.workers.dev',
  KV_PREFIX: {
    META: 'threats:meta',
    ALL_DATA: 'threats:all:data',
    SOURCE_DATA: (id) => `source:${id}:data`,
    SOURCE_HEALTH: (id) => `source:${id}:health`,
    SOURCES_CONFIG: 'sources:config'
  },
  FETCH_TIMEOUT: 10000,
  MAX_PER_SOURCE: 60,
  MAX_AGGREGATED: 200,
  DEDUP_KEY: (t) => t.id?.toUpperCase()?.trim() || t.title?.slice(0, 60).replace(/\s+/g, '-')
};

// --- Source Registry ---
const SOURCES = [
  {
    id: 'nvd',
    name: 'NVD',
    fullName: 'National Vulnerability Database',
    url: 'https://nvd.nist.gov',
    apiUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100&noRejected',
    enabled: true,
    tier: 1,
    color: '#3b82f6',
    description: 'US NIST official CVE database',
    category: 'vulnerability'
  },
  {
    id: 'cisa_kev',
    name: 'CISA KEV',
    fullName: 'CISA Known Exploited Vulnerabilities',
    url: 'https://cisa.gov/known-exploited-vulnerabilities',
    apiUrl: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    enabled: true,
    tier: 1,
    color: '#ef4444',
    description: 'Confirmed exploited vulnerabilities catalog',
    category: 'vulnerability'
  },
  {
    id: 'github',
    name: 'GitHub Advisories',
    fullName: 'GitHub Security Advisories',
    url: 'https://github.com/advisories',
    apiUrl: 'https://api.github.com/advisories?per_page=100&sort=published&direction=desc',
    enabled: true,
    tier: 1,
    color: '#8b5cf6',
    description: 'Open source vulnerability database',
    category: 'vulnerability'
  },
  {
    id: 'circl',
    name: 'CIRCL',
    fullName: 'CIRCL Vulnerability-Lookup',
    url: 'https://vulnerability.circl.lu',
    apiUrl: 'https://vulnerability.circl.lu/api/last',
    enabled: true,
    tier: 1,
    color: '#10b981',
    description: 'Luxembourg CERT multi-source lookup',
    category: 'vulnerability'
  },
  {
    id: 'trident',
    name: 'TridentStack',
    fullName: 'TridentStack CVE API',
    url: 'https://tridentstack.com',
    apiUrl: 'https://tridentstack.com/api/v1/cve?sort=published&limit=50',
    enabled: true,
    tier: 1,
    color: '#f59e0b',
    description: 'Free CVE API with EPSS & remediation data',
    category: 'vulnerability'
  },
  {
    id: 'osv',
    name: 'OSV.dev',
    fullName: 'Open Source Vulnerabilities',
    url: 'https://osv.dev',
    apiUrl: 'https://api.osv.dev/v1/querybatch',
    enabled: true,
    tier: 1,
    color: '#06b6d4',
    description: 'Google open source vulnerability DB',
    category: 'vulnerability'
  },
  {
    id: 'threatfox',
    name: 'ThreatFox',
    fullName: 'Abuse.ch ThreatFox',
    url: 'https://threatfox.abuse.ch',
    apiUrl: 'https://threatfox.abuse.ch/api/v1/',
    enabled: false,
    tier: 2,
    color: '#ec4899',
    description: 'Malware IOC sharing platform',
    category: 'ioc',
    apiKeyRequired: true,
    apiKeyEnv: 'THREATFOX_API_KEY'
  },
  {
    id: 'urlhaus',
    name: 'URLhaus',
    fullName: 'Abuse.ch URLhaus',
    url: 'https://urlhaus.abuse.ch',
    apiUrl: 'https://urlhaus-api.abuse.ch/v1/',
    enabled: false,
    tier: 2,
    color: '#f97316',
    description: 'Malware distribution site database',
    category: 'ioc',
    apiKeyRequired: true,
    apiKeyEnv: 'URLHAUS_API_KEY'
  },
  {
    id: 'virustotal',
    name: 'VirusTotal',
    fullName: 'VirusTotal Intelligence',
    url: 'https://virustotal.com',
    apiUrl: 'https://www.virustotal.com/api/v3/',
    enabled: false,
    tier: 2,
    color: '#22c55e',
    description: 'File & URL reputation intelligence',
    category: 'reputation',
    apiKeyRequired: true,
    apiKeyEnv: 'VIRUSTOTAL_API_KEY'
  },
  {
    id: 'shodan',
    name: 'Shodan',
    fullName: 'Shodan Search Engine',
    url: 'https://shodan.io',
    apiUrl: 'https://api.shodan.io/',
    enabled: false,
    tier: 2,
    color: '#6366f1',
    description: 'Internet-connected device intelligence',
    category: 'attack-surface',
    apiKeyRequired: true,
    apiKeyEnv: 'SHODAN_API_KEY'
  }
];

// --- Utility Functions ---
function getCorsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || CONFIG.CORS_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
    'Access-Control-Max-Age': '86400',
    'Content-Type': 'application/json',
    'X-Worker-Version': CONFIG.VERSION,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Cache-Control': 'public, max-age=300'
  };
}

function jsonResponse(data, status = 200, origin) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: getCorsHeaders(origin)
  });
}

function errorResponse(message, status = 500, origin) {
  return jsonResponse({ error: true, message, version: CONFIG.VERSION }, status, origin);
}

async function fetchWithTimeout(url, options = {}, timeout = CONFIG.FETCH_TIMEOUT) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return response;
  } catch (e) {
    clearTimeout(id);
    throw e;
  }
}

function normalizeSeverity(sev) {
  if (!sev) return 'MEDIUM';
  const s = String(sev).toUpperCase().trim();
  if (s.includes('CRIT')) return 'CRITICAL';
  if (s.includes('HIGH')) return 'HIGH';
  if (s.includes('MED')) return 'MEDIUM';
  if (s.includes('LOW')) return 'LOW';
  return 'MEDIUM';
}

function scoreToSeverity(score) {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  return 'LOW';
}

// --- Standardized Threat Builder ---
function buildThreat({ id, title, description, severity, score, source, sourceUrl, published, modified, tags = [], references = [], raw = null }) {
  const sev = normalizeSeverity(severity);
  const sc = typeof score === 'number' ? score : (sev === 'CRITICAL' ? 9.5 : sev === 'HIGH' ? 7.5 : sev === 'MEDIUM' ? 5.5 : 3.0);
  return {
    id: id?.toUpperCase()?.trim() || `UNKNOWN-${Date.now()}`,
    title: title || 'Untitled Threat',
    description: description || 'No description available.',
    severity: sev,
    score: Math.min(Math.max(sc, 0), 10),
    source,
    sourceUrl: sourceUrl || '',
    published: published || new Date().toISOString(),
    modified: modified || new Date().toISOString(),
    tags: [...new Set(tags)].filter(Boolean),
    references: [...new Set(references)].filter(Boolean).slice(0, 10),
    raw: raw ? JSON.stringify(raw).slice(0, 2000) : null
  };
}

// --- Source Fetchers ---
const SourceFetchers = {
  async nvd(env) {
    const date = new Date();
    date.setDate(date.getDate() - 30);
    const pubStart = date.toISOString().split('T')[0] + 'T00:00:00.000';
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100&noRejected&pubStartDate=${pubStart}`;

    const res = await fetchWithTimeout(url, {}, 12000);
    if (!res.ok) throw new Error(`NVD HTTP ${res.status}`);
    const data = await res.json();

    const threats = [];
    for (const item of (data.vulnerabilities || []).slice(0, CONFIG.MAX_PER_SOURCE)) {
      const cve = item.cve;
      if (!cve) continue;

      let score = 0;
      let severity = 'MEDIUM';
      const cvss31 = cve.metrics?.cvssMetricV31?.[0];
      const cvss30 = cve.metrics?.cvssMetricV30?.[0];
      const cvss = cvss31 || cvss30;
      if (cvss) {
        score = cvss.cvssData?.baseScore || 0;
        severity = cvss.cvssData?.baseSeverity || scoreToSeverity(score);
      }

      const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || cve.descriptions?.[0]?.value || '';
      const refs = (cve.references || []).map(r => r.url).filter(Boolean);

      threats.push(buildThreat({
        id: cve.id,
        title: `${cve.id}: ${desc.slice(0, 80)}...`,
        description: desc,
        severity,
        score,
        source: 'nvd',
        sourceUrl: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        published: cve.published,
        modified: cve.lastModified,
        tags: ['cve', 'nvd'],
        references: refs,
        raw: { cve }
      }));
    }
    return threats;
  },

  async cisa_kev(env) {
    const res = await fetchWithTimeout(SOURCES.find(s => s.id === 'cisa_kev').apiUrl, {}, 10000);
    if (!res.ok) throw new Error(`CISA HTTP ${res.status}`);
    const data = await res.json();

    const threats = [];
    for (const item of (data.vulnerabilities || []).slice(0, CONFIG.MAX_PER_SOURCE)) {
      const tags = ['kev', 'cisa', 'exploited'];
      if (item.knownRansomwareCampaignUse === 'Known') tags.push('ransomware');

      threats.push(buildThreat({
        id: item.cveID,
        title: `${item.cveID}: ${item.vulnerabilityName}`,
        description: `Vendor: ${item.vendorProject} | Product: ${item.product} | ${item.shortDescription || item.vulnerabilityName}`,
        severity: 'CRITICAL',
        score: 9.5,
        source: 'cisa_kev',
        sourceUrl: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${item.cveID}`,
        published: item.dateAdded ? new Date(item.dateAdded).toISOString() : new Date().toISOString(),
        modified: item.dueDate ? new Date(item.dueDate).toISOString() : new Date().toISOString(),
        tags,
        references: [item.notes || ''],
        raw: item
      }));
    }
    return threats;
  },

  async github(env) {
    const res = await fetchWithTimeout('https://api.github.com/advisories?per_page=100&sort=published&direction=desc', {
      headers: { 'Accept': 'application/vnd.github+json', 'User-Agent': 'CYBERDUDEBIVASH-Worker/6.0' }
    }, 10000);
    if (!res.ok) throw new Error(`GitHub HTTP ${res.status}`);
    const data = await res.json();

    const threats = [];
    for (const adv of (Array.isArray(data) ? data : []).slice(0, CONFIG.MAX_PER_SOURCE)) {
      const id = adv.cve_id || adv.ghsa_id;
      if (!id) continue;

      const ecosystems = (adv.vulnerabilities || []).map(v => v.package?.ecosystem).filter(Boolean);
      const tags = ['github-advisory', 'opensource', ...ecosystems];

      threats.push(buildThreat({
        id,
        title: `${id}: ${adv.summary || 'GitHub Advisory'}`,
        description: adv.description || adv.summary || 'No description',
        severity: adv.severity,
        score: adv.cvss?.score,
        source: 'github',
        sourceUrl: adv.html_url || `https://github.com/advisories/${adv.ghsa_id}`,
        published: adv.published_at,
        modified: adv.updated_at,
        tags: [...new Set(tags)],
        references: [adv.html_url, ...(adv.references || [])].filter(Boolean),
        raw: adv
      }));
    }
    return threats;
  },

  async circl(env) {
    const res = await fetchWithTimeout('https://vulnerability.circl.lu/api/last', {}, 10000);
    if (!res.ok) throw new Error(`CIRCL HTTP ${res.status}`);
    const data = await res.json();

    const threats = [];
    for (const cve of (Array.isArray(data) ? data : []).slice(0, CONFIG.MAX_PER_SOURCE)) {
      let score = 0;
      let severity = 'MEDIUM';
      if (cve.cvss3) {
        score = cve.cvss3;
        severity = scoreToSeverity(score);
      } else if (cve.cvss) {
        score = cve.cvss;
        severity = scoreToSeverity(score);
      }

      threats.push(buildThreat({
        id: cve.id,
        title: `${cve.id}: ${cve.summary?.slice(0, 80) || 'CIRCL Entry'}`,
        description: cve.summary || 'No summary available',
        severity,
        score,
        source: 'circl',
        sourceUrl: `https://vulnerability.circl.lu/vuln/${cve.id}`,
        published: cve.Published,
        modified: cve.Modified,
        tags: ['cve', 'circl', 'luxembourg-cert'],
        references: (cve.references || []).map(r => typeof r === 'string' ? r : r?.url).filter(Boolean),
        raw: cve
      }));
    }
    return threats;
  },

  async trident(env) {
    const res = await fetchWithTimeout('https://tridentstack.com/api/v1/cve?sort=published&limit=50', {}, 10000);
    if (!res.ok) throw new Error(`TridentStack HTTP ${res.status}`);
    const data = await res.json();

    const threats = [];
    for (const item of (data.data || []).slice(0, CONFIG.MAX_PER_SOURCE)) {
      const tags = ['cve', 'tridentstack'];
      if (item.kev) tags.push('kev');
      if (item.epss > 0.5) tags.push('high-epss');

      threats.push(buildThreat({
        id: item.cve,
        title: `${item.cve}: ${item.summary?.slice(0, 80) || 'TridentStack Entry'}`,
        description: item.summary || 'No summary available',
        severity: item.severity,
        score: item.cvss,
        source: 'trident',
        sourceUrl: `https://tridentstack.com/cve/${item.cve}`,
        published: item.published,
        modified: item.modified,
        tags: [...new Set(tags)],
        references: item.references || [],
        raw: item
      }));
    }
    return threats;
  },

  async osv(env) {
    // OSV.dev is query-by-package; we query high-impact ecosystems
    const queries = [
      { package: { name: 'linux', ecosystem: 'Linux' } },
      { package: { name: 'openssl', ecosystem: 'Alpine' } },
      { package: { name: 'apache-httpd', ecosystem: 'Alpine' } },
      { package: { name: 'nginx', ecosystem: 'Alpine' } },
      { package: { name: 'openssh', ecosystem: 'Alpine' } }
    ];

    const res = await fetchWithTimeout('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries })
    }, 10000);

    if (!res.ok) throw new Error(`OSV HTTP ${res.status}`);
    const data = await res.json();

    const threats = [];
    const seen = new Set();
    for (const result of (data.results || [])) {
      for (const vuln of (result.vulns || [])) {
        if (seen.has(vuln.id)) continue;
        seen.add(vuln.id);

        const aliases = vuln.aliases || [];
        const cveId = aliases.find(a => a.startsWith('CVE-')) || vuln.id;

        let score = 0;
        let severity = 'MEDIUM';
        if (vuln.severity) {
          const sev = Array.isArray(vuln.severity) ? vuln.severity[0] : vuln.severity;
          if (sev?.score) {
            score = parseFloat(sev.score);
            severity = scoreToSeverity(score);
          } else if (sev?.type === 'CVSS_V3') {
            score = parseFloat(sev.score) || 0;
            severity = scoreToSeverity(score);
          }
        }

        threats.push(buildThreat({
          id: cveId,
          title: `${cveId}: ${vuln.summary?.slice(0, 80) || 'OSV Entry'}`,
          description: vuln.details || vuln.summary || 'No details available',
          severity,
          score,
          source: 'osv',
          sourceUrl: `https://osv.dev/vulnerability/${vuln.id}`,
          published: vuln.published,
          modified: vuln.modified,
          tags: ['osv', 'opensource', ...(vuln.ecosystem ? [vuln.ecosystem] : [])],
          references: (vuln.references || []).map(r => r.url).filter(Boolean),
          raw: vuln
        }));

        if (threats.length >= CONFIG.MAX_PER_SOURCE) break;
      }
      if (threats.length >= CONFIG.MAX_PER_SOURCE) break;
    }
    return threats;
  }
};

// --- Ingestion Engine ---
async function ingestAllSources(env) {
  const results = {};
  const healthUpdates = {};
  const allThreats = [];

  const enabledSources = SOURCES.filter(s => s.enabled && SourceFetchers[s.id]);

  await Promise.allSettled(enabledSources.map(async (source) => {
    const startTime = Date.now();
    try {
      const fetcher = SourceFetchers[source.id];
      const threats = await fetcher(env);

      // Store per-source
      await env.THREAT_INTEL_KV.put(
        CONFIG.KV_PREFIX.SOURCE_DATA(source.id),
        JSON.stringify(threats.slice(0, CONFIG.MAX_PER_SOURCE)),
        { expirationTtl: 21600 } // 6 hours
      );

      // Update health
      healthUpdates[source.id] = {
        status: 'healthy',
        lastSync: new Date().toISOString(),
        count: threats.length,
        responseTime: Date.now() - startTime,
        error: null
      };

      results[source.id] = { success: true, count: threats.length };
      allThreats.push(...threats);
    } catch (err) {
      healthUpdates[source.id] = {
        status: 'degraded',
        lastSync: new Date().toISOString(),
        count: 0,
        responseTime: Date.now() - startTime,
        error: err.message
      };
      results[source.id] = { success: false, error: err.message };
    }
  }));

  // Store health data
  await env.THREAT_INTEL_KV.put(
    CONFIG.KV_PREFIX.SOURCES_CONFIG,
    JSON.stringify({ sources: SOURCES, health: healthUpdates, updatedAt: new Date().toISOString() }),
    { expirationTtl: 21600 }
  );

  // Deduplicate and aggregate
  const dedupMap = new Map();
  for (const threat of allThreats) {
    const key = CONFIG.DEDUP_KEY(threat);
    if (!dedupMap.has(key) || dedupMap.get(key).score < threat.score) {
      dedupMap.set(key, threat);
    }
  }

  const aggregated = Array.from(dedupMap.values())
    .sort((a, b) => new Date(b.published) - new Date(a.published))
    .slice(0, CONFIG.MAX_AGGREGATED);

  // Store aggregated
  await env.THREAT_INTEL_KV.put(
    CONFIG.KV_PREFIX.ALL_DATA,
    JSON.stringify(aggregated),
    { expirationTtl: 21600 }
  );

  // Store meta
  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const sourceCounts = {};
  for (const t of aggregated) {
    severityCounts[t.severity] = (severityCounts[t.severity] || 0) + 1;
    sourceCounts[t.source] = (sourceCounts[t.source] || 0) + 1;
  }

  await env.THREAT_INTEL_KV.put(
    CONFIG.KV_PREFIX.META,
    JSON.stringify({
      lastSync: new Date().toISOString(),
      threatCount: aggregated.length,
      sourceCount: Object.keys(sourceCounts).length,
      severityCounts,
      sourceCounts,
      version: CONFIG.VERSION
    }),
    { expirationTtl: 21600 }
  );

  return { success: true, aggregated: aggregated.length, sources: results };
}

// --- API Handlers ---
const APIHandlers = {
  async health(request, env, origin) {
    const metaRaw = await env.THREAT_INTEL_KV.get(CONFIG.KV_PREFIX.META);
    const meta = metaRaw ? JSON.parse(metaRaw) : null;

    const configRaw = await env.THREAT_INTEL_KV.get(CONFIG.KV_PREFIX.SOURCES_CONFIG);
    const config = configRaw ? JSON.parse(configRaw) : { health: {} };

    const sourceHealth = {};
    for (const source of SOURCES) {
      const h = config.health?.[source.id] || {};
      sourceHealth[source.id] = {
        name: source.name,
        fullName: source.fullName,
        enabled: source.enabled,
        status: h.status || 'unknown',
        lastSync: h.lastSync || null,
        count: h.count || 0,
        responseTime: h.responseTime || 0,
        error: h.error || null,
        color: source.color,
        category: source.category,
        apiKeyRequired: source.apiKeyRequired || false
      };
    }

    return jsonResponse({
      status: meta ? 'healthy' : 'degraded',
      version: CONFIG.VERSION,
      timestamp: new Date().toISOString(),
      overall: {
        totalThreats: meta?.threatCount || 0,
        activeSources: Object.values(sourceHealth).filter(s => s.status === 'healthy').length,
        totalSources: SOURCES.length,
        lastSync: meta?.lastSync || null
      },
      sources: sourceHealth
    }, 200, origin);
  },

  async sources(request, env, origin) {
    const configRaw = await env.THREAT_INTEL_KV.get(CONFIG.KV_PREFIX.SOURCES_CONFIG);
    const config = configRaw ? JSON.parse(configRaw) : { health: {} };

    return jsonResponse({
      sources: SOURCES.map(s => ({
        id: s.id,
        name: s.name,
        fullName: s.fullName,
        enabled: s.enabled,
        tier: s.tier,
        color: s.color,
        description: s.description,
        category: s.category,
        url: s.url,
        apiKeyRequired: s.apiKeyRequired || false,
        health: config.health?.[s.id] || { status: 'unknown', count: 0 }
      })),
      updatedAt: config.updatedAt || new Date().toISOString()
    }, 200, origin);
  },

  async summary(request, env, origin) {
    const metaRaw = await env.THREAT_INTEL_KV.get(CONFIG.KV_PREFIX.META);
    const meta = metaRaw ? JSON.parse(metaRaw) : null;

    if (!meta) {
      return jsonResponse({
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        sources: {},
        lastSync: null,
        aiThreats: 0,
        knownExploited: 0,
        version: CONFIG.VERSION
      }, 200, origin);
    }

    return jsonResponse({
      total: meta.threatCount || 0,
      critical: meta.severityCounts?.CRITICAL || 0,
      high: meta.severityCounts?.HIGH || 0,
      medium: meta.severityCounts?.MEDIUM || 0,
      low: meta.severityCounts?.LOW || 0,
      sources: meta.sourceCounts || {},
      sourceCount: meta.sourceCount || 0,
      lastSync: meta.lastSync,
      aiThreats: meta.threatCount || 0, // All are AI-monitored
      knownExploited: meta.severityCounts?.CRITICAL || 0,
      version: CONFIG.VERSION
    }, 200, origin);
  },

  async threats(request, env, origin) {
    const url = new URL(request.url);
    const sourceFilter = url.searchParams.get('source');
    const severityFilter = url.searchParams.get('severity');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
    const offset = parseInt(url.searchParams.get('offset') || '0');
    const search = url.searchParams.get('search')?.toLowerCase();

    let data = [];

    if (sourceFilter) {
      const sourceData = await env.THREAT_INTEL_KV.get(CONFIG.KV_PREFIX.SOURCE_DATA(sourceFilter));
      if (sourceData) data = JSON.parse(sourceData);
    } else {
      const allData = await env.THREAT_INTEL_KV.get(CONFIG.KV_PREFIX.ALL_DATA);
      if (allData) data = JSON.parse(allData);
    }

    // Apply filters
    if (severityFilter) {
      data = data.filter(t => t.severity === severityFilter.toUpperCase());
    }
    if (search) {
      data = data.filter(t => 
        t.id.toLowerCase().includes(search) ||
        t.title.toLowerCase().includes(search) ||
        t.description.toLowerCase().includes(search) ||
        t.tags.some(tag => tag.toLowerCase().includes(search))
      );
    }

    const total = data.length;
    const paginated = data.slice(offset, offset + limit);

    return jsonResponse({
      threats: paginated,
      pagination: {
        total,
        limit,
        offset,
        hasMore: offset + limit < total
      },
      filters: { source: sourceFilter, severity: severityFilter, search }
    }, 200, origin);
  },

  async ingest(request, env, origin) {
    const url = new URL(request.url);
    const secret = url.searchParams.get('secret');

    if (secret !== CONFIG.INGEST_SECRET) {
      return errorResponse('Unauthorized — invalid ingest secret', 401, origin);
    }

    const result = await ingestAllSources(env);
    return jsonResponse(result, 200, origin);
  }
};

// --- Main Router ---
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || CONFIG.CORS_ORIGIN;

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: getCorsHeaders(origin) });
    }

    // Rate limiting (simple in-memory per-IP)
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rateKey = `rate:${clientIP}:${Math.floor(Date.now() / 60000)}`;
    const rateCount = parseInt(await env.THREAT_INTEL_KV.get(rateKey) || '0');
    if (rateCount > 100) {
      return errorResponse('Rate limit exceeded — 100 requests/minute', 429, origin);
    }
    await env.THREAT_INTEL_KV.put(rateKey, String(rateCount + 1), { expirationTtl: 120 });

    // Route
    const path = url.pathname;

    try {
      if (path === '/api/v1/health') return await APIHandlers.health(request, env, origin);
      if (path === '/api/v1/sources') return await APIHandlers.sources(request, env, origin);
      if (path === '/api/v1/summary') return await APIHandlers.summary(request, env, origin);
      if (path === '/api/v1/threats') return await APIHandlers.threats(request, env, origin);
      if (path === '/api/v1/ingest') return await APIHandlers.ingest(request, env, origin);

      return errorResponse('Not Found', 404, origin);
    } catch (err) {
      console.error('Worker Error:', err);
      return errorResponse(`Internal error: ${err.message}`, 500, origin);
    }
  },

  async scheduled(event, env, ctx) {
    console.log('Cron triggered ingestion at', new Date().toISOString());
    await ingestAllSources(env);
  }
};
