/**
 * CYBERDUDEBIVASH AI SECURITY HUB ARMY
 * Production-Grade Threat Intelligence API
 * Cloudflare Worker Backend
 * Version: 1.0.0
 */

// ─── CONFIGURATION ──────────────────────────────────────────────────────────

const CONFIG = {
  VERSION: '1.0.0',
  API_PREFIX: '/api/v1',
  MAX_RESULTS: 100,
  DEFAULT_LIMIT: 50,
  RATE_LIMIT_PER_MIN: 100,
  CACHE_TTL: 300, // 5 minutes for API responses
  INGESTION_TTL: 86400 * 2, // 2 days for threat data
  META_TTL: 86400 * 7, // 7 days for metadata
};

const AI_KEYWORDS = [
  'artificial intelligence', 'machine learning', 'ml model', 'deep learning',
  'neural network', 'llm', 'large language model', 'generative ai', 'genai',
  'openai', 'chatgpt', 'claude', 'gemini', 'copilot', 'hugging face',
  'tensorflow', 'pytorch', 'onnx', 'model poisoning', 'prompt injection',
  'jailbreak', 'adversarial', 'model inversion', 'data poisoning',
  'transfer learning', 'fine-tuning', 'inference', 'embedding',
  'vector database', 'rag', 'retrieval augmented', 'langchain', 'llama',
  'mistral', 'anthropic', 'ai system', 'ai model', 'ai application',
  'natural language processing', 'nlp', 'computer vision', 'cv',
  'reinforcement learning', 'rlhf', 'training data', 'dataset',
  'sklearn', 'scikit-learn', 'keras', 'jax', 'mxnet', 'caffe',
  'ai agent', 'autonomous agent', 'multi-agent', 'agentic',
  'foundation model', 'diffusion model', 'stable diffusion',
  'midjourney', 'dall-e', 'whisper', 'bert', 'gpt', 'transformer',
  'attention mechanism', 'tokenization', 'embedding model',
  'vector store', 'pinecone', 'weaviate', 'chroma', 'milvus',
  'ollama', 'vllm', 'text generation', 'text-to-image',
  'speech recognition', 'speech synthesis', 'tts',
  'computer vision model', 'image classification', 'object detection',
  'segmentation', 'yolo', 'resnet', 'efficientnet',
  'federated learning', 'differential privacy', 'homomorphic encryption',
  'ai governance', 'ai safety', 'ai alignment', 'red teaming',
  'ai audit', 'model evaluation', 'benchmark', 'hallucination',
  'prompt engineering', 'system prompt', 'instruction tuning',
  'sft', 'supervised fine-tuning', 'lora', 'qlora', 'peft',
  'quantization', 'distillation', 'pruning', 'model compression',
  'mlp', 'cnn', 'rnn', 'lstm', 'gru', 'gan', 'vae', 'autoencoder',
  'normalizing flow', 'energy-based model', 'ebm',
  'neural radiance field', 'nerf', '3d reconstruction',
  'multimodal', 'vision language model', 'vlm',
  'ai infrastructure', 'gpu cluster', 'tpu', 'training cluster',
  'mlops', 'model serving', 'model registry', 'feature store',
  'data pipeline', 'etl', 'data lakehouse', 'delta lake',
  'apache spark', 'databricks', 'snowflake', 'bigquery',
  'sagemaker', 'vertex ai', 'azure ml', 'bedrock',
  'replicate', 'banana', 'modal', 'runpod', 'vast.ai',
  'ai api', 'inference endpoint', 'model endpoint',
  'api key leak', 'model weights', 'checkpoint',
  'pretrained model', 'base model', 'instruct model',
  'chat model', 'completion model', 'embedding endpoint',
  'semantic search', 'similarity search', 'nearest neighbor',
  'clustering', 'dimensionality reduction', 'pca', 'tsne', 'umap',
  'anomaly detection', 'fraud detection', 'recommendation system',
  'collaborative filtering', 'content-based filtering',
  'bandit algorithm', 'contextual bandit', 'reinforcement learning from feedback',
  'rlaif', 'dpo', 'direct preference optimization', 'ppo',
  'constitutional ai', 'self-critique', 'chain-of-thought',
  'tree-of-thought', 'graph-of-thought', 'react pattern',
  'tool use', 'function calling', 'plugin system',
  'ai orchestration', 'workflow engine', 'dag',
  'observability', 'monitoring', 'tracing', 'evaluation framework',
  'ai ethics', 'bias mitigation', 'fairness metric',
  'explainable ai', 'xai', 'interpretability', 'lime', 'shap',
  'counterfactual', 'concept drift', 'data drift',
  'model drift', 'performance degradation', 'concept drift detection',
  'shadow deployment', 'canary release', 'a/b testing',
  'blue-green deployment', 'feature flag', 'experimentation platform'
];

const SEVERITY_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 };
const SEVERITY_COLORS = { CRITICAL: '#ff3366', HIGH: '#ffaa00', MEDIUM: '#ffcc00', LOW: '#00ff88', NONE: '#8888aa' };

// ─── UTILITY FUNCTIONS ──────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function fetchWithRetry(url, options = {}, maxRetries = 3) {
  const baseDelay = 2000;
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(url, {
        ...options,
        cf: { cacheTtl: 3600, ...(options.cf || {}) }
      });
      if (response.ok) return response;
      if (response.status === 503 && i < maxRetries - 1) {
        await sleep(baseDelay * (i + 1));
        continue;
      }
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    } catch (err) {
      if (i === maxRetries - 1) throw err;
      await sleep(baseDelay * (i + 1));
    }
  }
  throw new Error('Max retries exceeded');
}

function sanitizeString(str) {
  if (!str) return '';
  return str.replace(/[<>"']/g, '');
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function generateId() {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// ─── THREAT INTELLIGENCE ENGINE ─────────────────────────────────────────────

class ThreatIntelEngine {
  constructor(env) {
    this.env = env;
    this.kv = env.THREAT_INTEL_KV;
  }

  async ingestAll() {
    const startTime = Date.now();
    const results = { nvd: [], cisa: [], errors: [] };

    // Fetch NVD (recent 30 days)
    try {
      const nvdData = await this.fetchNVD();
      results.nvd = this.processNVD(nvdData);
    } catch (e) {
      console.error('NVD ingestion failed:', e);
      results.errors.push({ source: 'NVD', error: 'Upstream source unavailable', timestamp: new Date().toISOString() });
    }

    // Fetch CISA KEV
    try {
      const cisaData = await this.fetchCISA();
      results.cisa = this.processCISA(cisaData);
    } catch (e) {
      console.error('CISA ingestion failed:', e);
      results.errors.push({ source: 'CISA', error: 'Upstream source unavailable', timestamp: new Date().toISOString() });
    }

    // Merge, deduplicate, store
    const merged = this.mergeThreats(results.nvd, results.cisa);
    await this.storeThreats(merged);

    const meta = {
      lastSync: new Date().toISOString(),
      sources: ['NVD', 'CISA'],
      threatCount: merged.length,
      aiThreatCount: merged.filter(t => t.tags.includes('ai-security')).length,
      kevCount: merged.filter(t => t.kev).length,
      criticalCount: merged.filter(t => t.severity === 'CRITICAL').length,
      errors: results.errors,
      durationMs: Date.now() - startTime
    };
    await this.storeMetadata(meta);

    return { ingested: merged.length, meta };
  }

  async fetchNVD() {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const pubStartDate = thirtyDaysAgo.toISOString().split('.')[0] + 'Z';

    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100&startIndex=0&pubStartDate=${pubStartDate}`;
    const response = await fetchWithRetry(url, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'CYBERDUDEBIVASH-ARMY/1.0'
      }
    });
    return await response.json();
  }

  async fetchCISA() {
    const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
    const response = await fetchWithRetry(url, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'CYBERDUDEBIVASH-ARMY/1.0'
      }
    });
    return await response.json();
  }

  processNVD(data) {
    if (!data?.vulnerabilities) return [];

    return data.vulnerabilities.map(item => {
      const cve = item.cve;
      const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available';

      // Extract CVSS v3.1 or v3.0 or v2.0
      let score = 0;
      let severity = 'NONE';
      let vector = null;

      const cvss31 = cve.metrics?.cvssMetricV31?.[0];
      const cvss30 = cve.metrics?.cvssMetricV30?.[0];
      const cvss20 = cve.metrics?.cvssMetricV2?.[0];

      if (cvss31) {
        score = cvss31.cvssData?.baseScore || 0;
        severity = cvss31.cvssData?.baseSeverity || 'NONE';
        vector = cvss31.cvssData?.vectorString || null;
      } else if (cvss30) {
        score = cvss30.cvssData?.baseScore || 0;
        severity = cvss30.cvssData?.baseSeverity || 'NONE';
        vector = cvss30.cvssData?.vectorString || null;
      } else if (cvss20) {
        score = cvss20.cvssData?.baseScore || 0;
        severity = score >= 7.0 ? 'HIGH' : score >= 4.0 ? 'MEDIUM' : 'LOW';
        vector = cvss20.cvssData?.vectorString || null;
      }

      // Extract affected products from CPE
      const affected = [];
      const configs = cve.configurations || [];
      for (const config of configs) {
        for (const node of config.nodes || []) {
          for (const match of node.cpeMatch || []) {
            if (match.criteria) {
              const parts = match.criteria.split(':');
              if (parts.length >= 5) {
                affected.push(`${parts[3]} ${parts[4]}${parts[5] !== '*' && parts[5] !== '-' ? ' ' + parts[5] : ''}`);
              }
            }
          }
        }
      }

      // AI relevance detection
      const textToCheck = `${desc} ${cve.id} ${affected.join(' ')}`.toLowerCase();
      const aiTags = [];
      for (const kw of AI_KEYWORDS) {
        if (textToCheck.includes(kw.toLowerCase())) aiTags.push(kw);
      }
      const isAI = aiTags.length > 0;

      const tags = [...new Set([...(isAI ? ['ai-security'] : []), 'cve', 'vulnerability'])];
      if (score >= 9.0) tags.push('critical-severity');
      else if (score >= 7.0) tags.push('high-severity');
      else if (score >= 4.0) tags.push('medium-severity');
      else tags.push('low-severity');

      // Extract CWE
      const cweList = (cve.weaknesses || []).map(w => {
        const desc = w.description?.find(d => d.lang === 'en')?.value;
        return desc || w.value;
      }).filter(Boolean);

      return {
        id: cve.id,
        title: desc.length > 150 ? desc.substring(0, 150) + '...' : desc,
        description: desc,
        severity,
        score: Math.round(score * 10) / 10,
        vector,
        source: 'NVD',
        published_at: cve.published,
        updated_at: cve.lastModified,
        affected_products: [...new Set(affected)].slice(0, 10),
        exploitability: score >= 7.0,
        tags,
        references: (cve.references || [])
          .filter(r => r.url)
          .map(r => ({ url: r.url, source: r.source || 'NVD' }))
          .slice(0, 10),
        confidence: 'HIGH',
        last_seen: new Date().toISOString(),
        threat_type: 'vulnerability',
        cwe: cweList[0] || null,
        cwe_list: cweList,
        kev: false,
        raw_source: 'nvd'
      };
    }).filter(t => {
      // Include if: AI-related, OR score >= 5.0, OR has exploit references
      const hasExploitRef = t.references.some(r =>
        r.url?.includes('exploit') || r.url?.includes('github.com') || r.url?.includes('packetstorm')
      );
      return t.tags.includes('ai-security') || t.score >= 5.0 || hasExploitRef;
    });
  }

  processCISA(data) {
    if (!data?.vulnerabilities) return [];

    return data.vulnerabilities.slice(0, 100).map(v => {
      const desc = v.shortDescription || v.vulnerabilityName || 'Known exploited vulnerability';
      const textToCheck = `${desc} ${v.cveID} ${v.vendorProject} ${v.product}`.toLowerCase();

      const aiTags = [];
      for (const kw of AI_KEYWORDS) {
        if (textToCheck.includes(kw.toLowerCase())) aiTags.push(kw);
      }

      const tags = [...new Set([
        ...(aiTags.length > 0 ? ['ai-security'] : []),
        'cisa-kev',
        'known-exploited',
        'vulnerability',
        'actively-exploited'
      ])];

      if (v.knownRansomwareCampaignUse === 'Known') tags.push('ransomware');

      return {
        id: v.cveID,
        title: v.vulnerabilityName || desc.substring(0, 150),
        description: desc,
        severity: 'CRITICAL',
        score: 9.5,
        vector: null,
        source: 'CISA',
        published_at: v.dateAdded ? `${v.dateAdded}T00:00:00Z` : new Date().toISOString(),
        updated_at: v.dateAdded ? `${v.dateAdded}T00:00:00Z` : new Date().toISOString(),
        affected_products: [`${v.vendorProject} ${v.product}`],
        exploitability: true,
        tags,
        references: [],
        confidence: 'HIGH',
        last_seen: new Date().toISOString(),
        threat_type: 'known-exploited',
        cwe: null,
        cwe_list: [],
        kev: true,
        raw_source: 'cisa',
        required_action: v.requiredAction || null,
        due_date: v.dueDate || null,
        ransomware: v.knownRansomwareCampaignUse === 'Known'
      };
    });
  }

  mergeThreats(nvd, cisa) {
    const map = new Map();

    // Add NVD first
    for (const t of nvd) map.set(t.id, t);

    // Merge CISA KEV entries
    for (const t of cisa) {
      if (map.has(t.id)) {
        const existing = map.get(t.id);
        existing.kev = true;
        existing.ransomware = t.ransomware || existing.ransomware;
        existing.tags = [...new Set([...existing.tags, ...t.tags, 'cisa-kev', 'known-exploited'])];
        existing.severity = 'CRITICAL';
        existing.score = Math.max(existing.score, t.score);
        existing.threat_type = 'known-exploited';
        if (t.required_action) existing.required_action = t.required_action;
        if (t.due_date) existing.due_date = t.due_date;
      } else {
        map.set(t.id, t);
      }
    }

    return Array.from(map.values()).sort((a, b) => {
      const sevDiff = (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0);
      if (sevDiff !== 0) return sevDiff;
      return new Date(b.published_at || 0) - new Date(a.published_at || 0);
    });
  }

  async storeThreats(threats) {
    const chunkSize = 40;
    const chunks = [];
    for (let i = 0; i < threats.length; i += chunkSize) {
      chunks.push(threats.slice(i, i + chunkSize));
    }

    await this.kv.put('threats:meta', JSON.stringify({
      count: threats.length,
      chunks: chunks.length,
      updated: new Date().toISOString()
    }), { expirationTtl: CONFIG.INGESTION_TTL });

    for (let i = 0; i < chunks.length; i++) {
      await this.kv.put(`threats:chunk:${i}`, JSON.stringify(chunks[i]), {
        expirationTtl: CONFIG.INGESTION_TTL
      });
    }
  }

  async storeMetadata(meta) {
    await this.kv.put('meta:ingestion', JSON.stringify(meta), {
      expirationTtl: CONFIG.META_TTL
    });
  }

  async getThreats() {
    const metaRaw = await this.kv.get('threats:meta');
    if (!metaRaw) return [];

    const meta = JSON.parse(metaRaw);
    const threats = [];
    for (let i = 0; i < meta.chunks; i++) {
      const chunkRaw = await this.kv.get(`threats:chunk:${i}`);
      if (chunkRaw) threats.push(...JSON.parse(chunkRaw));
    }
    return threats;
  }

  async getMetadata() {
    const raw = await this.kv.get('meta:ingestion');
    return raw ? JSON.parse(raw) : null;
  }

  async storeLead(lead) {
    const key = `lead:${generateId()}`;
    await this.kv.put(key, JSON.stringify({
      ...lead,
      createdAt: new Date().toISOString()
    }), { expirationTtl: 86400 * 365 });
    return key;
  }
}

// ─── API ROUTER ───────────────────────────────────────────────────────────────

class APIRouter {
  constructor(engine, corsOrigin, env) {
    this.engine = engine;
    this.corsOrigin = corsOrigin;
    this.env = env;
  }

  json(data, status = 200, extraHeaders = {}) {
    const headers = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': this.corsOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
      'X-API-Version': CONFIG.VERSION,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      ...extraHeaders
    };

    if (status === 200) {
      headers['Cache-Control'] = `public, max-age=${CONFIG.CACHE_TTL}`;
    } else {
      headers['Cache-Control'] = 'no-store';
    }

    return new Response(JSON.stringify(data, null, 2), { status, headers });
  }

  error(message, status = 500, code = 'INTERNAL_ERROR') {
    return this.json({ error: message, status, code, timestamp: new Date().toISOString() }, status);
  }

  async route(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': this.corsOrigin,
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    try {
      if (path === `${CONFIG.API_PREFIX}/health`) return await this.health();
      if (path === `${CONFIG.API_PREFIX}/threats`) return await this.threats(url);
      if (path.startsWith(`${CONFIG.API_PREFIX}/threats/`)) return await this.threatDetail(path, url);
      if (path === `${CONFIG.API_PREFIX}/summary`) return await this.summary();
      if (path === `${CONFIG.API_PREFIX}/sources`) return await this.sources();
      if (path === `${CONFIG.API_PREFIX}/search`) return await this.search(url);
      if (path === `${CONFIG.API_PREFIX}/stats`) return await this.stats();
      if (path === `${CONFIG.API_PREFIX}/timeline`) return await this.timeline();
      if (path === `${CONFIG.API_PREFIX}/alerts`) return await this.alerts();
      if (path === `${CONFIG.API_PREFIX}/subscribe`) return await this.subscribe(request);
      if (path === `${CONFIG.API_PREFIX}/ingest`) return await this.triggerIngest(request);
      if (path === `${CONFIG.API_PREFIX}/feed`) return await this.feed(url);

      return this.error('Not Found', 404, 'NOT_FOUND');
    } catch (e) {
      console.error('API Error:', e);
      return this.error('Internal server error', 500, 'INTERNAL_ERROR');
    }
  }

  async health() {
    const meta = await this.engine.getMetadata();
    return this.json({
      status: 'healthy',
      version: CONFIG.VERSION,
      timestamp: new Date().toISOString(),
      environment: 'production',
      lastSync: meta?.lastSync || null,
      sources: meta?.sources || [],
      threatCount: meta?.threatCount || 0,
      uptime: 'operational'
    });
  }

  async threats(url) {
    const threats = await this.engine.getThreats();
    const severity = url.searchParams.get('severity')?.toUpperCase();
    const tag = url.searchParams.get('tag')?.toLowerCase();
    const aiOnly = url.searchParams.get('ai') === 'true';
    const kevOnly = url.searchParams.get('kev') === 'true';
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), CONFIG.MAX_RESULTS);
    const offset = parseInt(url.searchParams.get('offset') || '0');

    let filtered = threats;
    if (severity) filtered = filtered.filter(t => t.severity === severity);
    if (tag) filtered = filtered.filter(t => t.tags.some(tg => tg.toLowerCase().includes(tag)));
    if (aiOnly) filtered = filtered.filter(t => t.tags.includes('ai-security'));
    if (kevOnly) filtered = filtered.filter(t => t.kev);

    const total = filtered.length;
    const paginated = filtered.slice(offset, offset + limit);

    return this.json({
      data: paginated,
      meta: {
        total,
        limit,
        offset,
        hasMore: offset + limit < total,
        returned: paginated.length,
        filters: { severity, tag, aiOnly, kevOnly }
      }
    });
  }

  async threatDetail(path, url) {
    const id = path.split('/').pop();
    if (!id || !id.startsWith('CVE-')) {
      return this.error('Invalid CVE ID', 400, 'INVALID_ID');
    }

    const threats = await this.engine.getThreats();
    const threat = threats.find(t => t.id === id.toUpperCase());
    if (!threat) return this.error('Threat not found', 404, 'NOT_FOUND');

    return this.json({ data: threat });
  }

  async summary() {
    const threats = await this.engine.getThreats();
    const meta = await this.engine.getMetadata();

    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
    const sourceCounts = {};
    const tagCounts = {};
    const typeCounts = {};
    let aiCount = 0;
    let kevCount = 0;
    let ransomwareCount = 0;
    let totalScore = 0;

    for (const t of threats) {
      severityCounts[t.severity] = (severityCounts[t.severity] || 0) + 1;
      sourceCounts[t.source] = (sourceCounts[t.source] || 0) + 1;
      typeCounts[t.threat_type] = (typeCounts[t.threat_type] || 0) + 1;
      if (t.tags.includes('ai-security')) aiCount++;
      if (t.kev) kevCount++;
      if (t.ransomware) ransomwareCount++;
      totalScore += t.score || 0;

      for (const tag of t.tags) {
        tagCounts[tag] = (tagCounts[tag] || 0) + 1;
      }
    }

    const avgScore = threats.length > 0 ? Math.round((totalScore / threats.length) * 10) / 10 : 0;

    let freshness = 'unknown';
    let freshnessMinutes = null;
    if (meta?.lastSync) {
      const diff = Date.now() - new Date(meta.lastSync).getTime();
      freshnessMinutes = Math.round(diff / 60000);
      freshness = freshnessMinutes < 60 ? `${freshnessMinutes}m ago` :
                  freshnessMinutes < 1440 ? `${Math.round(freshnessMinutes / 60)}h ago` :
                  `${Math.round(freshnessMinutes / 1440)}d ago`;
    }

    return this.json({
      total: threats.length,
      severity: severityCounts,
      sources: sourceCounts,
      types: typeCounts,
      topTags: Object.entries(tagCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 15)
        .map(([name, count]) => ({ name, count })),
      aiThreats: aiCount,
      knownExploited: kevCount,
      ransomware: ransomwareCount,
      averageScore: avgScore,
      lastSync: meta?.lastSync,
      freshness,
      freshnessMinutes,
      ingestionDuration: meta?.durationMs,
      errors: meta?.errors?.length || 0
    });
  }

  async sources() {
    const meta = await this.engine.getMetadata();
    const errors = meta?.errors || [];

    return this.json({
      sources: [
        {
          name: 'NVD',
          fullName: 'National Vulnerability Database',
          url: 'https://nvd.nist.gov',
          description: 'U.S. government repository of standards-based vulnerability management data',
          feedUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
          lastSync: meta?.lastSync,
          status: errors.some(e => e.source === 'NVD') ? 'degraded' : 'healthy',
          reliability: 'HIGH',
          coverage: 'Global CVE database'
        },
        {
          name: 'CISA',
          fullName: 'Cybersecurity and Infrastructure Security Agency',
          url: 'https://www.cisa.gov/known-exploited-vulnerabilities',
          description: 'Authoritative catalog of known exploited vulnerabilities',
          feedUrl: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
          lastSync: meta?.lastSync,
          status: errors.some(e => e.source === 'CISA') ? 'degraded' : 'healthy',
          reliability: 'HIGH',
          coverage: 'Actively exploited vulnerabilities'
        }
      ],
      nextIngestion: meta?.lastSync ?
        new Date(new Date(meta.lastSync).getTime() + 6 * 60 * 60 * 1000).toISOString() :
        null
    });
  }

  async search(url) {
    const q = sanitizeString(url.searchParams.get('q'))?.toLowerCase();
    if (!q || q.length < 2) {
      return this.error('Query must be at least 2 characters', 400, 'INVALID_QUERY');
    }

    const threats = await this.engine.getThreats();
    const results = threats.filter(t =>
      t.id.toLowerCase().includes(q) ||
      t.title.toLowerCase().includes(q) ||
      t.description.toLowerCase().includes(q) ||
      t.tags.some(tag => tag.toLowerCase().includes(q)) ||
      t.affected_products.some(p => p.toLowerCase().includes(q))
    ).slice(0, CONFIG.MAX_RESULTS);

    return this.json({
      data: results,
      meta: { query: q, count: results.length, limit: CONFIG.MAX_RESULTS }
    });
  }

  async stats() {
    const threats = await this.engine.getThreats();
    const daily = {};
    const weekly = {};
    const monthly = {};

    for (const t of threats) {
      const date = t.published_at?.split('T')[0] || 'unknown';
      const week = date !== 'unknown' ? getWeekKey(date) : 'unknown';
      const month = date !== 'unknown' ? date.substring(0, 7) : 'unknown';

      [daily, weekly, monthly].forEach((bucket, idx) => {
        const key = [date, week, month][idx];
        if (key === 'unknown') return;
        if (!bucket[key]) bucket[key] = { count: 0, critical: 0, high: 0, medium: 0, low: 0, ai: 0 };
        bucket[key].count++;
        if (t.severity === 'CRITICAL') bucket[key].critical++;
        if (t.severity === 'HIGH') bucket[key].high++;
        if (t.severity === 'MEDIUM') bucket[key].medium++;
        if (t.severity === 'LOW') bucket[key].low++;
        if (t.tags.includes('ai-security')) bucket[key].ai++;
      });
    }

    return this.json({
      daily: sortTimeEntries(daily).slice(-30),
      weekly: sortTimeEntries(weekly).slice(-12),
      monthly: sortTimeEntries(monthly).slice(-12),
      severityDistribution: {
        critical: threats.filter(t => t.severity === 'CRITICAL').length,
        high: threats.filter(t => t.severity === 'HIGH').length,
        medium: threats.filter(t => t.severity === 'MEDIUM').length,
        low: threats.filter(t => t.severity === 'LOW').length
      }
    });
  }

  async timeline() {
    const threats = await this.engine.getThreats();
    const sorted = [...threats]
      .sort((a, b) => new Date(b.published_at || 0) - new Date(a.published_at || 0))
      .slice(0, 30);

    return this.json({
      events: sorted.map(t => ({
        id: t.id,
        date: t.published_at,
        title: t.title,
        severity: t.severity,
        score: t.score,
        source: t.source,
        tags: t.tags.slice(0, 5),
        kev: t.kev,
        ai: t.tags.includes('ai-security')
      }))
    });
  }

  async alerts() {
    const threats = await this.engine.getThreats();
    const alerts = threats
      .filter(t => t.severity === 'CRITICAL' || t.kev || t.tags.includes('ai-security'))
      .slice(0, 20);

    return this.json({
      alerts,
      meta: {
        generatedAt: new Date().toISOString(),
        count: alerts.length,
        critical: alerts.filter(a => a.severity === 'CRITICAL').length,
        kev: alerts.filter(a => a.kev).length,
        ai: alerts.filter(a => a.tags.includes('ai-security')).length
      }
    });
  }

  async subscribe(request) {
    if (request.method !== 'POST') {
      return this.error('Method not allowed', 405, 'METHOD_NOT_ALLOWED');
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return this.error('Invalid JSON body', 400, 'INVALID_BODY');
    }

    const email = sanitizeString(body.email);
    const name = sanitizeString(body.name || '');
    const company = sanitizeString(body.company || '');
    const interest = sanitizeString(body.interest || 'general');

    if (!email || !isValidEmail(email)) {
      return this.error('Valid email required', 400, 'INVALID_EMAIL');
    }

    const lead = { email, name, company, interest, source: 'army-dashboard', ip: request.headers.get('CF-Connecting-IP') };
    await this.engine.storeLead(lead);

    return this.json({
      success: true,
      message: 'Successfully subscribed to threat intelligence alerts',
      data: { email, interest }
    });
  }

  async triggerIngest(request) {
    const configuredSecret = this.env?.INGEST_SECRET;

    if (!configuredSecret) {
      console.error('INGEST_SECRET is not configured');
      return this.error('Service configuration error', 503, 'INGEST_AUTH_NOT_CONFIGURED');
    }

    const auth = request.headers.get('Authorization') || '';

    if (!auth.startsWith('Bearer ')) {
      return this.error('Unauthorized', 401, 'UNAUTHORIZED');
    }

    const suppliedSecret = auth.slice(7).trim();

    if (!suppliedSecret || suppliedSecret !== configuredSecret) {
      return this.error('Unauthorized', 401, 'UNAUTHORIZED');
    }

    try {
      const result = await this.engine.ingestAll();
      return this.json({
        success: true,
        message: 'Ingestion triggered successfully',
        result
      });
    } catch (e) {
      console.error('Ingestion failed:', e);
      return this.error('Ingestion failed', 500, 'INGESTION_FAILED');
    }
  }

  async feed(url) {
    const format = url.searchParams.get('format') || 'json';
    const threats = await this.engine.getThreats();
    const recent = threats.slice(0, 50);

    if (format === 'json') {
      return this.json({
        feed: {
          title: 'CYBERDUDEBIVASH AI Security Threat Feed',
          link: 'https://army.cyberdudebivash.in',
          description: 'Real-time AI security threat intelligence feed',
          lastBuildDate: new Date().toISOString(),
          items: recent.map(t => ({
            id: t.id,
            title: `[${t.severity}] ${t.id}: ${t.title}`,
            description: t.description,
            link: `https://nvd.nist.gov/vuln/detail/${t.id}`,
            pubDate: t.published_at,
            categories: t.tags,
            severity: t.severity,
            score: t.score
          }))
        }
      });
    }

    // RSS format
    const rssItems = recent.map(t => `
      <item>
        <title>${escapeXml(`[${t.severity}] ${t.id}`)}</title>
        <link>https://nvd.nist.gov/vuln/detail/${t.id}</link>
        <guid>${t.id}</guid>
        <pubDate>${new Date(t.published_at).toUTCString()}</pubDate>
        <description>${escapeXml(t.description)}</description>
        ${t.tags.map(tag => `<category>${escapeXml(tag)}</category>`).join('')}
      </item>
    `).join('');

    const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>CYBERDUDEBIVASH AI Security Threat Feed</title>
    <link>https://army.cyberdudebivash.in</link>
    <description>Real-time AI security threat intelligence feed</description>
    <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
    <language>en</language>
    ${rssItems}
  </channel>
</rss>`;

    return new Response(rss, {
      headers: {
        'Content-Type': 'application/rss+xml',
        'Access-Control-Allow-Origin': this.corsOrigin
      }
    });
  }
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────

function getWeekKey(dateStr) {
  const d = new Date(dateStr);
  const weekStart = new Date(d);
  weekStart.setDate(d.getDate() - d.getDay());
  return weekStart.toISOString().split('T')[0];
}

function sortTimeEntries(obj) {
  return Object.entries(obj)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([date, stats]) => ({ date, ...stats }));
}

function escapeXml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// ─── RATE LIMITER ─────────────────────────────────────────────────────────────

async function checkRateLimit(kv, clientIP) {
  const key = `rate:${clientIP}`;
  const now = Date.now();
  const windowStart = now - 60000; // 1 minute window

  let data = await kv.get(key);
  let record = data ? JSON.parse(data) : { count: 0, windowStart: now };

  if (record.windowStart < windowStart) {
    record = { count: 0, windowStart: now };
  }

  record.count++;
  await kv.put(key, JSON.stringify(record), { expirationTtl: 120 });

  return {
    allowed: record.count <= CONFIG.RATE_LIMIT_PER_MIN,
    remaining: Math.max(0, CONFIG.RATE_LIMIT_PER_MIN - record.count),
    reset: record.windowStart + 60000
  };
}

// ─── MAIN EXPORT ──────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Rate limiting
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rateLimit = await checkRateLimit(env.THREAT_INTEL_KV, clientIP);

    if (!rateLimit.allowed) {
      return new Response(JSON.stringify({
        error: 'Rate limit exceeded',
        code: 'RATE_LIMITED',
        retryAfter: Math.ceil((rateLimit.reset - Date.now()) / 1000)
      }), {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'X-RateLimit-Limit': String(CONFIG.RATE_LIMIT_PER_MIN),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': String(rateLimit.reset),
          'Access-Control-Allow-Origin': env.CORS_ORIGIN || '*'
        }
      });
    }

    const corsOrigin = env.CORS_ORIGIN || '*';
    const engine = new ThreatIntelEngine(env);
    const router = new APIRouter(engine, corsOrigin, env);

    const response = await router.route(request);

    // Add rate limit headers to successful responses
    const newHeaders = new Headers(response.headers);
    newHeaders.set('X-RateLimit-Limit', String(CONFIG.RATE_LIMIT_PER_MIN));
    newHeaders.set('X-RateLimit-Remaining', String(rateLimit.remaining));
    newHeaders.set('X-RateLimit-Reset', String(rateLimit.reset));

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });
  },

  async scheduled(event, env, ctx) {
    console.log('Scheduled ingestion triggered at', new Date().toISOString());
    const engine = new ThreatIntelEngine(env);
    try {
      const result = await engine.ingestAll();
      console.log('Ingestion complete:', JSON.stringify(result));
    } catch (e) {
      console.error('Scheduled ingestion failed:', e);
    }
  }
};
