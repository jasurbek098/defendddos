// server_ultimate_secure.js — полная версия с исправлениями для Render
// Massive standalone Node.js server with multi-layer DDoS defenses.
// Everything in one file. No external NPM dependencies.
// HTML UIs in Russian (contains "Руслан ака я докажу").
// --------------------------------------------------------------------

// --------------------------- IMPORTS --------------------------------
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const url = require('url');
const os = require('os');
const { execSync } = require('child_process');
const { StringDecoder } = require('string_decoder');

// -------------------------- CONFIG ----------------------------------
// Fixed secrets (no environment variables)
const GENERATED_ADMIN_TOKEN = 'q9HfX2e7BzRkM8vP0sVnYcT4wLrJ6uF3ZdA1pQe8YmN5oU2xG0HtC7kLwS4bV1zA';
const GENERATED_COOKIE_SECRET = 'c4d2e1f0b9a8c7d6e5f4a3b2c1d0e9f8';

const CONFIG = {
  // Ports (FIXED FOR RENDER: use environment PORT)
  PORT_HTTP: 10000,
  PORT_HTTPS: 8443,

  // Toggle auto-gen self-signed cert (not used on Render)
  AUTO_GEN_HTTPS_CERT: false,

  // Per-IP token bucket (target ~10 req/sec)
  TOKEN_BUCKET_CAPACITY: 12,
  TOKEN_REFILL_PER_SEC: 10,

  // Sliding window burst control
  WINDOW_MS: 1000,      // 1 second
  WINDOW_LIMIT: 10,     // max 10 req / WINDOW_MS

  // Concurrent connection limit per IP
  MAX_CONCURRENT_PER_IP: 6,

  // Proof-of-Work (POW)
  POW_BASE_DIFFICULTY: 20,
  POW_MAX_DIFFICULTY: 36,

  // Backoff / strikes
  BACKOFF_BASE_MS: 200,
  BACKOFF_MAX_MS: 10 * 60 * 1000,
  STRIKES_TO_BLACKLIST: 6,
  BLACKLIST_MS: 6 * 60 * 60 * 1000, // 6 hours

  // Subnet (/24) aggregation
  ENABLE_SUBNET_AGGREGATION: true,
  SUBNET_TOKEN_MULTIPLIER: 50,

  // Distributed attack detection
  UNIQUE_IP_WINDOW_MS: 10 * 1000, // 10s
  UNIQUE_IP_THRESHOLD: 300,
  UNDER_ATTACK_RAISE_DIFFICULTY_BY: 8,
  UNDER_ATTACK_STRICT_MULTIPLIER: 0.3,

  // Global soft cap
  GLOBAL_REQUEST_CAP_PER_SEC: 5000,

  // Slowloris protection parameters
  MIN_HEADER_COMPLETE_MS: 3000,
  MAX_HEADER_COMPLETE_MS: 30 * 1000,
  MAX_BODY_CHUNK_WAIT_MS: 5000,

  // Cookie/signing secret and admin token
  COOKIE_SECRET: GENERATED_COOKIE_SECRET,
  ADMIN_TOKEN: GENERATED_ADMIN_TOKEN,

  // Paths for certs if needed (not necessary on Render)
  HTTPS_KEY_PATH: './server.key',
  HTTPS_CERT_PATH: './server.cert',

  // Misc
  VERBOSE: true,
  TRUSTED_PROXIES: [],

  // Limits
  FREE_CHALLENGE_PAGES_PER_IP: 8,
  MAX_IP_ENTRIES_IN_MEMORY: 200000
};

// ----------------------- GLOBAL STATE -------------------------------
const state = {
  ipMap: new Map(),         // ip -> state obj
  subnetMap: new Map(),     // subnet -> aggregate state
  blacklist: new Map(),     // ip -> until timestamp
  whitelist: new Set(),     // trusted IPs
  uniqueIpTimestamps: [],   // { ip, t }
  underAttack: { active: false, since: 0 },
  recentRequests: []        // timestamps for RPS
};

// ----------------------- UTIL FUNCTIONS -----------------------------

function now() { return Date.now(); }
function log(...args) { if (CONFIG.VERBOSE) console.log(new Date().toISOString(), ...args); }
function warn(...args) { console.warn(new Date().toISOString(), 'WARN:', ...args); }
function error(...args) { console.error(new Date().toISOString(), 'ERROR:', ...args); }

// Normalize IPv6-mapped IPv4 addresses, and ::1
function normalizeIp(raw) {
  if (!raw) return '0.0.0.0';
  if (raw.startsWith('::ffff:')) return raw.slice(7);
  if (raw === '::1') return '127.0.0.1';
  return raw;
}

// Extract client IP (respect X-Forwarded-For only when TRUSTED_PROXIES provided)
function extractClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff && CONFIG.TRUSTED_PROXIES.length > 0) {
    const client = xff.split(',')[0].trim();
    return normalizeIp(client);
  }
  return normalizeIp(req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : '0.0.0.0');
}

// Return /24 subnet string for IPv4 or the IP itself for IPv6
function subnet24(ip) {
  ip = normalizeIp(ip);
  const parts = ip.split('.');
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  return ip;
}

// sha256 hex
function sha256hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

// HMAC sign/verify
function hmacSign(data) {
  return crypto.createHmac('sha256', CONFIG.COOKIE_SECRET).update(String(data)).digest('hex');
}
function hmacVerify(data, sig) {
  try {
    const expected = hmacSign(data);
    const a = Buffer.from(expected, 'hex');
    const b = Buffer.from(sig, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch (e) {
    return false;
  }
}

// Count leading zero bits in hex string (for POW)
function countLeadingZeroBits(hex) {
  let zeros = 0;
  for (let i = 0; i < hex.length; i++) {
    const nib = parseInt(hex[i], 16);
    if (nib === 0) { zeros += 4; continue; }
    for (let b = 3; b >= 0; b--) {
      if (((nib >> b) & 1) === 0) zeros++;
      else return zeros;
    }
  }
  return zeros;
}

// --------------------- IP STATE MANAGEMENT ---------------------------

// create or return ip state
function ensureIpState(ip) {
  ip = normalizeIp(ip);
  if (state.ipMap.has(ip)) return state.ipMap.get(ip);
  const s = {
    ip,
    tokens: CONFIG.TOKEN_BUCKET_CAPACITY,
    lastRefill: now(),
    window: [],
    concurrent: 0,
    strikes: 0,
    backoffUntil: 0,
    powDifficulty: CONFIG.POW_BASE_DIFFICULTY,
    lastSeen: now(),
    freeChallengePages: 0
  };
  // memory cap pruning
  if (state.ipMap.size > CONFIG.MAX_IP_ENTRIES_IN_MEMORY) {
    // prune 5% oldest by lastSeen
    const arr = Array.from(state.ipMap.entries());
    arr.sort((a, b) => a[1].lastSeen - b[1].lastSeen);
    const toRemove = Math.max(1, Math.floor(arr.length * 0.05));
    for (let i = 0; i < toRemove; i++) state.ipMap.delete(arr[i][0]);
    log('Pruned ipMap by', toRemove, 'entries due to memory cap');
  }
  state.ipMap.set(ip, s);
  return s;
}

// refill ip tokens
function refillIpTokens(s) {
  const elapsed = (now() - s.lastRefill) / 1000;
  if (elapsed > 0) {
    const multiplier = state.underAttack.active ? CONFIG.UNDER_ATTACK_STRICT_MULTIPLIER : 1;
    const add = elapsed * CONFIG.TOKEN_REFILL_PER_SEC * multiplier;
    s.tokens = Math.min(CONFIG.TOKEN_BUCKET_CAPACITY, s.tokens + add);
    s.lastRefill = now();
  }
}

// subnet state
function ensureSubnetState(sub) {
  if (state.subnetMap.has(sub)) return state.subnetMap.get(sub);
  const ss = {
    subnet: sub,
    tokens: CONFIG.TOKEN_BUCKET_CAPACITY * CONFIG.SUBNET_TOKEN_MULTIPLIER,
    lastRefill: now(),
    window: []
  };
  state.subnetMap.set(sub, ss);
  return ss;
}
function refillSubnetTokens(ss) {
  const elapsed = (now() - ss.lastRefill) / 1000;
  if (elapsed > 0) {
    const add = elapsed * CONFIG.TOKEN_REFILL_PER_SEC * CONFIG.SUBNET_TOKEN_MULTIPLIER;
    ss.tokens = Math.min(CONFIG.TOKEN_BUCKET_CAPACITY * CONFIG.SUBNET_TOKEN_MULTIPLIER * 4, ss.tokens + add);
    ss.lastRefill = now();
  }
}

// sliding window add + check
function slidingWindowAdd(s, windowMs, limit) {
  const t = now();
  const cutoff = t - windowMs;
  while (s.window.length && s.window[0] < cutoff) s.window.shift();
  s.window.push(t);
  return s.window.length <= limit;
}

// ----------------- Distributed Attack Detection ----------------------

function registerUniqueIp(ip) {
  const t = now();
  state.uniqueIpTimestamps.push({ ip, t });
  const cutoff = t - CONFIG.UNIQUE_IP_WINDOW_MS;
  while (state.uniqueIpTimestamps.length && state.uniqueIpTimestamps[0].t < cutoff) state.uniqueIpTimestamps.shift();
  const uniq = new Set(state.uniqueIpTimestamps.map(x => x.ip));
  if (!state.underAttack.active && uniq.size >= CONFIG.UNIQUE_IP_THRESHOLD) {
    state.underAttack.active = true;
    state.underAttack.since = t;
    log('UNDER_ATTACK: engaged', { uniqueIPs: uniq.size });
    // escalate POW difficulty for tracked IPs
    for (const s of state.ipMap.values()) {
      s.powDifficulty = Math.min(CONFIG.POW_MAX_DIFFICULTY, (s.powDifficulty || CONFIG.POW_BASE_DIFFICULTY) + CONFIG.UNDER_ATTACK_RAISE_DIFFICULTY_BY);
    }
  }
  if (state.underAttack.active && uniq.size < Math.floor(CONFIG.UNIQUE_IP_THRESHOLD * 0.6)) {
    state.underAttack.active = false;
    log('UNDER_ATTACK: disengaged', { uniqueIPs: uniq.size });
    // relax difficulties
    for (const s of state.ipMap.values()) {
      s.powDifficulty = Math.max(CONFIG.POW_BASE_DIFFICULTY, (s.powDifficulty || CONFIG.POW_BASE_DIFFICULTY) - Math.floor(CONFIG.UNDER_ATTACK_RAISE_DIFFICULTY_BY / 2));
    }
  }
}

// ------------------- Global RPS register -----------------------------

function registerGlobalRequest() {
  const t = now();
  state.recentRequests.push(t);
  while (state.recentRequests.length && state.recentRequests[0] < t - 1000) state.recentRequests.shift();
  return state.recentRequests.length;
}

// ------------------- POW (Proof-of-Work) -----------------------------

// make a signed challenge: base:ts:hmac
function makePowChallengeInternal() {
  const rand = crypto.randomBytes(16).toString('hex');
  const ts = Math.floor(now() / 1000).toString(16);
  const base = `${rand}:${ts}`;
  const sig = hmacSign(base);
  return `${base}:${sig}`;
}
function verifyPowChallengeSignature(challenge) {
  if (!challenge) return false;
  const parts = challenge.split(':');
  if (parts.length < 3) return false;
  const sig = parts.pop();
  const base = parts.join(':');
  return hmacVerify(base, sig);
}
function verifyPowHeaders(challenge, nonce, claimedHashHex, difficulty) {
  if (!challenge || !nonce || !claimedHashHex) return false;
  if (!verifyPowChallengeSignature(challenge)) return false;
  const computed = sha256hex(challenge + ':' + nonce);
  if (computed !== claimedHashHex) return false;
  const zeros = countLeadingZeroBits(computed);
  return zeros >= difficulty;
}

// challenge cookie helpers
function makeChallengeCookieInternal() {
  const challenge = makePowChallengeInternal();
  const expires = now() + 5 * 60 * 1000; // 5 minutes
  const payload = `${challenge}|${expires}`;
  const sig = hmacSign(payload);
  return Buffer.from(`${payload}|${sig}`).toString('base64');
}
function parseChallengeCookieInternal(cookieBase64) {
  try {
    const decoded = Buffer.from(cookieBase64, 'base64').toString('utf8');
    const parts = decoded.split('|');
    if (parts.length < 3) return null;
    const sig = parts.pop();
    const payload = parts.join('|');
    if (!hmacVerify(payload, sig)) return null;
    const expires = parseInt(parts[parts.length - 1], 10);
    if (now() > expires) return null;
    const challenge = parts.slice(0, parts.length - 1).join(':');
    return challenge;
  } catch (e) {
    return null;
  }
}

// Aliases for functions
function makePowChallenge() { return makePowChallengeInternal(); }
function makeChallengeCookie() { return makeChallengeCookieInternal(); }
function parseChallengeCookie(cookieBase64) { return parseChallengeCookieInternal(cookieBase64); }

// -------------------- HTML challenge page (RU) -----------------------

function htmlChallengePage(difficulty, cookieValue) {
  const cookieSafe = cookieValue || '';
  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Защита — Руслан ака я докажу</title>
<style>
  body{margin:0;background:#071428;color:#e6f0ff;font-family:Inter,Roboto,Arial,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh}
  .card{background:#0b1b2b;padding:24px;border-radius:12px;box-shadow:0 10px 40px rgba(2,6,23,.6);max-width:800px;width:100%}
  h1{margin:0 0 8px;font-size:20px}
  p{margin:0 0 12px;color:#9fb7ff}
  .status{background:#061323;padding:12px;border-radius:8px;font-family:monospace}
  button{background:#2563eb;padding:8px 12px;border-radius:8px;border:none;color:white;cursor:pointer}
  .small{font-size:13px;color:#7fa1ff}
</style>
</head>
<body>
  <div class="card">
    <h1>CYBERSECURITY</h1>
    <p>Для доступа требуется небольшая задача Proof-of-Work — быстро для людей, дорого для массовых ботов.</p>
    <div id="status" class="status">Загрузка задачи...</div>
    <div style="margin-top:12px"><button id="retry">Попробовать снова</button> <span class="small">Поддержка: modern browser</span></div>
  </div>
<script>
(async function(){
  const status = document.getElementById('status');
  const retry = document.getElementById('retry');
  retry.onclick = run;
  async function sha256hex(s){
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
    return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
  }
  function countLeadingZeroBits(hex){
    let zeros=0;
    for(let i=0;i<hex.length;i++){
      const nib=parseInt(hex[i],16);
      if(nib===0){zeros+=4;continue;}
      for(let b=3;b>=0;b--){ if(((nib>>b)&1)===0) zeros++; else return zeros; }
    }
    return zeros;
  }
  async function run(){
    try{
      status.textContent='Запрос задачи...';
      const r = await fetch('/pow-challenge');
      if(!r.ok){ status.textContent='Ошибка получения задачи: '+r.status; return; }
      const j = await r.json();
      const challenge = j.challenge;
      const difficulty = j.difficulty;
      status.textContent='Решаю задачу (сложность '+difficulty+')...';
      let nonce = 0;
      const start = performance.now();
      while(true){
        const candidate = challenge + ':' + nonce;
        const h = await sha256hex(candidate);
        if(countLeadingZeroBits(h) >= difficulty){
          const took = Math.round(performance.now()-start);
          status.textContent='Решено за '+took+'ms, отправляю запрос...';
          const resp = await fetch('/resource', { method:'GET', headers:{
            'X-POW-CHALLENGE': challenge,
            'X-POW-NONCE': String(nonce),
            'X-POW-HASH': h
          }});
          const text = await resp.text();
          status.textContent = 'Ответ сервера: ' + text;
          break;
        }
        nonce++;
        if(nonce % 500 === 0) await new Promise(r=>setTimeout(r,0));
      }
    } catch(e){
      status.textContent = 'Ошибка: ' + e;
    }
  }
  run();
})();
</script>
</body>
</html>`;
}

// -------------------- Admin stats builder ----------------------------

function buildAdminStats() {
  const ips = [];
  for (const [ip, s] of state.ipMap.entries()) {
    ips.push({
      ip,
      tokens: Math.floor(s.tokens),
      powDifficulty: s.powDifficulty,
      concurrent: s.concurrent,
      strikes: s.strikes,
      backoffUntil: s.backoffUntil ? new Date(s.backoffUntil).toISOString() : null,
      lastSeen: new Date(s.lastSeen).toISOString()
    });
  }
  return {
    time: new Date().toISOString(),
    underAttack: state.underAttack,
    recentRequestsLast1s: state.recentRequests.length,
    trackedIpCount: state.ipMap.size,
    ips,
    blacklist: Array.from(state.blacklist.entries()).map(([ip, until]) => ({ ip, until: new Date(until).toISOString() }))
  };
}

// -------------------- Request handler (core) -------------------------

async function handleRequest(req, res) {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || '/';
  const method = req.method || 'GET';

  // Extract client IP and state
  const ip = extractClientIp(req);
  const s = ensureIpState(ip);
  s.lastSeen = now();

  // Quick health probe
  if (pathname === '/health' && method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, time: new Date().toISOString() }));
    return;
  }

  // Admin endpoint
  if (pathname === '/admin' && method === 'GET') {
    const token = (parsed.query && parsed.query.token) || '';
    if (token !== CONFIG.ADMIN_TOKEN) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized' }));
      return;
    }
    const stats = buildAdminStats();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(stats, null, 2));
    return;
  }

  // If IP in whitelist -> relax checks (still sandbox)
  if (state.whitelist.has(ip)) {
    // optional: quick allow most GET to /
  }

  // Blacklist check
  const bl = state.blacklist.get(ip);
  if (bl && now() < bl) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  } else if (bl && now() >= bl) {
    state.blacklist.delete(ip);
  }

  // Slowloris: if headers taking too long, socket timeout/callback will close - handled in wrapper

  // Concurrency protection
  s.concurrent = (s.concurrent || 0) + 1;
  // decrement when socket closes
  req.on('close', () => {
    s.concurrent = Math.max(0, (s.concurrent || 1) - 1);
  });

  if (s.concurrent > CONFIG.MAX_CONCURRENT_PER_IP) {
    s.strikes = (s.strikes || 0) + 1;
    s.backoffUntil = now() + Math.min(CONFIG.BACKOFF_MAX_MS, CONFIG.BACKOFF_BASE_MS * Math.pow(2, s.strikes));
    log('Too many concurrent', { ip, concurrent: s.concurrent });
    res.writeHead(429, { 'Content-Type': 'text/plain' });
    res.end('Too many concurrent connections from your IP');
    return;
  }

  // Sliding-window per-IP
  const winOk = slidingWindowAdd(s, CONFIG.WINDOW_MS, CONFIG.WINDOW_LIMIT);
  if (!winOk) {
    s.strikes = (s.strikes || 0) + 1;
    s.backoffUntil = now() + Math.min(CONFIG.BACKOFF_MAX_MS, CONFIG.BACKOFF_BASE_MS * Math.pow(2, s.strikes));
    log('Sliding window exceeded', { ip, windowLen: s.window.length });
    if (s.strikes >= CONFIG.STRIKES_TO_BLACKLIST) {
      const until = now() + CONFIG.BLACKLIST_MS;
      state.blacklist.set(ip, until);
      log('Blacklisted due to repeated sliding-window', { ip, until: new Date(until).toISOString() });
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden');
      return;
    }
    res.writeHead(429, { 'Content-Type': 'text/plain' });
    res.end('Rate limit exceeded (burst)');
    return;
  }

  // Token-bucket per-IP
  refillIpTokens(s);
  if (now() < s.backoffUntil) {
    res.writeHead(429, { 'Content-Type': 'text/plain' });
    res.end('Backoff — try later');
    return;
  }
  if (s.tokens < 1) {
    s.strikes = (s.strikes || 0) + 1;
    s.backoffUntil = now() + Math.min(CONFIG.BACKOFF_MAX_MS, CONFIG.BACKOFF_BASE_MS * Math.pow(2, s.strikes));
    log('Token bucket depleted', { ip, tokens: s.tokens, strikes: s.strikes });
    if (s.strikes >= CONFIG.STRIKES_TO_BLACKLIST) {
      const until = now() + CONFIG.BLACKLIST_MS;
      state.blacklist.set(ip, until);
      log('Blacklisted after tokens exhausted', { ip, until: new Date(until).toISOString() });
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden');
      return;
    }
    res.writeHead(429, { 'Content-Type': 'text/plain' });
    res.end('Rate limit exceeded (tokens)');
    return;
  }
  s.tokens -= 1;

  // Subnet aggregation throttle
  if (CONFIG.ENABLE_SUBNET_AGGREGATION) {
    const sub = subnet24(ip);
    const ss = ensureSubnetState(sub);
    refillSubnetTokens(ss);
    const cutoff = now() - CONFIG.WINDOW_MS;
    while (ss.window.length && ss.window[0] < cutoff) ss.window.shift();
    ss.window.push(now());
    if (ss.tokens < 1) {
      log('Subnet token exhausted', { sub, ip, ssWindow: ss.window.length });
      s.strikes = (s.strikes || 0) + 1;
      if (s.strikes >= CONFIG.STRIKES_TO_BLACKLIST) {
        const until = now() + CONFIG.BLACKLIST_MS;
        state.blacklist.set(ip, until);
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
        return;
      }
      res.writeHead(429, { 'Content-Type': 'text/plain' });
      res.end('Rate limit (subnet)');
      return;
    }
    ss.tokens -= 1;
  }

  // Register unique IPs (distributed attack detection)
  registerUniqueIp(ip);

  // Global soft cap
  const globalRps = registerGlobalRequest();
  if (globalRps > CONFIG.GLOBAL_REQUEST_CAP_PER_SEC) {
    log('Global RPS cap exceeded', { globalRps });
    // During extreme load, probabilistically reject some percent of clients to preserve origin
    const rand = Math.random();
    if (rand < 0.5) {
      res.writeHead(503, { 'Content-Type': 'text/plain' });
      res.end('Service busy — try later');
      return;
    }
  }

  // Adaptive under-attack behavior
  if (state.underAttack.active) {
    // probabilistic extra throttling for non-whitelisted IPs
    if (!state.whitelist.has(ip)) {
      if (Math.random() < 0.6) { // drop ~60% requests under heavy attack
        s.strikes = (s.strikes || 0) + 1;
        res.writeHead(429, { 'Content-Type': 'text/plain' });
        res.end('Under heavy attack — retry');
        return;
      }
    }
    // raise difficulty a bit for this IP
    s.powDifficulty = Math.min(CONFIG.POW_MAX_DIFFICULTY, (s.powDifficulty || CONFIG.POW_BASE_DIFFICULTY) + Math.floor(CONFIG.UNDER_ATTACK_RAISE_DIFFICULTY_BY / 2));
  }

  // Route handling:
  try {
    if (pathname === '/' && method === 'GET') {
      const difficulty = Math.min(CONFIG.POW_MAX_DIFFICULTY, s.powDifficulty || CONFIG.POW_BASE_DIFFICULTY);
      const cookieVal = makeChallengeCookie();
      res.setHeader('Set-Cookie', `CHALLENGE=${cookieVal}; HttpOnly; Path=/; SameSite=Lax`);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(htmlChallengePage(difficulty, cookieVal));
      return;
    }

    if (pathname === '/pow-challenge' && method === 'GET') {
      const difficulty = Math.min(CONFIG.POW_MAX_DIFFICULTY, s.powDifficulty || CONFIG.POW_BASE_DIFFICULTY);
      const challenge = makePowChallenge();
      const cookieVal = makeChallengeCookie();
      res.setHeader('Set-Cookie', `CHALLENGE=${cookieVal}; HttpOnly; Path=/; SameSite=Lax`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ challenge, difficulty }));
      return;
    }

    if (pathname === '/resource' && method === 'GET') {
      const challengeHeader = req.headers['x-pow-challenge'];
      const nonceHeader = req.headers['x-pow-nonce'];
      const hashHeader = req.headers['x-pow-hash'];
      const cookieHeader = req.headers.cookie;
      let cookieChallenge = null;
      if (cookieHeader) {
        const cookies = parseCookies(cookieHeader);
        if (cookies.CHALLENGE) cookieChallenge = parseChallengeCookie(cookies.CHALLENGE);
      }
      let usedChallenge = null;
      if (challengeHeader && verifyPowChallengeSignature(challengeHeader)) usedChallenge = challengeHeader;
      else if (cookieChallenge) usedChallenge = cookieChallenge;

      if (!usedChallenge || !nonceHeader || !hashHeader) {
        s.freeChallengePages = (s.freeChallengePages || 0) + 1;
        if (s.freeChallengePages > CONFIG.FREE_CHALLENGE_PAGES_PER_IP) {
          s.strikes = (s.strikes || 0) + 1;
          if (s.strikes >= CONFIG.STRIKES_TO_BLACKLIST) {
            const until = now() + CONFIG.BLACKLIST_MS;
            state.blacklist.set(ip, until);
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Forbidden');
            return;
          }
          res.writeHead(429, { 'Content-Type': 'text/plain' });
          res.end('Rate limited');
          return;
        }
        const difficulty = Math.min(CONFIG.POW_MAX_DIFFICULTY, s.powDifficulty || CONFIG.POW_BASE_DIFFICULTY);
        const cookieVal = makeChallengeCookie();
        res.setHeader('Set-Cookie', `CHALLENGE=${cookieVal}; HttpOnly; Path=/; SameSite=Lax`);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(htmlChallengePage(difficulty, cookieVal));
        return;
      }

      const difficulty = Math.min(CONFIG.POW_MAX_DIFFICULTY, s.powDifficulty || CONFIG.POW_BASE_DIFFICULTY);
      const ok = verifyPowHeaders(usedChallenge, nonceHeader, hashHeader, difficulty);
      if (!ok) {
        s.strikes = (s.strikes || 0) + 1;
        s.backoffUntil = now() + Math.min(CONFIG.BACKOFF_MAX_MS, CONFIG.BACKOFF_BASE_MS * Math.pow(2, s.strikes));
        if (s.strikes >= CONFIG.STRIKES_TO_BLACKLIST) {
          const until = now() + CONFIG.BLACKLIST_MS;
          state.blacklist.set(ip, until);
          log('Blacklisted after invalid POW', { ip, until: new Date(until).toISOString() });
          res.writeHead(403, { 'Content-Type': 'text/plain' });
          res.end('Forbidden');
          return;
        }
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Invalid proof-of-work');
        return;
      }

      // POW success — slightly reward client (reduce difficulty)
      s.powDifficulty = Math.max(CONFIG.POW_BASE_DIFFICULTY, (s.powDifficulty || CONFIG.POW_BASE_DIFFICULTY) - 1);
      // Serve protected resource
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('Protected resource — OK. Server time: ' + new Date().toISOString());
      return;
    }

    // Fallback
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
    return;
  } catch (e) {
    error('handleRequest error', e);
    try { res.writeHead(500, { 'Content-Type': 'text/plain' }); res.end('Internal server error'); } catch (er) {}
    return;
  }
}

// parse cookie header helper
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  const parts = header.split(';').map(s => s.trim());
  for (const p of parts) {
    const idx = p.indexOf('=');
    if (idx < 0) continue;
    out[p.slice(0, idx)] = p.slice(idx + 1);
  }
  return out;
}

// ------------------ handleRequestWrapper and swap-in ------------------

// wrapper that enforces header/body timeouts and catches errors
function handleRequestWrapper(req, res) {
  const socket = req.socket;
  // header timeout
  let headerTimeout = setTimeout(() => {
    try { socket.destroy(); } catch (e) {}
  }, CONFIG.MAX_HEADER_COMPLETE_MS);
  req.on('data', () => {
    clearTimeout(headerTimeout);
  });
  req.on('end', () => {
    clearTimeout(headerTimeout);
  });
  // body chunk timeout
  socket.setTimeout(CONFIG.MAX_BODY_CHUNK_WAIT_MS, () => {
    try { socket.destroy(); } catch (e) {}
  });

  try {
    handleRequest(req, res);
  } catch (e) {
    error('handleRequestWrapper internal error', e);
    try { res.writeHead(500, {'Content-Type':'text/plain'}); res.end('Internal error'); } catch (er) {}
  }
}

// ---------------------- Server bootstrap -------------------

const server = http.createServer(handleRequestWrapper);

// Basic clientError handler
server.on('clientError', (err, socket) => {
  try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch (e) {}
});

// set timeouts to mitigate slowloris
server.setTimeout(CONFIG.MAX_HEADER_COMPLETE_MS + 5000, (socket) => {
  try { socket.destroy(); } catch (e) {}
});

// FIXED FOR RENDER: Use environment PORT
const PORT = process.env.PORT || 10000;
server.listen(PORT, '0.0.0.0', () => {
  log(`server_ultimate_secure.js listening on port ${PORT}`);
  log('ADMIN_TOKEN:', CONFIG.ADMIN_TOKEN);
  log('COOKIE_SECRET:', CONFIG.COOKIE_SECRET);
});

// --------------------- Periodic cleanup, metrics ----------------------

setInterval(() => {
  // prune stale ipMap entries not seen for 24h
  const cutoff = now() - 24 * 60 * 60 * 1000;
  for (const [ip, s] of state.ipMap.entries()) {
    if (s.lastSeen < cutoff) state.ipMap.delete(ip);
  }
  // prune uniqueIpTimestamps older than window
  const cutoffU = now() - CONFIG.UNIQUE_IP_WINDOW_MS;
  while (state.uniqueIpTimestamps.length && state.uniqueIpTimestamps[0].t < cutoffU) state.uniqueIpTimestamps.shift();
  // prune expired blacklists
  for (const [ip, until] of state.blacklist.entries()) {
    if (now() >= until) state.blacklist.delete(ip);
  }
}, 60 * 1000);

// metrics log
setInterval(() => {
  try {
    const metrics = {
      time: new Date().toISOString(),
      ipCount: state.ipMap.size,
      blacklistSize: state.blacklist.size,
      underAttack: state.underAttack.active,
      recentRequestsLast1s: state.recentRequests.length,
      memMB: Math.round(process.memoryUsage().heapUsed / 1024 / 1024)
    };
    log('METRICS', JSON.stringify(metrics));
  } catch (e) {}
}, 5 * 60 * 1000);

// --------------------- Graceful shutdown -------------------------------

function gracefulShutdown() {
  log('Graceful shutdown initiated.');
  try {
    server.close(() => {
      log('Server closed.');
      process.exit(0);
    });
    // force exit after 10s
    setTimeout(() => {
      log('Forcing shutdown.');
      process.exit(1);
    }, 10000);
  } catch (e) {
    log('Error during shutdown', e);
    process.exit(1);
  }
}
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

log('Server loaded: full handler active. Server ready.');


