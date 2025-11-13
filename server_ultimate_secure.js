// server_ultimate_secure.js — полная версия без process.env
// Massive standalone Node.js server with multi-layer DDoS defenses.
// Everything in one file. No external NPM dependencies.
// HTML UIs in Russian.
// --------------------------------------------------------------------

// --------------------------- IMPORTS --------------------------------
const http = require('http');
const crypto = require('crypto');
const url = require('url');

// -------------------------- CONFIG ----------------------------------
// Hardcoded secrets (no environment variables)
const CONFIG = {
  // Ports (используем порт Render)
  PORT: 10000,

  // Per-IP token bucket (target ~10 req/sec)
  TOKEN_BUCKET_CAPACITY: 12,
  TOKEN_REFILL_PER_SEC: 10,

  // Sliding window burst control
  WINDOW_MS: 1000,
  WINDOW_LIMIT: 10,

  // Concurrent connection limit per IP
  MAX_CONCURRENT_PER_IP: 6,

  // Proof-of-Work (POW)
  POW_BASE_DIFFICULTY: 16, // Reduced for better UX
  POW_MAX_DIFFICULTY: 24,

  // Backoff / strikes
  BACKOFF_BASE_MS: 200,
  BACKOFF_MAX_MS: 10 * 60 * 1000,
  STRIKES_TO_BLACKLIST: 6,
  BLACKLIST_MS: 6 * 60 * 60 * 1000,

  // Cookie/signing secret and admin token
  COOKIE_SECRET: 'c4d2e1f0b9a8c7d6e5f4a3b2c1d0e9f8',
  ADMIN_TOKEN: 'q9HfX2e7BzRkM8vP0sVnYcT4wLrJ6uF3ZdA1pQe8YmN5oU2xG0HtC7kLwS4bV1zA',

  // Misc
  VERBOSE: true,

  // Limits
  FREE_CHALLENGE_PAGES_PER_IP: 8,
  MAX_IP_ENTRIES_IN_MEMORY: 20000
};

// ----------------------- GLOBAL STATE -------------------------------
const state = {
  ipMap: new Map(),
  blacklist: new Map(),
  recentRequests: []
};

// ----------------------- UTIL FUNCTIONS -----------------------------
function now() { return Date.now(); }
function log(...args) { if (CONFIG.VERBOSE) console.log(new Date().toISOString(), ...args); }

function normalizeIp(raw) {
  if (!raw) return '0.0.0.0';
  if (raw.startsWith('::ffff:')) return raw.slice(7);
  if (raw === '::1') return '127.0.0.1';
  return raw;
}

function extractClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const client = xff.split(',')[0].trim();
    return normalizeIp(client);
  }
  return normalizeIp(req.socket.remoteAddress || '0.0.0.0');
}

function sha256hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function hmacSign(data) {
  return crypto.createHmac('sha256', CONFIG.COOKIE_SECRET).update(String(data)).digest('hex');
}

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
function ensureIpState(ip) {
  ip = normalizeIp(ip);
  if (state.ipMap.has(ip)) return state.ipMap.get(ip);
  
  // Memory management
  if (state.ipMap.size > CONFIG.MAX_IP_ENTRIES_IN_MEMORY) {
    const arr = Array.from(state.ipMap.entries());
    arr.sort((a, b) => a[1].lastSeen - b[1].lastSeen);
    const toRemove = Math.max(1, Math.floor(arr.length * 0.05));
    for (let i = 0; i < toRemove; i++) state.ipMap.delete(arr[i][0]);
  }

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
  state.ipMap.set(ip, s);
  return s;
}

function refillIpTokens(s) {
  const elapsed = (now() - s.lastRefill) / 1000;
  if (elapsed > 0) {
    const add = elapsed * CONFIG.TOKEN_REFILL_PER_SEC;
    s.tokens = Math.min(CONFIG.TOKEN_BUCKET_CAPACITY, s.tokens + add);
    s.lastRefill = now();
  }
}

function slidingWindowAdd(s, windowMs, limit) {
  const t = now();
  const cutoff = t - windowMs;
  while (s.window.length && s.window[0] < cutoff) s.window.shift();
  s.window.push(t);
  return s.window.length <= limit;
}

// ------------------- POW (Proof-of-Work) -----------------------------
function makePowChallenge() {
  const rand = crypto.randomBytes(16).toString('hex');
  const ts = Math.floor(now() / 1000).toString(16);
  const base = `${rand}:${ts}`;
  const sig = hmacSign(base);
  return `${base}:${sig}`;
}

function verifyPowSolution(challenge, nonce, difficulty) {
  if (!challenge || !nonce) return false;
  
  // Basic challenge format validation
  const parts = challenge.split(':');
  if (parts.length < 3) return false;
  
  const computed = sha256hex(challenge + ':' + nonce);
  const zeros = countLeadingZeroBits(computed);
  return zeros >= difficulty;
}

// -------------------- HTML challenge page (RU) -----------------------
function htmlChallengePage(difficulty) {
  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CYBERSECURITY PROTECTION</title>
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
    <h1>🔒 CYBERSECURITY PROTECTION</h1>
    <p>Для доступа требуется небольшая задача Proof-of-Work — быстро для людей, дорого для массовых ботов.</p>
    <div id="status" class="status">Загрузка задачи...</div>
    <div style="margin-top:12px">
      <button id="retry">Попробовать снова</button> 
      <span class="small">Поддержка: modern browser</span>
    </div>
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
      for(let b=3;b>=0;b--){ 
        if(((nib>>b)&1)===0) zeros++; 
        else return zeros; 
      }
    }
    return zeros;
  }
  
  async function run(){
    try{
      status.textContent='Запрос задачи...';
      const r = await fetch('/pow-challenge');
      if(!r.ok){ 
        status.textContent='Ошибка получения задачи: '+r.status; 
        return; 
      }
      const j = await r.json();
      const challenge = j.challenge;
      const difficulty = j.difficulty;
      status.textContent='Решаю задачу (сложность '+difficulty+')...';
      let nonce = 0;
      const start = performance.now();
      
      while(true){
        const h = await sha256hex(challenge + ':' + nonce);
        if(countLeadingZeroBits(h) >= difficulty){
          const took = Math.round(performance.now()-start);
          status.textContent='Решено за '+took+'ms, отправляю запрос...';
          
          const resp = await fetch('/resource?challenge=' + encodeURIComponent(challenge) + '&nonce=' + nonce);
          const text = await resp.text();
          status.textContent = '✅ ' + text;
          break;
        }
        nonce++;
        if(nonce % 500 === 0) await new Promise(r=>setTimeout(r,0));
      }
    } catch(e){
      status.textContent = '❌ Ошибка: ' + e.message;
    }
  }
  run();
})();
</script>
</body>
</html>`;
}

// -------------------- Request handler -------------------------
async function handleRequest(req, res) {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || '/';
  const method = req.method || 'GET';

  // Add CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  const ip = extractClientIp(req);
  const s = ensureIpState(ip);
  s.lastSeen = now();

  // Health check endpoint
  if (pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      ok: true, 
      time: new Date().toISOString(),
      ip: ip,
      trackedIps: state.ipMap.size
    }));
    return;
  }

  // Admin endpoint
  if (pathname === '/admin') {
    const token = parsed.query.token || '';
    if (token !== CONFIG.ADMIN_TOKEN) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized' }));
      return;
    }
    const stats = {
      time: new Date().toISOString(),
      trackedIpCount: state.ipMap.size,
      blacklistSize: state.blacklist.size,
      recentRequests: state.recentRequests.length
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(stats, null, 2));
    return;
  }

  // Blacklist check
  const bl = state.blacklist.get(ip);
  if (bl && now() < bl) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden - IP blacklisted');
    return;
  } else if (bl && now() >= bl) {
    state.blacklist.delete(ip);
  }

  // Concurrency protection
  s.concurrent = (s.concurrent || 0) + 1;
  req.on('close', () => {
    s.concurrent = Math.max(0, (s.concurrent || 1) - 1);
  });

  if (s.concurrent > CONFIG.MAX_CONCURRENT_PER_IP) {
    s.strikes = (s.strikes || 0) + 1;
    s.backoffUntil = now() + Math.min(CONFIG.BACKOFF_MAX_MS, CONFIG.BACKOFF_BASE_MS * Math.pow(2, s.strikes));
    res.writeHead(429, { 'Content-Type': 'text/plain' });
    res.end('Too many concurrent connections');
    return;
  }

  // Rate limiting - sliding window
  const winOk = slidingWindowAdd(s, CONFIG.WINDOW_MS, CONFIG.WINDOW_LIMIT);
  if (!winOk) {
    s.strikes = (s.strikes || 0) + 1;
    s.backoffUntil = now() + Math.min(CONFIG.BACKOFF_MAX_MS, CONFIG.BACKOFF_BASE_MS * Math.pow(2, s.strikes));
    
    if (s.strikes >= CONFIG.STRIKES_TO_BLACKLIST) {
      const until = now() + CONFIG.BLACKLIST_MS;
      state.blacklist.set(ip, until);
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden - IP blacklisted');
      return;
    }
    
    res.writeHead(429, { 'Content-Type': 'text/plain' });
    res.end('Rate limit exceeded (burst)');
    return;
  }

  // Rate limiting - token bucket
  refillIpTokens(s);
  
  if (now() < s.backoffUntil) {
    res.writeHead(429, { 'Content-Type': 'text/plain' });
    res.end('Backoff — try later');
    return;
  }
  
  if (s.tokens < 1) {
    s.strikes = (s.strikes || 0) + 1;
    s.backoffUntil = now() + Math.min(CONFIG.BACKOFF_MAX_MS, CONFIG.BACKOFF_BASE_MS * Math.pow(2, s.strikes));
    
    if (s.strikes >= CONFIG.STRIKES_TO_BLACKLIST) {
      const until = now() + CONFIG.BLACKLIST_MS;
      state.blacklist.set(ip, until);
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden - IP blacklisted');
      return;
    }
    
    res.writeHead(429, { 'Content-Type': 'text/plain' });
    res.end('Rate limit exceeded (tokens)');
    return;
  }
  s.tokens -= 1;

  // Global request tracking
  state.recentRequests.push(now());
  const cutoff = now() - 1000;
  while (state.recentRequests.length && state.recentRequests[0] < cutoff) {
    state.recentRequests.shift();
  }

  try {
    // Serve main challenge page
    if (pathname === '/' && method === 'GET') {
      const difficulty = Math.min(CONFIG.POW_MAX_DIFFICULTY, s.powDifficulty || CONFIG.POW_BASE_DIFFICULTY);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(htmlChallengePage(difficulty));
      return;
    }

    // POW challenge endpoint
    if (pathname === '/pow-challenge' && method === 'GET') {
      const difficulty = Math.min(CONFIG.POW_MAX_DIFFICULTY, s.powDifficulty || CONFIG.POW_BASE_DIFFICULTY);
      const challenge = makePowChallenge();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ challenge, difficulty }));
      return;
    }

    // Resource endpoint (requires POW)
    if (pathname === '/resource' && method === 'GET') {
      const challenge = parsed.query.challenge;
      const nonce = parsed.query.nonce;
      
      if (!challenge || !nonce) {
        s.freeChallengePages = (s.freeChallengePages || 0) + 1;
        if (s.freeChallengePages > CONFIG.FREE_CHALLENGE_PAGES_PER_IP) {
          res.writeHead(429, { 'Content-Type': 'text/plain' });
          res.end('Too many failed attempts');
          return;
        }
        
        const difficulty = Math.min(CONFIG.POW_MAX_DIFFICULTY, s.powDifficulty || CONFIG.POW_BASE_DIFFICULTY);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(htmlChallengePage(difficulty));
        return;
      }

      const difficulty = Math.min(CONFIG.POW_MAX_DIFFICULTY, s.powDifficulty || CONFIG.POW_BASE_DIFFICULTY);
      const isValid = verifyPowSolution(challenge, nonce, difficulty);
      
      if (!isValid) {
        s.strikes = (s.strikes || 0) + 1;
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Invalid proof-of-work');
        return;
      }

      // Success - reduce difficulty for good clients
      s.powDifficulty = Math.max(CONFIG.POW_BASE_DIFFICULTY, (s.powDifficulty || CONFIG.POW_BASE_DIFFICULTY) - 1);
      
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('🎉 Access granted! Protected resource loaded successfully. Time: ' + new Date().toISOString());
      return;
    }

    // Fallback - show available endpoints
    res.writeHead(404, { 'Content-Type': 'text/html' });
    res.end(`
      <html>
        <body style="font-family: Arial; padding: 20px;">
          <h1>404 - Not Found</h1>
          <p>Available endpoints:</p>
          <ul>
            <li><a href="/">/</a> - Main page</li>
            <li><a href="/health">/health</a> - Health check</li>
            <li><a href="/pow-challenge">/pow-challenge</a> - Get POW challenge</li>
            <li>/resource?challenge=...&nonce=... - Access protected resource</li>
          </ul>
        </body>
      </html>
    `);
    
  } catch (e) {
    log('handleRequest error', e);
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Internal server error');
  }
}

// ---------------------- Server startup -------------------
const server = http.createServer(handleRequest);

// Use fixed port
const PORT = CONFIG.PORT;

server.listen(PORT, '0.0.0.0', () => {
  log(`🚀 Server successfully started on port ${PORT}`);
  log(`📧 Admin token: ${CONFIG.ADMIN_TOKEN}`);
  log(`🔐 Cookie secret: ${CONFIG.COOKIE_SECRET}`);
  log(`📍 Server URL: http://localhost:${PORT}/`);
});

// Cleanup interval
setInterval(() => {
  const cutoff = now() - 24 * 60 * 60 * 1000;
  for (const [ip, s] of state.ipMap.entries()) {
    if (s.lastSeen < cutoff) state.ipMap.delete(ip);
  }
  
  for (const [ip, until] of state.blacklist.entries()) {
    if (now() >= until) state.blacklist.delete(ip);
  }
}, 60 * 1000);

// Graceful shutdown
process.on('SIGTERM', () => {
  log('Shutting down gracefully...');
  server.close(() => {
    process.exit(0);
  });
});

log('Server loaded and ready for requests!');
