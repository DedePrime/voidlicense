const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 8090;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'void123';
const ONLINE_TIMEOUT = 30000;
const SESSION_TTL = 1000 * 60 * 60 * 12; // 12h
const LOGIN_WINDOW = 1000 * 60 * 5;      // 5 min
const LOGIN_MAX_ATTEMPTS = 5;
const MAX_LOGS = 500;
const MAX_DAYS = 36500;                  // ~100 anni

const DB_FILE = path.join(__dirname, 'db.json');
const BACKUP_FILE = path.join(__dirname, 'db.backup.json');

let db = { licenses: [], logs: [] };
let saveTimer = null;

// ---------- Persistenza ----------
function loadDb() {
  if (fs.existsSync(DB_FILE)) {
    try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) {}
  }
  if (!db.licenses) db.licenses = [];
  if (!db.logs) db.logs = [];
}
function saveDbNow() {
  try {
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
    fs.renameSync(tmp, DB_FILE);
    fs.copyFileSync(DB_FILE, BACKUP_FILE);
  } catch (e) {}
}
function saveDb() {
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(saveDbNow, 300);
}

// ---------- Utils ----------
function genKey() {
  const p = [];
  for (let i = 0; i < 4; i++) p.push(crypto.randomBytes(2).toString('hex').toUpperCase());
  return 'VOID-' + p.join('-');
}
function findLic(k) { return db.licenses.find(l => l.key === k); }
function isOnline(l) { return l.lastPing && (Date.now() - l.lastPing) < ONLINE_TIMEOUT; }
function isExpired(l) { return !l.infinite && l.expiresAt < Date.now(); }
function addLog(action, detail, ip) {
  db.logs.unshift({ ts: Date.now(), action, detail: detail || '', ip: ip || '' });
  if (db.logs.length > MAX_LOGS) db.logs.length = MAX_LOGS;
  saveDb();
}

// ---------- Sessioni admin ----------
const sessions = new Map();
const loginAttempts = new Map();

function createSession() {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { expires: Date.now() + SESSION_TTL });
  return token;
}
function checkSession(token) {
  const s = sessions.get(token);
  if (!s) return false;
  if (s.expires < Date.now()) { sessions.delete(token); return false; }
  return true;
}
setInterval(() => {
  const now = Date.now();
  for (const [t, s] of sessions) if (s.expires < now) sessions.delete(t);
  for (const [ip, a] of loginAttempts) if (now - a.firstTs > LOGIN_WINDOW) loginAttempts.delete(ip);
}, 60000);

function loginRateLimit(req, res, next) {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const a = loginAttempts.get(ip) || { count: 0, firstTs: now };
  if (now - a.firstTs > LOGIN_WINDOW) { a.count = 0; a.firstTs = now; }
  if (a.count >= LOGIN_MAX_ATTEMPTS) {
    return res.status(429).json({ ok: false, msg: 'Troppi tentativi. Riprova tra qualche minuto.' });
  }
  loginAttempts.set(ip, a);
  req._loginAttempt = () => { a.count++; loginAttempts.set(ip, a); };
  next();
}

// ---------- App ----------
loadDb();
const app = express();
app.set('trust proxy', true);
app.use(express.json({ limit: '512kb' }));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Pass, X-Admin-Token');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ---------- API licenza (client) ----------
app.post('/api/license/check', (req, res) => {
  const { key, hwid, username } = req.body || {};
  if (!key) return res.json({ ok: false, msg: 'Chiave mancante' });
  if (!hwid) return res.json({ ok: false, msg: 'HWID mancante' });
  const lic = findLic(key);
  if (!lic) return res.json({ ok: false, msg: 'Chiave non valida' });
  if (lic.banned) return res.json({ ok: false, msg: 'Licenza disattivata' });
  if (isExpired(lic)) return res.json({ ok: false, msg: 'Licenza scaduta' });

  if (!username) {
    if (!lic.username) return res.json({ ok: false, msg: 'Licenza non configurata' });
    if (lic.hwid && lic.hwid !== hwid) return res.json({ ok: false, msg: 'Licenza in uso su un altro PC' });
    lic.lastPing = Date.now(); lic.lastIp = req.ip || ''; saveDb();
    return res.json({ ok: true, msg: 'OK', expires: lic.infinite ? -1 : lic.expiresAt, infinite: !!lic.infinite, username: lic.username });
  }
  if (!lic.username) {
    const taken = db.licenses.find(l => l.username && l.username.toLowerCase() === username.toLowerCase());
    if (taken && taken.key !== key) return res.json({ ok: false, msg: 'Username gia usato' });
    lic.username = username; lic.hwid = hwid; lic.lastPing = Date.now(); lic.lastIp = req.ip || ''; saveDb();
    return res.json({ ok: true, msg: 'OK', expires: lic.infinite ? -1 : lic.expiresAt, infinite: !!lic.infinite, username: lic.username });
  }
  if (lic.username.toLowerCase() !== username.toLowerCase()) return res.json({ ok: false, msg: 'Username non corrisponde' });
  if (lic.hwid && lic.hwid !== hwid) return res.json({ ok: false, msg: 'Licenza in uso su un altro PC' });
  lic.hwid = hwid; lic.lastPing = Date.now(); lic.lastIp = req.ip || ''; saveDb();
  res.json({ ok: true, msg: 'OK', expires: lic.infinite ? -1 : lic.expiresAt, infinite: !!lic.infinite, username: lic.username });
});

app.post('/api/license/heartbeat', (req, res) => {
  const { key, hwid, username } = req.body || {};
  const lic = findLic(key);
  if (!lic) return res.json({ ok: false });
  if (lic.banned) return res.json({ ok: false, banned: true });
  if (isExpired(lic)) return res.json({ ok: false, expired: true });
  if (lic.hwid && lic.hwid !== hwid) return res.json({ ok: false, hwid: true });
  if (lic.username && username && lic.username.toLowerCase() !== username.toLowerCase()) return res.json({ ok: false, user: true });
  lic.lastPing = Date.now(); lic.lastIp = req.ip || ''; saveDb();
  res.json({ ok: true, infinite: !!lic.infinite });
});

app.post('/api/license/register', (req, res) => {
  const { key, hwid, username } = req.body || {};
  const lic = findLic(key);
  if (!lic) return res.json({ ok: false, msg: 'Chiave non valida' });
  if (lic.banned) return res.json({ ok: false, msg: 'Licenza disattivata' });
  if (isExpired(lic)) return res.json({ ok: false, msg: 'Licenza scaduta' });
  if (!username || username.length < 2) return res.json({ ok: false, msg: 'Username corto' });
  const taken = db.licenses.find(l => l.username && l.username.toLowerCase() === username.toLowerCase() && l.key !== key);
  if (taken) return res.json({ ok: false, msg: 'Username gia in uso' });
  lic.username = username; lic.hwid = hwid; lic.lastPing = Date.now(); lic.lastIp = req.ip || ''; saveDb();
  res.json({ ok: true });
});

// ---------- Auth admin ----------
function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (token && checkSession(token)) return next();
  if (req.headers['x-admin-pass'] === ADMIN_PASSWORD) return next();
  return res.status(401).json({ ok: false });
}

app.post('/api/admin/login', loginRateLimit, (req, res) => {
  const pass = (req.body || {}).password;
  if (pass !== ADMIN_PASSWORD) {
    req._loginAttempt();
    addLog('login.fail', '', req.ip);
    return res.json({ ok: false, msg: 'Password errata' });
  }
  const token = createSession();
  addLog('login.ok', '', req.ip);
  res.json({ ok: true, token });
});

app.post('/api/admin/logout', adminAuth, (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token) sessions.delete(token);
  addLog('logout', '', req.ip);
  res.json({ ok: true });
});

// ---------- Admin: liste, filtri, stats ----------
app.get('/api/admin/list', adminAuth, (req, res) => {
  const now = Date.now();
  const q = (req.query.q || '').toLowerCase().trim();
  const filter = req.query.filter || 'all';
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const perPage = Math.min(200, Math.max(10, parseInt(req.query.perPage, 10) || 50));

  let list = db.licenses.map(l => ({
    key: l.key, username: l.username || null, hwid: l.hwid,
    online: isOnline(l), banned: !!l.banned,
    infinite: !!l.infinite,
    expiresAt: l.infinite ? Number.MAX_SAFE_INTEGER : l.expiresAt,
    expired: isExpired(l),
    createdAt: l.createdAt,
    lastPingAgo: l.lastPing ? Math.floor((now - l.lastPing) / 1000) : null,
    lastIp: l.lastIp, note: l.note || ''
  }));

  if (q) {
    list = list.filter(l =>
      (l.key && l.key.toLowerCase().includes(q)) ||
      (l.username && l.username.toLowerCase().includes(q)) ||
      (l.note && l.note.toLowerCase().includes(q)) ||
      (l.hwid && l.hwid.toLowerCase().includes(q))
    );
  }
  if (filter === 'online') list = list.filter(l => l.online && !l.banned && !l.expired);
  else if (filter === 'offline') list = list.filter(l => !l.online && !l.banned && !l.expired);
  else if (filter === 'expired') list = list.filter(l => l.expired);
  else if (filter === 'banned') list = list.filter(l => l.banned);
  else if (filter === 'infinite') list = list.filter(l => l.infinite);

  list.sort((a, b) => (b.online - a.online) || a.key.localeCompare(b.key));

  const total = list.length;
  const start = (page - 1) * perPage;
  const paged = list.slice(start, start + perPage);

  res.json({ ok: true, licenses: paged, total, page, perPage, serverTime: now });
});

app.get('/api/admin/stats', adminAuth, (req, res) => {
  const now = Date.now();
  const total = db.licenses.length;
  let online = 0, banned = 0, expired = 0, active = 0, infinite = 0;
  for (const l of db.licenses) {
    const o = isOnline(l);
    const e = isExpired(l);
    if (o && !l.banned && !e) online++;
    if (l.banned) banned++;
    if (e) expired++;
    if (!l.banned && !e) active++;
    if (l.infinite) infinite++;
  }
  res.json({ ok: true, stats: { total, online, banned, expired, active, infinite, logs: db.logs.length } });
});

app.get('/api/admin/logs', adminAuth, (req, res) => {
  res.json({ ok: true, logs: db.logs.slice(0, 200) });
});

// ---------- Admin: azioni ----------
app.post('/api/admin/create', adminAuth, (req, res) => {
  const { days, username, note, infinite } = req.body || {};
  const d = parseInt(days, 10) || 30;
  if (!username) return res.json({ ok: false, msg: 'Username obbligatorio' });
  if (db.licenses.find(l => l.username && l.username.toLowerCase() === username.toLowerCase()))
    return res.json({ ok: false, msg: 'Username gia usato' });
  if (!infinite && (d < 1 || d > MAX_DAYS)) return res.json({ ok: false, msg: 'Giorni non validi (1-' + MAX_DAYS + ')' });

  const lic = {
    key: genKey(), username, hwid: null,
    createdAt: Date.now(),
    expiresAt: infinite ? Number.MAX_SAFE_INTEGER : Date.now() + d * 24 * 3600 * 1000,
    infinite: !!infinite,
    banned: false, lastPing: 0, lastIp: null, note: note || ''
  };
  db.licenses.push(lic); saveDb();
  addLog('create', `${lic.key} → ${username} (${infinite ? '∞' : d + 'gg'})`, req.ip);
  res.json({ ok: true, license: lic });
});

app.post('/api/admin/ban', adminAuth, (req, res) => {
  const lic = findLic((req.body || {}).key);
  if (!lic) return res.json({ ok: false });
  lic.banned = !!(req.body || {}).banned;
  saveDb();
  addLog(lic.banned ? 'ban' : 'unban', lic.key, req.ip);
  res.json({ ok: true });
});

app.post('/api/admin/reset', adminAuth, (req, res) => {
  const lic = findLic((req.body || {}).key);
  if (!lic) return res.json({ ok: false });
  lic.hwid = null; lic.lastPing = 0; saveDb();
  addLog('reset-hwid', lic.key, req.ip);
  res.json({ ok: true });
});

app.post('/api/admin/resetUser', adminAuth, (req, res) => {
  const lic = findLic((req.body || {}).key);
  if (!lic) return res.json({ ok: false });
  lic.username = null; lic.hwid = null; lic.lastPing = 0; saveDb();
  addLog('reset-user', lic.key, req.ip);
  res.json({ ok: true });
});

// Estendi di N giorni
app.post('/api/admin/extend', adminAuth, (req, res) => {
  const lic = findLic((req.body || {}).key);
  if (!lic) return res.json({ ok: false, msg: 'Licenza non trovata' });
  if (lic.infinite) return res.json({ ok: false, msg: 'Licenza infinita: disattiva prima l\'infinito' });
  const d = parseInt((req.body || {}).days, 10);
  if (!d || d < 1 || d > MAX_DAYS) return res.json({ ok: false, msg: 'Giorni non validi (1-' + MAX_DAYS + ')' });
  lic.expiresAt = Math.max(lic.expiresAt, Date.now()) + d * 24 * 3600 * 1000;
  saveDb();
  addLog('extend', `${lic.key} +${d}gg`, req.ip);
  res.json({ ok: true, expiresAt: lic.expiresAt });
});

// Imposta una data di scadenza precisa
app.post('/api/admin/setExpiry', adminAuth, (req, res) => {
  const lic = findLic((req.body || {}).key);
  if (!lic) return res.json({ ok: false, msg: 'Licenza non trovata' });
  const ts = parseInt((req.body || {}).expiresAt, 10);
  if (!ts || !Number.isFinite(ts)) return res.json({ ok: false, msg: 'Data non valida' });
  lic.expiresAt = ts;
  lic.infinite = false;
  saveDb();
  addLog('set-expiry', `${lic.key} → ${new Date(ts).toISOString().slice(0, 10)}`, req.ip);
  res.json({ ok: true, expiresAt: lic.expiresAt });
});

// Rendi infinita
app.post('/api/admin/setInfinite', adminAuth, (req, res) => {
  const lic = findLic((req.body || {}).key);
  if (!lic) return res.json({ ok: false, msg: 'Licenza non trovata' });
  lic.infinite = true;
  lic.expiresAt = Number.MAX_SAFE_INTEGER;
  saveDb();
  addLog('set-infinite', lic.key, req.ip);
  res.json({ ok: true });
});

app.post('/api/admin/delete', adminAuth, (req, res) => {
  const k = (req.body || {}).key;
  db.licenses = db.licenses.filter(l => l.key !== k);
  saveDb();
  addLog('delete', k, req.ip);
  res.json({ ok: true });
});

app.post('/api/admin/rename', adminAuth, (req, res) => {
  const { key, username } = req.body || {};
  const lic = findLic(key);
  if (!lic) return res.json({ ok: false, msg: 'Non trovata' });
  if (!username || username.length < 2) return res.json({ ok: false, msg: 'Username corto' });
  const taken = db.licenses.find(l => l.username && l.username.toLowerCase() === username.toLowerCase() && l.key !== key);
  if (taken) return res.json({ ok: false, msg: 'Username gia usato' });
  lic.username = username; saveDb();
  addLog('rename', `${lic.key} → ${username}`, req.ip);
  res.json({ ok: true });
});

app.post('/api/admin/note', adminAuth, (req, res) => {
  const { key, note } = req.body || {};
  const lic = findLic(key);
  if (!lic) return res.json({ ok: false });
  lic.note = String(note || '').slice(0, 500); saveDb();
  addLog('note', lic.key, req.ip);
  res.json({ ok: true });
});

// ---------- Export CSV ----------
app.get('/api/admin/export.csv', adminAuth, (req, res) => {
  const now = Date.now();
  const rows = [['key', 'username', 'hwid', 'status', 'infinite', 'expiresAt', 'createdAt', 'lastPing', 'lastIp', 'note']];
  for (const l of db.licenses) {
    const status = l.banned ? 'banned' : (isExpired(l) ? 'expired' : (isOnline(l) ? 'online' : 'offline'));
    rows.push([
      l.key, l.username || '', l.hwid || '', status,
      l.infinite ? 'yes' : 'no',
      l.infinite ? 'NEVER' : new Date(l.expiresAt).toISOString(),
      new Date(l.createdAt).toISOString(),
      l.lastPing ? new Date(l.lastPing).toISOString() : '',
      l.lastIp || '', l.note || ''
    ]);
  }
  const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
  res.header('Content-Type', 'text/csv');
  res.header('Content-Disposition', 'attachment; filename="voidlicense-export.csv"');
  res.send(csv);
});

// ---------- Static ----------
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log('VoidLicense v2.1.0 - Port ' + PORT);
  if (ADMIN_PASSWORD === 'admin123') {
    console.warn('⚠️  ADMIN_PASSWORD di default! Imposta la variabile d\'ambiente.');
  }
});
