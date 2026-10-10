'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/* ============================================================
 * CONFIGURAZIONE
 * ============================================================ */
const PORT = process.env.PORT || 8090;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'void123';
const ONLINE_TIMEOUT = 30000;             // 30s → considerato online
const SESSION_TTL = 1000 * 60 * 60 * 12;  // 12h
const LOGIN_WINDOW = 1000 * 60 * 5;       // 5 min
const LOGIN_MAX_ATTEMPTS = 5;
const MAX_LOGS = 500;
const MAX_DAYS = 36500;

const DATA_DIR = process.env.DATA_DIR || __dirname;
try { if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}
const DB_FILE = path.join(DATA_DIR, 'db.json');
const BACKUP_FILE = path.join(DATA_DIR, 'db.backup.json');

/* ============================================================
 * DATABASE
 * ============================================================ */
let db = { licenses: [], logs: [] };
let saveTimer = null;

function loadDb() {
  if (fs.existsSync(DB_FILE)) {
    try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) {}
  }
  if (!db.licenses) db.licenses = [];
  if (!db.logs) db.logs = [];

  // Migrazione: aggiungi maxPrograms se mancante
  for (const l of db.licenses) {
    if (typeof l.maxPrograms !== 'number') l.maxPrograms = 1;
    if (!Array.isArray(l.programs)) l.programs = [];
  }
}
function saveDbNow() {
  try {
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
    fs.renameSync(tmp, DB_FILE);
    try { fs.copyFileSync(DB_FILE, BACKUP_FILE); } catch (e) {}
  } catch (e) {}
}
function saveDb() {
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(saveDbNow, 300);
}

function genKey() {
  const p = [];
  for (let i = 0; i < 4; i++) p.push(crypto.randomBytes(2).toString('hex').toUpperCase());
  return 'VOID-' + p.join('-');
}
function genProgramId() {
  return crypto.randomBytes(8).toString('hex');
}
function findLic(k) { return db.licenses.find(l => l.key === k); }
function isOnline(l) { return l.lastPing && (Date.now() - l.lastPing) < ONLINE_TIMEOUT; }
function isExpired(l) { return !l.infinite && l.expiresAt < Date.now(); }

function addLog(action, detail, ip) {
  db.logs.unshift({ ts: Date.now(), action, detail: detail || '', ip: ip || '' });
  if (db.logs.length > MAX_LOGS) db.logs.length = MAX_LOGS;
  saveDb();
}

/* ============================================================
 * PROGRAMMI ASSOCIATI A UNA LICENZA
 * Ogni licenza ha maxPrograms (default 1).
 * Ogni "programma" è identificato da: appId + hwid.
 * Es: { appId: 'voidutility', hwid: 'abc123...', activatedAt: ts }
 * ============================================================ */
function findProgram(lic, appId, hwid) {
  if (!lic.programs) lic.programs = [];
  return lic.programs.find(p => p.appId === appId && p.hwid === hwid);
}
function countPrograms(lic, appId) {
  if (!lic.programs) lic.programs = [];
  return lic.programs.filter(p => p.appId === appId).length;
}
function addProgram(lic, appId, hwid) {
  if (!lic.programs) lic.programs = [];
  if (!findProgram(lic, appId, hwid)) {
    lic.programs.push({
      id: genProgramId(),
      appId,
      hwid,
      activatedAt: Date.now(),
      lastSeen: Date.now()
    });
    return true;
  }
  return false;
}
function removeProgram(lic, appId, hwid) {
  if (!lic.programs) return false;
  const before = lic.programs.length;
  lic.programs = lic.programs.filter(p => !(p.appId === appId && p.hwid === hwid));
  return lic.programs.length < before;
}
function removeAllPrograms(lic) {
  lic.programs = [];
}

/* ============================================================
 * SESSIONI & RATE LIMIT
 * ============================================================ */
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

/* ============================================================
 * APP
 * ============================================================ */
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

/* ============================================================
 * PING PUBBLICO
 * ============================================================ */
app.get('/api/ping', (req, res) => {
  res.json({ ok: true, ts: Date.now(), version: '3.0.0' });
});

/* ============================================================
 * LICENSE CHECK — supporta multi-programma
 * Body: { key, hwid, username?, appId? }
 * Se appId manca → default 'voidutility' (retrocompatibile)
 * ============================================================ */
app.post('/api/license/check', (req, res) => {
  const { key, hwid, username, appId } = req.body || {};
  const APP = appId || 'voidutility';

  if (!key) return res.json({ ok: false, msg: 'Chiave mancante' });
  if (!hwid) return res.json({ ok: false, msg: 'HWID mancante' });

  const lic = findLic(key);
  if (!lic) return res.json({ ok: false, msg: 'Chiave non valida' });

  // ✅ REVOCA ISTANTANEA
  if (lic.banned) return res.json({ ok: false, revoked: true, msg: 'Licenza disattivata' });
  if (isExpired(lic)) return res.json({ ok: false, revoked: true, expired: true, msg: 'Licenza scaduta' });

  // Verifica limite programmi
  const existing = findProgram(lic, APP, hwid);
  if (!existing) {
    const used = countPrograms(lic, APP);
    if (used >= lic.maxPrograms) {
      // Se lo slot è pieno ma uno dei programmi registrati è per un altro HWID
      return res.json({
        ok: false,
        revoked: false,
        slotFull: true,
        msg: `Limite raggiunto (${lic.maxPrograms} programmi). Contatta l'assistenza per resettare.`
      });
    }
    addProgram(lic, APP, hwid);
  } else {
    existing.lastSeen = Date.now();
  }

  // --- Registrazione utente ---
  if (!username) {
    if (!lic.username) {
      lic.lastPing = Date.now();
      lic.lastIp = req.ip || '';
      saveDb();
      return res.json({
        ok: true,
        msg: 'OK',
        expires: lic.infinite ? -1 : lic.expiresAt,
        infinite: !!lic.infinite,
        username: null,
        needsSetup: true,
        maxPrograms: lic.maxPrograms,
        usedPrograms: countPrograms(lic, APP)
      });
    }
    // Check HWID: se la licenza ha hwid vecchio diverso e non c'è programma → blocca
    lic.lastPing = Date.now();
    lic.lastIp = req.ip || '';
    saveDb();
    return res.json({
      ok: true,
      msg: 'OK',
      expires: lic.infinite ? -1 : lic.expiresAt,
      infinite: !!lic.infinite,
      username: lic.username,
      maxPrograms: lic.maxPrograms,
      usedPrograms: countPrograms(lic, APP)
    });
  }

  // --- Registrazione con username ---
  if (!lic.username) {
    const taken = db.licenses.find(l =>
      l.username && l.username.toLowerCase() === username.toLowerCase()
    );
    if (taken && taken.key !== key) {
      return res.json({ ok: false, msg: 'Username gia usato' });
    }
    lic.username = username;
    lic.lastPing = Date.now();
    lic.lastIp = req.ip || '';
    saveDb();
    return res.json({
      ok: true,
      msg: 'OK',
      expires: lic.infinite ? -1 : lic.expiresAt,
      infinite: !!lic.infinite,
      username: lic.username,
      maxPrograms: lic.maxPrograms,
      usedPrograms: countPrograms(lic, APP)
    });
  }

  if (lic.username.toLowerCase() !== username.toLowerCase()) {
    return res.json({ ok: false, msg: 'Username non corrisponde' });
  }

  lic.lastPing = Date.now();
  lic.lastIp = req.ip || '';
  saveDb();

  res.json({
    ok: true,
    msg: 'OK',
    expires: lic.infinite ? -1 : lic.expiresAt,
    infinite: !!lic.infinite,
    username: lic.username,
    maxPrograms: lic.maxPrograms,
    usedPrograms: countPrograms(lic, APP)
  });
});

/* ============================================================
 * HEARTBEAT — check ogni 5s dal client
 * Body: { key, hwid, username, appId? }
 * ============================================================ */
app.post('/api/license/heartbeat', (req, res) => {
  const { key, hwid, username, appId } = req.body || {};
  const APP = appId || 'voidutility';

  const lic = findLic(key);
  if (!lic) return res.json({ ok: false, revoked: true, msg: 'Licenza non trovata' });

  // ✅ REVOCA ISTANTANEA — questi campi dicono al client di chiudersi
  if (lic.banned) return res.json({ ok: false, revoked: true, msg: 'Licenza disattivata' });
  if (isExpired(lic)) return res.json({ ok: false, revoked: true, expired: true, msg: 'Licenza scaduta' });

  // Verifica che il programma sia registrato per questo HWID
  const prog = findProgram(lic, APP, hwid);
  if (!prog) {
    return res.json({
      ok: false,
      revoked: true,
      hwid_mismatch: true,
      msg: 'Questo PC non è autorizzato per la licenza'
    });
  }

  if (lic.username && username && lic.username.toLowerCase() !== username.toLowerCase()) {
    return res.json({ ok: false, revoked: true, user: true, msg: 'Username non corrisponde' });
  }

  prog.lastSeen = Date.now();
  lic.lastPing = Date.now();
  lic.lastIp = req.ip || '';
  saveDb();

  res.json({
    ok: true,
    infinite: !!lic.infinite,
    expires: lic.infinite ? -1 : lic.expiresAt
  });
});

/* ============================================================
 * REGISTER (usato dal setup gate al primo avvio)
 * ============================================================ */
app.post('/api/license/register', (req, res) => {
  const { key, hwid, username, appId } = req.body || {};
  const APP = appId || 'voidutility';

  const lic = findLic(key);
  if (!lic) return res.json({ ok: false, msg: 'Chiave non valida' });
  if (lic.banned) return res.json({ ok: false, revoked: true, msg: 'Licenza disattivata' });
  if (isExpired(lic)) return res.json({ ok: false, revoked: true, expired: true, msg: 'Licenza scaduta' });
  if (!username || username.length < 2) return res.json({ ok: false, msg: 'Username corto' });

  if (lic.username && lic.username.toLowerCase() !== username.toLowerCase()) {
    return res.json({ ok: false, msg: 'Licenza gia associata a un altro utente' });
  }

  const taken = db.licenses.find(l =>
    l.username && l.username.toLowerCase() === username.toLowerCase() && l.key !== key
  );
  if (taken) return res.json({ ok: false, msg: 'Username gia in uso' });

  // Verifica limite programmi
  const existing = findProgram(lic, APP, hwid);
  if (!existing && countPrograms(lic, APP) >= lic.maxPrograms) {
    return res.json({
      ok: false,
      slotFull: true,
      msg: `Limite raggiunto (${lic.maxPrograms} programmi)`
    });
  }
  if (!existing) addProgram(lic, APP, hwid);

  lic.username = username;
  lic.lastPing = Date.now();
  lic.lastIp = req.ip || '';
  saveDb();
  addLog('register', `${lic.key} → ${username} [${APP}]`, req.ip);
  res.json({ ok: true });
});

/* ============================================================
 * ADMIN AUTH
 * ============================================================ */
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

/* ============================================================
 * ADMIN LIST
 * ============================================================ */
app.get('/api/admin/list', adminAuth, (req, res) => {
  const now = Date.now();
  const q = (req.query.q || '').toLowerCase().trim();
  const filter = req.query.filter || 'all';
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const perPage = Math.min(200, Math.max(10, parseInt(req.query.perPage, 10) || 50));

  let list = db.licenses.map(l => ({
    key: l.key,
    username: l.username || null,
    hwid: l.hwid || null,
    online: isOnline(l),
    banned: !!l.banned,
    infinite: !!l.infinite,
    maxPrograms: l.maxPrograms || 1,
    programsCount: (l.programs || []).length,
    programs: l.programs || [],
    expiresAt: l.infinite ? Number.MAX_SAFE_INTEGER : l.expiresAt,
    expired: isExpired(l),
    createdAt: l.createdAt,
    lastPingAgo: l.lastPing ? Math.floor((now - l.lastPing) / 1000) : null,
    lastIp: l.lastIp,
    note: l.note || ''
  }));

  if (q) list = list.filter(l =>
    (l.key && l.key.toLowerCase().includes(q)) ||
    (l.username && l.username.toLowerCase().includes(q)) ||
    (l.note && l.note.toLowerCase().includes(q)) ||
    (l.hwid && l.hwid.toLowerCase().includes(q))
  );

  if (filter === 'online') list = list.filter(l => l.online && !l.banned && !l.expired);
  else if (filter === 'offline') list = list.filter(l => !l.online && !l.banned && !l.expired);
  else if (filter === 'expired') list = list.filter(l => l.expired);
  else if (filter === 'banned') list = list.filter(l => l.banned);
  else if (filter === 'infinite') list = list.filter(l => l.infinite);

  list.sort((a, b) => (b.online - a.online) || a.key.localeCompare(b.key));
  const total = list.length;
  const start = (page - 1) * perPage;
  res.json({ ok: true, licenses: list.slice(start, start + perPage), total, page, perPage, serverTime: now });
});

/* ============================================================
 * ADMIN STATS
 * ============================================================ */
app.get('/api/admin/stats', adminAuth, (req, res) => {
  const total = db.licenses.length;
  let online = 0, banned = 0, expired = 0, active = 0, infinite = 0;
  for (const l of db.licenses) {
    const o = isOnline(l), e = isExpired(l);
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

/* ============================================================
 * ADMIN CREATE — con maxPrograms configurabile
 * ============================================================ */
app.post('/api/admin/create', adminAuth, (req, res) => {
  const { days, username, note, infinite, maxPrograms } = req.body || {};
  const d = parseInt(days, 10) || 30;
  const mp = Math.max(1, Math.min(50, parseInt(maxPrograms, 10) || 1));

  if (!infinite && (d < 1 || d > MAX_DAYS)) return res.json({ ok: false, msg: 'Giorni non validi' });
  if (username && db.licenses.find(l => l.username && l.username.toLowerCase() === username.toLowerCase())) {
    return res.json({ ok: false, msg: 'Username gia usato' });
  }

  const lic = {
    key: genKey(),
    username: username || null,
    hwid: null,
    createdAt: Date.now(),
    expiresAt: infinite ? Number.MAX_SAFE_INTEGER : Date.now() + d * 24 * 3600 * 1000,
    infinite: !!infinite,
    banned: false,
    maxPrograms: mp,
    programs: [],
    lastPing: 0,
    lastIp: null,
    note: note || ''
  };
  db.licenses.push(lic);
  saveDb();
  addLog('create', `${lic.key}${username ? ' → ' + username : ''} (${infinite ? '∞' : d + 'gg'}, ${mp} prog)`, req.ip);
  res.json({ ok: true, license: lic });
});

/* ============================================================
 * ADMIN BAN/UNBAN — revoca istantanea
 * ============================================================ */
app.post('/api/admin/ban', adminAuth, (req, res) => {
  const lic = findLic((req.body || {}).key);
  if (!lic) return res.json({ ok: false });
  lic.banned = !!(req.body || {}).banned;
  saveDb();
  addLog(lic.banned ? 'ban' : 'unban', lic.key, req.ip);
  res.json({ ok: true });
});

/* ============================================================
 * ADMIN RESET HWID — rimuove TUTTI i programmi registrati
 * ============================================================ */
app.post('/api/admin/reset', adminAuth, (req, res) => {
  const lic = findLic((req.body || {}).key);
  if (!lic) return res.json({ ok: false });
  removeAllPrograms(lic);
  lic.hwid = null;
  lic.lastPing = 0;
  saveDb();
  addLog('reset-hwid', lic.key, req.ip);
  res.json({ ok: true });
});

app.post('/api/admin/resetUser', adminAuth, (req, res) => {
  const lic = findLic((req.body || {}).key);
  if (!lic) return res.json({ ok: false });
  lic.username = null;
  lic.hwid = null;
  lic.lastPing = 0;
  removeAllPrograms(lic);
  saveDb();
  addLog('reset-user', lic.key, req.ip);
  res.json({ ok: true });
});

/* ============================================================
 * ADMIN — rimuovi singolo programma
 * ============================================================ */
app.post('/api/admin/removeProgram', adminAuth, (req, res) => {
  const { key, programId } = req.body || {};
  const lic = findLic(key);
  if (!lic) return res.json({ ok: false, msg: 'Licenza non trovata' });
  if (!Array.isArray(lic.programs)) lic.programs = [];
  const before = lic.programs.length;
  lic.programs = lic.programs.filter(p => p.id !== programId);
  saveDb();
  if (lic.programs.length < before) {
    addLog('remove-program', `${lic.key} → ${programId}`, req.ip);
    return res.json({ ok: true });
  }
  res.json({ ok: false, msg: 'Programma non trovato' });
});

/* ============================================================
 * ADMIN — setMaxPrograms
 * ============================================================ */
app.post('/api/admin/setMaxPrograms', adminAuth, (req, res) => {
  const { key, maxPrograms } = req.body || {};
  const lic = findLic(key);
  if (!lic) return res.json({ ok: false });
  const mp = Math.max(1, Math.min(50, parseInt(maxPrograms, 10) || 1));
  lic.maxPrograms = mp;
  saveDb();
  addLog('set-max-programs', `${lic.key} → ${mp}`, req.ip);
  res.json({ ok: true, maxPrograms: mp });
});

/* ============================================================
 * ADMIN EXTEND / SET EXPIRY / SET INFINITE
 * ============================================================ */
app.post('/api/admin/extend', adminAuth, (req, res) => {
  const lic = findLic((req.body || {}).key);
  if (!lic) return res.json({ ok: false, msg: 'Licenza non trovata' });
  if (lic.infinite) return res.json({ ok: false, msg: 'Licenza infinita' });
  const d = parseInt((req.body || {}).days, 10);
  if (!d || d < 1 || d > MAX_DAYS) return res.json({ ok: false, msg: 'Giorni non validi' });
  lic.expiresAt = Math.max(lic.expiresAt, Date.now()) + d * 24 * 3600 * 1000;
  saveDb();
  addLog('extend', `${lic.key} +${d}gg`, req.ip);
  res.json({ ok: true, expiresAt: lic.expiresAt });
});

app.post('/api/admin/setExpiry', adminAuth, (req, res) => {
  const lic = findLic((req.body || {}).key);
  if (!lic) return res.json({ ok: false });
  const ts = parseInt((req.body || {}).expiresAt, 10);
  if (!ts || !Number.isFinite(ts)) return res.json({ ok: false, msg: 'Data non valida' });
  lic.expiresAt = ts;
  lic.infinite = false;
  saveDb();
  addLog('set-expiry', `${lic.key} → ${new Date(ts).toISOString().slice(0, 10)}`, req.ip);
  res.json({ ok: true, expiresAt: lic.expiresAt });
});

app.post('/api/admin/setInfinite', adminAuth, (req, res) => {
  const lic = findLic((req.body || {}).key);
  if (!lic) return res.json({ ok: false });
  lic.infinite = true;
  lic.expiresAt = Number.MAX_SAFE_INTEGER;
  saveDb();
  addLog('set-infinite', lic.key, req.ip);
  res.json({ ok: true });
});

/* ============================================================
 * ADMIN DELETE
 * ============================================================ */
app.post('/api/admin/delete', adminAuth, (req, res) => {
  const k = (req.body || {}).key;
  db.licenses = db.licenses.filter(l => l.key !== k);
  saveDb();
  addLog('delete', k, req.ip);
  res.json({ ok: true });
});

/* ============================================================
 * ADMIN RENAME / NOTE
 * ============================================================ */
app.post('/api/admin/rename', adminAuth, (req, res) => {
  const { key, username } = req.body || {};
  const lic = findLic(key);
  if (!lic) return res.json({ ok: false, msg: 'Non trovata' });
  if (!username || username.length < 2) return res.json({ ok: false, msg: 'Username corto' });
  const taken = db.licenses.find(l =>
    l.username && l.username.toLowerCase() === username.toLowerCase() && l.key !== key
  );
  if (taken) return res.json({ ok: false, msg: 'Username gia usato' });
  lic.username = username;
  saveDb();
  addLog('rename', `${lic.key} → ${username}`, req.ip);
  res.json({ ok: true });
});

app.post('/api/admin/note', adminAuth, (req, res) => {
  const { key, note } = req.body || {};
  const lic = findLic(key);
  if (!lic) return res.json({ ok: false });
  lic.note = String(note || '').slice(0, 500);
  saveDb();
  addLog('note', lic.key, req.ip);
  res.json({ ok: true });
});

/* ============================================================
 * ADMIN EXPORT CSV
 * ============================================================ */
app.get('/api/admin/export.csv', adminAuth, (req, res) => {
  const rows = [[
    'key','username','hwid','status','infinite','maxPrograms','programsCount',
    'expiresAt','createdAt','lastPing','lastIp','note'
  ]];
  for (const l of db.licenses) {
    const status = l.banned ? 'banned' : (isExpired(l) ? 'expired' : (isOnline(l) ? 'online' : 'offline'));
    rows.push([
      l.key,
      l.username || '',
      l.hwid || '',
      status,
      l.infinite ? 'yes' : 'no',
      l.maxPrograms || 1,
      (l.programs || []).length,
      l.infinite ? 'NEVER' : new Date(l.expiresAt).toISOString(),
      new Date(l.createdAt).toISOString(),
      l.lastPing ? new Date(l.lastPing).toISOString() : '',
      l.lastIp || '',
      l.note || ''
    ]);
  }
  const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
  res.header('Content-Type', 'text/csv');
  res.header('Content-Disposition', 'attachment; filename="voidlicense-export.csv"');
  res.send(csv);
});

/* ============================================================
 * ADMIN.HTML
 * ============================================================ */
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log('VoidLicense v3.0.0 - Port ' + PORT);
  if (ADMIN_PASSWORD === 'admin123' || ADMIN_PASSWORD === 'void123') {
    console.warn('⚠️  ADMIN_PASSWORD è quella di default! Impostala su Render.');
  }
});
