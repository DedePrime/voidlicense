const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const PORT = 8090;
const ADMIN_PASSWORD = 'admin123';
const ONLINE_TIMEOUT = 30000;
const DB_FILE = path.join(__dirname, 'db.json');
let db = { licenses: [] };
function loadDb() {
  if (fs.existsSync(DB_FILE)) { try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) {} }
  if (!db.licenses) db.licenses = [];
}
function saveDb() { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
function genKey() {
  const p = [];
  for (let i = 0; i < 4; i++) p.push(crypto.randomBytes(2).toString('hex').toUpperCase());
  return 'VOID-' + p.join('-');
}
function findLic(k) { return db.licenses.find(l => l.key === k); }
function isOnline(l) { return l.lastPing && (Date.now() - l.lastPing) < ONLINE_TIMEOUT; }
loadDb();
const app = express();
app.use(express.json({ limit: '512kb' }));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Pass');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.post('/api/license/check', (req, res) => {
  const { key, hwid, username } = req.body || {};
  if (!key) return res.json({ ok: false, msg: 'Chiave mancante' });
  if (!hwid) return res.json({ ok: false, msg: 'HWID mancante' });
  const lic = findLic(key);
  if (!lic) return res.json({ ok: false, msg: 'Chiave non valida' });
  if (lic.banned) return res.json({ ok: false, msg: 'Licenza disattivata' });
  if (lic.expiresAt < Date.now()) return res.json({ ok: false, msg: 'Licenza scaduta' });
  if (!username) {
    if (!lic.username) return res.json({ ok: false, msg: 'Licenza non configurata' });
    if (lic.hwid && lic.hwid !== hwid) return res.json({ ok: false, msg: 'Licenza in uso su un altro PC' });
    lic.lastPing = Date.now(); lic.lastIp = req.ip || ''; saveDb();
    return res.json({ ok: true, msg: 'OK', expires: lic.expiresAt, username: lic.username });
  }
  if (!lic.username) {
    const taken = db.licenses.find(l => l.username && l.username.toLowerCase() === username.toLowerCase());
    if (taken && taken.key !== key) return res.json({ ok: false, msg: 'Username gia usato' });
    lic.username = username; lic.hwid = hwid; lic.lastPing = Date.now(); lic.lastIp = req.ip || ''; saveDb();
    return res.json({ ok: true, msg: 'OK', expires: lic.expiresAt, username: lic.username });
  }
  if (lic.username.toLowerCase() !== username.toLowerCase()) return res.json({ ok: false, msg: 'Username non corrisponde' });
  if (lic.hwid && lic.hwid !== hwid) return res.json({ ok: false, msg: 'Licenza in uso su un altro PC' });
  lic.hwid = hwid; lic.lastPing = Date.now(); lic.lastIp = req.ip || ''; saveDb();
  res.json({ ok: true, msg: 'OK', expires: lic.expiresAt, username: lic.username });
});
app.post('/api/license/heartbeat', (req, res) => {
  const { key, hwid, username } = req.body || {};
  const lic = findLic(key);
  if (!lic) return res.json({ ok: false });
  if (lic.banned) return res.json({ ok: false, banned: true });
  if (lic.expiresAt < Date.now()) return res.json({ ok: false, expired: true });
  if (lic.hwid && lic.hwid !== hwid) return res.json({ ok: false, hwid: true });
  if (lic.username && username && lic.username.toLowerCase() !== username.toLowerCase()) return res.json({ ok: false, user: true });
  lic.lastPing = Date.now(); lic.lastIp = req.ip || ''; saveDb();
  res.json({ ok: true });
});
app.post('/api/license/register', (req, res) => {
  const { key, hwid, username } = req.body || {};
  const lic = findLic(key);
  if (!lic) return res.json({ ok: false, msg: 'Chiave non valida' });
  if (lic.banned) return res.json({ ok: false, msg: 'Licenza disattivata' });
  if (lic.expiresAt < Date.now()) return res.json({ ok: false, msg: 'Licenza scaduta' });
  if (!username || username.length < 2) return res.json({ ok: false, msg: 'Username corto' });
  const taken = db.licenses.find(l => l.username && l.username.toLowerCase() === username.toLowerCase() && l.key !== key);
  if (taken) return res.json({ ok: false, msg: 'Username gia in uso' });
  lic.username = username; lic.hwid = hwid; lic.lastPing = Date.now(); lic.lastIp = req.ip || ''; saveDb();
  res.json({ ok: true });
});
function adminAuth(req, res, next) {
  if (req.headers['x-admin-pass'] !== ADMIN_PASSWORD) return res.status(401).json({ ok: false });
  next();
}
app.post('/api/admin/login', (req, res) => res.json({ ok: (req.body||{}).password === ADMIN_PASSWORD }));
app.get('/api/admin/list', adminAuth, (req, res) => {
  const now = Date.now();
  const list = db.licenses.map(l => ({
    key: l.key, username: l.username || null, hwid: l.hwid,
    online: isOnline(l), banned: !!l.banned,
    expiresAt: l.expiresAt, expired: l.expiresAt < now, createdAt: l.createdAt,
    lastPingAgo: l.lastPing ? Math.floor((now - l.lastPing)/1000) : null,
    lastIp: l.lastIp, note: l.note || ''
  }));
  res.json({ ok: true, licenses: list, serverTime: now });
});
app.post('/api/admin/create', adminAuth, (req, res) => {
  const { days, username, note } = req.body || {};
  const d = parseInt(days, 10) || 30;
  if (!username) return res.json({ ok: false, msg: 'Username obbligatorio' });
  if (db.licenses.find(l => l.username && l.username.toLowerCase() === username.toLowerCase())) return res.json({ ok: false, msg: 'Username gia usato' });
  const lic = { key: genKey(), username, hwid: null, createdAt: Date.now(),
    expiresAt: Date.now() + d*24*3600*1000, banned: false, lastPing: 0, lastIp: null, note: note || '' };
  db.licenses.push(lic); saveDb();
  res.json({ ok: true, license: lic });
});
app.post('/api/admin/ban', adminAuth, (req, res) => {
  const lic = findLic((req.body||{}).key);
  if (!lic) return res.json({ ok: false });
  lic.banned = !!(req.body||{}).banned; saveDb();
  res.json({ ok: true });
});
app.post('/api/admin/reset', adminAuth, (req, res) => {
  const lic = findLic((req.body||{}).key);
  if (!lic) return res.json({ ok: false });
  lic.hwid = null; lic.lastPing = 0; saveDb();
  res.json({ ok: true });
});
app.post('/api/admin/resetUser', adminAuth, (req, res) => {
  const lic = findLic((req.body||{}).key);
  if (!lic) return res.json({ ok: false });
  lic.username = null; lic.hwid = null; lic.lastPing = 0; saveDb();
  res.json({ ok: true });
});
app.post('/api/admin/extend', adminAuth, (req, res) => {
  const lic = findLic((req.body||{}).key);
  if (!lic) return res.json({ ok: false });
  const d = parseInt((req.body||{}).days, 10) || 30;
  lic.expiresAt = Math.max(lic.expiresAt, Date.now()) + d*24*3600*1000; saveDb();
  res.json({ ok: true });
});
app.post('/api/admin/delete', adminAuth, (req, res) => {
  const k = (req.body||{}).key;
  db.licenses = db.licenses.filter(l => l.key !== k); saveDb();
  res.json({ ok: true });
});
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.listen(PORT, '0.0.0.0', () => {
  console.log('============================================');
  console.log('  VoidLicense Server');
  console.log('  Dashboard: http://localhost:' + PORT);
  console.log('  Password: ' + ADMIN_PASSWORD);
  console.log('============================================');
});