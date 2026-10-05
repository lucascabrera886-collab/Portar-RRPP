'use strict';
// Portal de RRPP · sin dependencias (Node 22+). Base de datos: SQLite integrada.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'portal.db');
const PUBLIC_DIR = path.join(__dirname, 'public');
const SESSION_DAYS = 14;

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','rrpp','recepcion')),
  pass TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, date TEXT, show_rate REAL NOT NULL DEFAULT 0.65,
  capacity INTEGER, lists_open INTEGER NOT NULL DEFAULT 1, is_current INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS guests (
  id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  rrpp_id INTEGER REFERENCES users(id), name TEXT NOT NULL, name_key TEXT NOT NULL, dni TEXT, note TEXT,
  qty INTEGER NOT NULL DEFAULT 1, checked_at INTEGER, checked_qty INTEGER, checked_by INTEGER REFERENCES users(id),
  walkin INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_guests_event ON guests(event_id, rrpp_id);
`);

// ---------- utilidades ----------
const now = () => Date.now();
const json = (res, code, data, headers = {}) => {
  const body = JSON.stringify(data);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(body);
};
const fail = (code, msg) => Object.assign(new Error(msg), { code });
const normName = s => String(s).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/\s+/g, ' ').trim();
const clean = (s, max) => String(s ?? '').replace(/[\u0000-\u001f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
const cleanDni = s => String(s ?? '').replace(/[^0-9a-zA-Z]/g, '').slice(0, 20);

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(pw, salt, 32);
  return `scrypt$${salt.toString('hex')}$${h.toString('hex')}`;
}
function checkPassword(pw, stored) {
  const [, saltHex, hashHex] = String(stored).split('$');
  if (!saltHex || !hashHex) return false;
  const h = crypto.scryptSync(pw, Buffer.from(saltHex, 'hex'), 32);
  return crypto.timingSafeEqual(h, Buffer.from(hashHex, 'hex'));
}
const sha = t => crypto.createHash('sha256').update(t).digest('hex');

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > 1_000_000) { reject(fail(413, 'Pedido demasiado grande')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(fail(400, 'JSON inválido')); }
    });
    req.on('error', reject);
  });
}

// ---------- sesiones ----------
function userFromReq(req) {
  const tok = parseCookies(req).sid;
  if (!tok) return null;
  const row = db.prepare(`SELECT u.id, u.username, u.name, u.role, u.active, s.expires FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`).get(sha(tok));
  if (!row || row.expires < now() || !row.active) return null;
  return { id: row.id, username: row.username, name: row.name, role: row.role };
}
function startSession(req, res, userId) {
  const tok = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id, expires) VALUES (?,?,?)').run(sha(tok), userId, now() + SESSION_DAYS * 864e5);
  const secure = process.env.COOKIE_SECURE === '1' || req.headers['x-forwarded-proto'] === 'https';
  return `sid=${tok}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}${secure ? '; Secure' : ''}`;
}
db.prepare('DELETE FROM sessions WHERE expires < ?').run(now());

const attempts = new Map();
function throttle(key) {
  const t = now(); const a = (attempts.get(key) || []).filter(x => t - x < 10 * 60e3);
  if (a.length >= 8) throw fail(429, 'Demasiados intentos. Probá de nuevo en unos minutos.');
  a.push(t); attempts.set(key, a);
}

// ---------- reglas de negocio ----------
function currentEvent() {
  return db.prepare('SELECT * FROM events WHERE is_current = 1 ORDER BY id DESC LIMIT 1').get()
    || db.prepare('SELECT * FROM events ORDER BY id DESC LIMIT 1').get();
}
function eventFromQuery(q) {
  const id = Number(q.get('event'));
  const ev = id ? db.prepare('SELECT * FROM events WHERE id = ?').get(id) : currentEvent();
  if (!ev) throw fail(404, 'No hay eventos cargados');
  return ev;
}
const need = (user, ...roles) => { if (!user) throw fail(401, 'Iniciá sesión'); if (!roles.includes(user.role)) throw fail(403, 'No tenés permiso para esto'); };

function parseLines(text) {
  const rows = [];
  for (const raw of String(text || '').split(/\r?\n/).slice(0, 500)) {
    const line = raw.trim(); if (!line) continue;
    const parts = line.split(/[,;\t]/).map(s => s.trim()).filter(Boolean);
    let name = parts.shift() || ''; let qty = 1; let dni = ''; const notes = [];
    const plus = name.match(/^(.*?)\s*\+\s*(\d{1,2})$/);
    if (plus) { name = plus[1]; qty = 1 + Number(plus[2]); }
    for (const p of parts) {
      if (/^x?\d{1,2}$/i.test(p)) qty = Number(p.replace(/x/i, '')) || 1;
      else if (/^\d{6,9}$/.test(p.replace(/\./g, ''))) dni = p.replace(/\./g, '');
      else notes.push(p);
    }
    name = clean(name, 80);
    if (name.length < 2) continue;
    rows.push({ name, dni: cleanDni(dni), note: clean(notes.join(' · '), 120), qty: Math.min(Math.max(qty, 1), 30) });
  }
  return rows;
}

function summary(ev) {
  const per = db.prepare(`SELECT u.id, u.name, COALESCE(SUM(g.qty),0) AS lista, COALESCE(SUM(CASE WHEN g.checked_at IS NOT NULL THEN g.checked_qty END),0) AS ingresaron
    FROM users u LEFT JOIN guests g ON g.rrpp_id = u.id AND g.event_id = ? WHERE u.role = 'rrpp' AND (u.active = 1 OR g.id IS NOT NULL) GROUP BY u.id ORDER BY lista DESC, u.name`).all(ev.id);
  const hist = new Map(db.prepare(`SELECT rrpp_id, SUM(qty) l, COALESCE(SUM(CASE WHEN checked_at IS NOT NULL THEN checked_qty END),0) c FROM guests WHERE event_id != ? AND rrpp_id IS NOT NULL GROUP BY rrpp_id`).all(ev.id).map(r => [r.rrpp_id, r]));
  const puerta = db.prepare(`SELECT COALESCE(SUM(checked_qty),0) n FROM guests WHERE event_id = ? AND rrpp_id IS NULL AND checked_at IS NOT NULL`).get(ev.id).n;
  let lista = 0, esperados = 0, ingresaron = 0;
  const rrpps = per.map(r => {
    const h = hist.get(r.id);
    const useHist = h && h.l >= 20;
    const rate = useHist ? Math.min(1, Math.max(0.05, h.c / h.l)) : ev.show_rate;
    const esp = Math.max(r.ingresaron, Math.round(r.lista * rate));
    lista += r.lista; esperados += esp; ingresaron += r.ingresaron;
    return { id: r.id, name: r.name, lista: r.lista, esperados: esp, ingresaron: r.ingresaron, rate, base: useHist ? 'historial' : 'general' };
  });
  const sinNombre = db.prepare(`SELECT COALESCE(SUM(qty),0) n FROM guests WHERE event_id = ? AND rrpp_id IS NULL AND walkin = 0`).get(ev.id).n;
  lista += sinNombre; esperados += sinNombre;
  const total = ingresaron + puerta;
  const totalEsperado = esperados + puerta;
  return {
    event: { id: ev.id, name: ev.name, date: ev.date, show_rate: ev.show_rate, capacity: ev.capacity, lists_open: !!ev.lists_open },
    totals: { lista, esperados: totalEsperado, ingresaron: total, puerta, faltan: Math.max(0, totalEsperado - total), capacidad: ev.capacity },
    rrpps, at: now()
  };
}

function guestRow(g, dupMap, role) {
  const out = { id: g.id, event_id: g.event_id, rrpp_id: g.rrpp_id, rrpp_name: g.rrpp_name || null, name: g.name, dni: g.dni, note: g.note, qty: g.qty,
    checked_at: g.checked_at, checked_qty: g.checked_qty, walkin: !!g.walkin, created_at: g.created_at };
  if (role !== 'rrpp') {
    const keyN = 'n:' + g.name_key; const keyD = g.dni ? 'd:' + g.dni : null;
    out.dup = (dupMap.get(keyN) || 0) > 1 || (keyD && (dupMap.get(keyD) || 0) > 1) || false;
  }
  return out;
}

function listGuests(ev, user) {
  let rows;
  if (user.role === 'rrpp') rows = db.prepare(`SELECT g.*, NULL AS rrpp_name FROM guests g WHERE g.event_id = ? AND g.rrpp_id = ? ORDER BY g.id DESC`).all(ev.id, user.id);
  else rows = db.prepare(`SELECT g.*, u.name AS rrpp_name FROM guests g LEFT JOIN users u ON u.id = g.rrpp_id WHERE g.event_id = ? ORDER BY g.id DESC`).all(ev.id);
  const dup = new Map();
  if (user.role !== 'rrpp') for (const g of rows) { const a = 'n:' + g.name_key; dup.set(a, (dup.get(a) || 0) + 1); if (g.dni) { const b = 'd:' + g.dni; dup.set(b, (dup.get(b) || 0) + 1); } }
  return rows.map(g => guestRow(g, dup, user.role));
}
function guestsVersion(ev, user) {
  const r = user.role === 'rrpp'
    ? db.prepare('SELECT COUNT(*) c, COALESCE(MAX(updated_at),0) m, COALESCE(SUM(qty),0) q FROM guests WHERE event_id = ? AND rrpp_id = ?').get(ev.id, user.id)
    : db.prepare('SELECT COUNT(*) c, COALESCE(MAX(updated_at),0) m, COALESCE(SUM(qty),0) q FROM guests WHERE event_id = ?').get(ev.id);
  return `"${user.role}-${ev.id}-${r.c}-${r.m}-${r.q}"`;
}

// ---------- rutas ----------
const routes = [];
const route = (method, pattern, handler) => routes.push({ method, re: new RegExp('^' + pattern.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), handler });

route('POST', '/api/login', async ({ req, res, body }) => {
  const username = clean(body.username, 40).toLowerCase(); const password = String(body.password || '');
  throttle(`${req.socket.remoteAddress}|${username}`);
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!u || !u.active || !checkPassword(password, u.pass)) throw fail(401, 'Usuario o contraseña incorrectos');
  attempts.delete(`${req.socket.remoteAddress}|${username}`);
  const cookie = startSession(req, res, u.id);
  json(res, 200, { id: u.id, username: u.username, name: u.name, role: u.role }, { 'Set-Cookie': cookie });
});
route('POST', '/api/logout', async ({ req, res }) => {
  const tok = parseCookies(req).sid; if (tok) db.prepare('DELETE FROM sessions WHERE token = ?').run(sha(tok));
  json(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' });
});
route('GET', '/api/me', async ({ res, user }) => { need(user, 'admin', 'rrpp', 'recepcion'); json(res, 200, user); });
route('POST', '/api/me/password', async ({ res, user, body }) => {
  need(user, 'admin', 'rrpp', 'recepcion');
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
  if (!checkPassword(String(body.current || ''), u.pass)) throw fail(400, 'La contraseña actual no es correcta');
  const next = String(body.next || ''); if (next.length < 8) throw fail(400, 'La nueva contraseña debe tener al menos 8 caracteres');
  db.prepare('UPDATE users SET pass = ? WHERE id = ?').run(hashPassword(next), user.id);
  json(res, 200, { ok: true });
});

// usuarios (admin)
route('GET', '/api/users', async ({ res, user }) => { need(user, 'admin'); json(res, 200, db.prepare('SELECT id, username, name, role, active FROM users ORDER BY role, name').all()); });
route('POST', '/api/users', async ({ res, user, body }) => {
  need(user, 'admin');
  const username = clean(body.username, 40).toLowerCase().replace(/[^a-z0-9._-]/g, ''); const name = clean(body.name, 60);
  const role = body.role; const pw = String(body.password || '');
  if (username.length < 3) throw fail(400, 'El usuario necesita al menos 3 letras o números (sin espacios)');
  if (!name) throw fail(400, 'Falta el nombre');
  if (!['admin', 'rrpp', 'recepcion'].includes(role)) throw fail(400, 'Rol inválido');
  if (pw.length < 8) throw fail(400, 'La contraseña debe tener al menos 8 caracteres');
  if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) throw fail(409, 'Ese usuario ya existe');
  const r = db.prepare('INSERT INTO users (username, name, role, pass, active, created_at) VALUES (?,?,?,?,1,?)').run(username, name, role, hashPassword(pw), now());
  json(res, 201, { id: Number(r.lastInsertRowid), username, name, role, active: 1 });
});
route('PATCH', '/api/users/:id', async ({ res, user, body, params }) => {
  need(user, 'admin');
  const id = Number(params.id); const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!u) throw fail(404, 'Usuario no encontrado');
  if (body.name !== undefined) db.prepare('UPDATE users SET name = ? WHERE id = ?').run(clean(body.name, 60) || u.name, id);
  if (body.role !== undefined) {
    if (!['admin', 'rrpp', 'recepcion'].includes(body.role)) throw fail(400, 'Rol inválido');
    if (id === user.id && body.role !== 'admin') throw fail(400, 'No podés sacarte el rol de admin a vos mismo');
    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(body.role, id);
  }
  if (body.active !== undefined) {
    if (id === user.id && !body.active) throw fail(400, 'No podés desactivarte a vos mismo');
    db.prepare('UPDATE users SET active = ? WHERE id = ?').run(body.active ? 1 : 0, id);
    if (!body.active) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
  }
  if (body.password) {
    if (String(body.password).length < 8) throw fail(400, 'La contraseña debe tener al menos 8 caracteres');
    db.prepare('UPDATE users SET pass = ? WHERE id = ?').run(hashPassword(String(body.password)), id);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
  }
  json(res, 200, db.prepare('SELECT id, username, name, role, active FROM users WHERE id = ?').get(id));
});

// eventos
route('GET', '/api/events', async ({ res, user }) => {
  need(user, 'admin', 'rrpp', 'recepcion');
  json(res, 200, db.prepare('SELECT id, name, date, show_rate, capacity, lists_open, is_current FROM events ORDER BY id DESC').all());
});
route('POST', '/api/events', async ({ res, user, body }) => {
  need(user, 'admin');
  const name = clean(body.name, 80); if (!name) throw fail(400, 'Falta el nombre del evento');
  const rate = Math.min(1, Math.max(0.05, Number(body.show_rate ?? 0.65) || 0.65));
  const cap = body.capacity ? Math.max(1, Number(body.capacity) | 0) : null;
  db.exec('UPDATE events SET is_current = 0');
  const r = db.prepare('INSERT INTO events (name, date, show_rate, capacity, lists_open, is_current, created_at) VALUES (?,?,?,?,1,1,?)').run(name, clean(body.date, 30), rate, cap, now());
  json(res, 201, { id: Number(r.lastInsertRowid) });
});
route('PATCH', '/api/events/:id', async ({ res, user, body, params }) => {
  need(user, 'admin');
  const id = Number(params.id); const ev = db.prepare('SELECT * FROM events WHERE id = ?').get(id);
  if (!ev) throw fail(404, 'Evento no encontrado');
  const name = body.name !== undefined ? (clean(body.name, 80) || ev.name) : ev.name;
  const date = body.date !== undefined ? clean(body.date, 30) : ev.date;
  const rate = body.show_rate !== undefined ? Math.min(1, Math.max(0.05, Number(body.show_rate) || ev.show_rate)) : ev.show_rate;
  const cap = body.capacity !== undefined ? (body.capacity ? Math.max(1, Number(body.capacity) | 0) : null) : ev.capacity;
  const open = body.lists_open !== undefined ? (body.lists_open ? 1 : 0) : ev.lists_open;
  if (body.is_current) db.exec('UPDATE events SET is_current = 0');
  const cur = body.is_current !== undefined ? (body.is_current ? 1 : 0) : ev.is_current;
  db.prepare('UPDATE events SET name=?, date=?, show_rate=?, capacity=?, lists_open=?, is_current=? WHERE id=?').run(name, date, rate, cap, open, cur, id);
  json(res, 200, { ok: true });
});

// resumen unificado (todos los roles)
route('GET', '/api/summary', async ({ res, user, url }) => { need(user, 'admin', 'rrpp', 'recepcion'); json(res, 200, summary(eventFromQuery(url.searchParams))); });

// invitados
route('GET', '/api/guests', async ({ req, res, user, url }) => {
  need(user, 'admin', 'rrpp', 'recepcion');
  const ev = eventFromQuery(url.searchParams); const etag = guestsVersion(ev, user);
  if (req.headers['if-none-match'] === etag) { res.writeHead(304, { ETag: etag, 'Cache-Control': 'no-cache' }); return res.end(); }
  json(res, 200, { event_id: ev.id, guests: listGuests(ev, user) }, { ETag: etag, 'Cache-Control': 'no-cache' });
});
route('POST', '/api/guests', async ({ res, user, body }) => {
  need(user, 'admin', 'rrpp');
  const ev = db.prepare('SELECT * FROM events WHERE id = ?').get(Number(body.event)); if (!ev) throw fail(404, 'Evento no encontrado');
  if (user.role === 'rrpp' && !ev.lists_open) throw fail(403, 'La carga de listas está cerrada para este evento');
  let rows = body.text !== undefined ? parseLines(body.text) : [{ name: clean(body.name, 80), dni: cleanDni(body.dni), note: clean(body.note, 120), qty: Math.min(Math.max(Number(body.qty) || 1, 1), 30) }];
  rows = rows.filter(r => r.name.length >= 2);
  if (!rows.length) throw fail(400, 'No encontré ningún nombre para cargar');
  let rrppId = user.id;
  if (user.role === 'admin') {
    rrppId = Number(body.rrpp_id) || null;
    if (rrppId && !db.prepare("SELECT 1 FROM users WHERE id = ? AND role = 'rrpp'").get(rrppId)) throw fail(400, 'El RRPP elegido no existe');
    if (!rrppId) throw fail(400, 'Elegí a qué RRPP corresponde la lista');
  }
  const t = now(); const ins = db.prepare('INSERT INTO guests (event_id, rrpp_id, name, name_key, dni, note, qty, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)');
  db.exec('BEGIN');
  try { for (const r of rows) ins.run(ev.id, rrppId, r.name, normName(r.name), r.dni || null, r.note || null, r.qty, t, t); db.exec('COMMIT'); } catch (e) { db.exec('ROLLBACK'); throw e; }
  json(res, 201, { created: rows.length, personas: rows.reduce((a, r) => a + r.qty, 0) });
});
function loadGuest(id) { const g = db.prepare('SELECT * FROM guests WHERE id = ?').get(Number(id)); if (!g) throw fail(404, 'Invitado no encontrado'); return g; }
route('PATCH', '/api/guests/:id', async ({ res, user, body, params }) => {
  need(user, 'admin', 'rrpp', 'recepcion');
  const g = loadGuest(params.id); const ev = db.prepare('SELECT * FROM events WHERE id = ?').get(g.event_id);
  if (user.role === 'rrpp') {
    if (g.rrpp_id !== user.id) throw fail(403, 'Ese invitado no es de tu lista');
    if (g.checked_at) throw fail(409, 'Ya ingresó: no se puede modificar');
    if (!ev.lists_open) throw fail(403, 'La carga de listas está cerrada');
  }
  const name = body.name !== undefined ? clean(body.name, 80) : g.name; if (name.length < 2) throw fail(400, 'Falta el nombre');
  const dni = body.dni !== undefined ? cleanDni(body.dni) : g.dni;
  const note = body.note !== undefined ? clean(body.note, 120) : g.note;
  let qty = g.qty; if (body.qty !== undefined && user.role !== 'recepcion') qty = Math.min(Math.max(Number(body.qty) || 1, 1), 30);
  let rrppId = g.rrpp_id;
  if (user.role === 'admin' && body.rrpp_id !== undefined) {
    rrppId = body.rrpp_id ? Number(body.rrpp_id) : null;
    if (rrppId && !db.prepare("SELECT 1 FROM users WHERE id = ? AND role = 'rrpp'").get(rrppId)) throw fail(400, 'El RRPP elegido no existe');
  }
  db.prepare('UPDATE guests SET name=?, name_key=?, dni=?, note=?, qty=?, rrpp_id=?, updated_at=? WHERE id=?').run(name, normName(name), dni || null, note || null, qty, rrppId, now(), g.id);
  json(res, 200, { ok: true });
});
route('DELETE', '/api/guests/:id', async ({ res, user, params }) => {
  need(user, 'admin', 'rrpp');
  const g = loadGuest(params.id); const ev = db.prepare('SELECT * FROM events WHERE id = ?').get(g.event_id);
  if (user.role === 'rrpp') {
    if (g.rrpp_id !== user.id) throw fail(403, 'Ese invitado no es de tu lista');
    if (g.checked_at) throw fail(409, 'Ya ingresó: no se puede borrar');
    if (!ev.lists_open) throw fail(403, 'La carga de listas está cerrada');
  }
  db.prepare('DELETE FROM guests WHERE id = ?').run(g.id);
  json(res, 200, { ok: true });
});
route('POST', '/api/guests/:id/checkin', async ({ res, user, body, params }) => {
  need(user, 'admin', 'recepcion');
  const g = loadGuest(params.id);
  const qty = Math.min(Math.max(Number(body.qty ?? g.qty) | 0, 1), 60);
  db.prepare('UPDATE guests SET checked_at = ?, checked_qty = ?, checked_by = ?, updated_at = ? WHERE id = ?').run(now(), qty, user.id, now(), g.id);
  json(res, 200, { ok: true, checked_qty: qty });
});
route('POST', '/api/guests/:id/undo', async ({ res, user, params }) => {
  need(user, 'admin', 'recepcion');
  const g = loadGuest(params.id);
  if (g.walkin) db.prepare('DELETE FROM guests WHERE id = ?').run(g.id);
  else db.prepare('UPDATE guests SET checked_at = NULL, checked_qty = NULL, checked_by = NULL, updated_at = ? WHERE id = ?').run(now(), g.id);
  json(res, 200, { ok: true });
});
route('POST', '/api/walkins', async ({ res, user, body }) => {
  need(user, 'admin', 'recepcion');
  const ev = db.prepare('SELECT * FROM events WHERE id = ?').get(Number(body.event)); if (!ev) throw fail(404, 'Evento no encontrado');
  const name = clean(body.name, 80) || 'Sin nombre'; const qty = Math.min(Math.max(Number(body.qty) || 1, 1), 60); const t = now();
  db.prepare('INSERT INTO guests (event_id, rrpp_id, name, name_key, dni, note, qty, checked_at, checked_qty, checked_by, walkin, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?)')
    .run(ev.id, null, name, normName(name), cleanDni(body.dni) || null, clean(body.note, 120) || null, qty, t, qty, user.id, t, t);
  json(res, 201, { ok: true });
});

route('GET', '/api/export', async ({ res, user, url }) => {
  need(user, 'admin');
  const ev = eventFromQuery(url.searchParams);
  const rows = db.prepare(`SELECT g.name, g.dni, g.qty, COALESCE(u.name,'Puerta') AS rrpp, g.note, g.checked_qty, g.checked_at FROM guests g LEFT JOIN users u ON u.id = g.rrpp_id WHERE g.event_id = ? ORDER BY rrpp, g.name`).all(ev.id);
  const esc = v => { let s = String(v ?? ''); if (/^[=+\-@]/.test(s)) s = "'" + s; return /[",\n;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  const lines = ['Nombre,DNI,Personas,RRPP,Nota,Ingresaron,Hora de ingreso'];
  for (const r of rows) lines.push([r.name, r.dni, r.qty, r.rrpp, r.note, r.checked_at ? r.checked_qty : 0, r.checked_at ? new Date(r.checked_at).toISOString() : ''].map(esc).join(','));
  const fname = `lista-${ev.name.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}.csv`;
  res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="${fname}"`, 'Cache-Control': 'no-store' });
  res.end('﻿' + lines.join('\r\n'));
});

// ---------- servidor ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json' };
const SEC = {
  'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
};

const server = http.createServer(async (req, res) => {
  for (const [k, v] of Object.entries(SEC)) res.setHeader(k, v);
  const url = new URL(req.url, 'http://x');
  try {
    if (url.pathname.startsWith('/api/')) {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        const origin = req.headers.origin;
        if (origin && new URL(origin).host !== req.headers.host) throw fail(403, 'Origen no permitido');
      }
      const r = routes.find(x => x.method === req.method && x.re.test(url.pathname));
      if (!r) throw fail(404, 'No existe');
      const params = url.pathname.match(r.re).groups || {};
      const body = ['POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method) ? await readBody(req) : {};
      return await r.handler({ req, res, url, params, body, user: userFromReq(req) });
    }
    // estáticos
    let rel = url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname);
    const file = path.normalize(path.join(PUBLIC_DIR, rel));
    if (!file.startsWith(PUBLIC_DIR) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); return res.end('No encontrado'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    fs.createReadStream(file).pipe(res);
  } catch (e) {
    if (!e.code || typeof e.code !== 'number') { console.error(e); return json(res, 500, { error: 'Error interno' }); }
    json(res, e.code, { error: e.message });
  }
});

// ---------- primer arranque ----------
if (!db.prepare('SELECT 1 FROM users').get()) {
  const username = (process.env.ADMIN_USER || 'admin').toLowerCase();
  const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(6).toString('base64url');
  db.prepare('INSERT INTO users (username, name, role, pass, active, created_at) VALUES (?,?,?,?,1,?)').run(username, 'Administrador', 'admin', hashPassword(pw), now());
  console.log('\n  Se creó el usuario admin.');
  console.log(`  Usuario:    ${username}`);
  console.log(process.env.ADMIN_PASSWORD ? '  Contraseña: la definida en ADMIN_PASSWORD' : `  Contraseña: ${pw}   (cambiala al entrar)`);
}
if (!db.prepare('SELECT 1 FROM events').get()) {
  db.prepare('INSERT INTO events (name, date, show_rate, capacity, lists_open, is_current, created_at) VALUES (?,?,?,?,1,1,?)').run('Halloween 31/10', '2026-10-31', 0.65, null, now());
}
server.listen(PORT, () => console.log(`\n  Portal RRPP en http://localhost:${PORT}\n`));
module.exports = { server, db };
