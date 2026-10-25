'use strict';
/* Servidor do Controle Ceasa: contas (e-mail + senha) e sincronização em tempo real entre aparelhos.
   Sem dependências: só Node.js (>= 22.13). Dados em SQLite. Serve o app e a API no mesmo endereço. */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
process.removeAllListeners('warning');
process.on('warning', w => { if (w.name !== 'ExperimentalWarning') console.warn(w); });
const { DatabaseSync } = require('node:sqlite');

const VERSION = '1.0.0';
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUBLIC_DIR = path.resolve(process.env.PUBLIC_DIR || path.join(__dirname, 'public'));
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const SIGNUP_OPEN = process.env.SIGNUP_OPEN !== '0';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const MAX_BODY = 1024 * 1024, MAX_DOC = 64 * 1024, MAX_OPS = 200, MAX_DOCS_USER = 300000;
const SESSION_MS = 90 * 864e5, TOMB_MS = 30 * 864e5;
const LOG_QUIET = process.env.LOG_QUIET === '1';
const log = o => { if (!LOG_QUIET) console.log(JSON.stringify(Object.assign({ t: new Date().toISOString() }, o))); };

/* ---------------- banco ---------------- */
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'ceasa.db'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL, rsalt TEXT NOT NULL, rhash TEXT NOT NULL, seq INTEGER NOT NULL DEFAULT 0, gc_seq INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(tok TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created INTEGER NOT NULL, last INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS docs(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, coll TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, v INTEGER NOT NULL DEFAULT 0, seq INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, ts INTEGER NOT NULL, PRIMARY KEY(user_id, coll, id));
CREATE INDEX IF NOT EXISTS docs_seq ON docs(user_id, seq);
CREATE INDEX IF NOT EXISTS docs_coll ON docs(user_id, coll, deleted);`);
const Q = {
  userByEmail: db.prepare('SELECT * FROM users WHERE email=?'),
  userById: db.prepare('SELECT * FROM users WHERE id=?'),
  insUser: db.prepare('INSERT INTO users(email,salt,hash,rsalt,rhash,created) VALUES(?,?,?,?,?,?)'),
  setPass: db.prepare('UPDATE users SET salt=?,hash=?,rsalt=?,rhash=? WHERE id=?'),
  setRec: db.prepare('UPDATE users SET rsalt=?,rhash=? WHERE id=?'),
  insSess: db.prepare('INSERT INTO sessions(tok,user_id,created,last) VALUES(?,?,?,?)'),
  sess: db.prepare('SELECT s.tok,s.last,u.id,u.email,u.seq FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.tok=?'),
  touch: db.prepare('UPDATE sessions SET last=? WHERE tok=?'),
  delSess: db.prepare('DELETE FROM sessions WHERE tok=?'),
  delSessUser: db.prepare('DELETE FROM sessions WHERE user_id=?'),
  getDoc: db.prepare('SELECT data,v,seq,deleted FROM docs WHERE user_id=? AND coll=? AND id=?'),
  putDoc: db.prepare('INSERT INTO docs(user_id,coll,id,data,v,seq,deleted,ts) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(user_id,coll,id) DO UPDATE SET data=excluded.data,v=excluded.v,seq=excluded.seq,deleted=excluded.deleted,ts=excluded.ts'),
  userSeq: db.prepare('SELECT seq FROM users WHERE id=?'),
  setSeq: db.prepare('UPDATE users SET seq=? WHERE id=?'),
  count: db.prepare('SELECT COUNT(*) AS n FROM docs WHERE user_id=? AND deleted=0'),
  changes: db.prepare('SELECT coll,id,data,v,seq,deleted FROM docs WHERE user_id=? AND seq>? ORDER BY seq LIMIT 500'),
  gcUsers: db.prepare('SELECT DISTINCT user_id FROM docs WHERE deleted=1 AND ts<?'),
  gcMax: db.prepare('SELECT MAX(seq) AS m FROM docs WHERE user_id=? AND deleted=1 AND ts<?'),
  gcDel: db.prepare('DELETE FROM docs WHERE user_id=? AND deleted=1 AND ts<?'),
  gcSeq: db.prepare('UPDATE users SET gc_seq=MAX(gc_seq,?) WHERE id=?'),
  oldSess: db.prepare('DELETE FROM sessions WHERE last<?')
};
function gc() {
  const lim = Date.now() - TOMB_MS;
  for (const r of Q.gcUsers.all(lim)) { const m = Q.gcMax.get(r.user_id, lim).m || 0; Q.gcSeq.run(m, r.user_id); Q.gcDel.run(r.user_id, lim); }
  Q.oldSess.run(Date.now() - SESSION_MS);
}

/* ---------------- utilidades ---------------- */
class HttpError extends Error { constructor(status, code, extra) { super(code); this.status = status; this.code = code; this.extra = extra || {}; } }
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (e, k) => e ? rej(e) : res(k)));
const safeEq = (a, b) => { const x = Buffer.from(a, 'hex'), y = Buffer.from(b, 'hex'); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const emailKey = e => String(e == null ? '' : e).trim().toLowerCase();
const validEmail = e => e.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const normRec = s => String(s == null ? '' : s).toUpperCase().replace(/[^A-Z0-9]/g, '');
const newRec = () => { const abc = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let s = ''; const b = crypto.randomBytes(12); for (const x of b) s += abc[x % abc.length]; return s.slice(0, 4) + '-' + s.slice(4, 8) + '-' + s.slice(8, 12); };
const newToken = () => crypto.randomBytes(32).toString('base64url');
const COLL = /^[a-z][a-z0-9_-]{0,39}$/, DOCID = /^[A-Za-z0-9_-]{1,80}$/, FIELD = /^[A-Za-z_][A-Za-z0-9_]{0,39}$/;
const BAD_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
function cleanJson(v, depth) {                                   // recusa chaves perigosas e estruturas fundas demais
  if (depth > 8) throw new HttpError(400, 'invalid_data');
  if (Array.isArray(v)) { if (v.length > 500) throw new HttpError(400, 'invalid_data'); v.forEach(x => cleanJson(x, depth + 1)); return v; }
  if (v && typeof v === 'object') { for (const k of Object.keys(v)) { if (BAD_KEYS.has(k)) throw new HttpError(400, 'invalid_data'); cleanJson(v[k], depth + 1); } }
  return v;
}
const isObj = x => x && typeof x === 'object' && !Array.isArray(x);
function deepMerge(a, b) {
  if (!isObj(a) || !isObj(b)) return b;
  const out = Object.assign({}, a);
  for (const k of Object.keys(b)) { if (BAD_KEYS.has(k)) continue; out[k] = isObj(b[k]) && isObj(a[k]) ? deepMerge(a[k], b[k]) : b[k]; }
  return out;
}

/* ---------------- limites de tentativas ---------------- */
const hits = new Map();
function limit(key, max, ms) {
  const now = Date.now(); let h = hits.get(key);
  if (!h || h.reset < now) { h = { n: 0, reset: now + ms }; hits.set(key, h); }
  h.n++; return h.n <= max;
}
const fails = new Map();
const lockedOut = email => { const f = fails.get(email); return !!(f && f.until > Date.now()); };
function recordFail(email) { const f = fails.get(email) || { n: 0, until: 0 }; f.n++; if (f.n >= 8) { f.until = Date.now() + 15 * 60 * 1000; f.n = 0; } fails.set(email, f); }
setInterval(() => { const now = Date.now(); hits.forEach((h, k) => { if (h.reset < now) hits.delete(k); }); fails.forEach((f, k) => { if (f.until < now && !f.n) fails.delete(k); }); }, 60000).unref();
const clientIp = req => (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '?';

/* ---------------- sessões ---------------- */
function createSession(userId) {
  const tok = newToken(), now = Date.now();
  Q.insSess.run(sha256(tok), userId, now, now); return tok;
}
function authUser(req) {
  const m = /^Bearer ([A-Za-z0-9_-]{20,80})$/.exec(String(req.headers.authorization || ''));
  if (!m) throw new HttpError(401, 'unauthorized');
  const h = sha256(m[1]), s = Q.sess.get(h), now = Date.now();
  if (!s || now - s.last > SESSION_MS) { if (s) Q.delSess.run(h); throw new HttpError(401, 'unauthorized'); }
  if (now - s.last > 3600e3) Q.touch.run(now, h);
  return { id: Number(s.id), email: s.email, tokHash: h };
}

/* ---------------- dados: consulta, escrita, mudanças ---------------- */
const waiters = new Map();
function notify(userId) { const w = waiters.get(userId); if (w) { waiters.delete(userId); w.forEach(f => f()); } }
const rowDoc = r => ({ coll: r.coll, id: r.id, data: JSON.parse(r.data), v: Number(r.v), seq: Number(r.seq), deleted: !!r.deleted });
function runQuery(userId, coll, filters) {
  if (!COLL.test(coll)) throw new HttpError(400, 'invalid_coll');
  if (!Array.isArray(filters) || filters.length > 6) throw new HttpError(400, 'invalid_filters');
  const conds = ['user_id=?', 'coll=?', 'deleted=0'], params = [userId, coll];
  for (const f of filters) {
    if (!Array.isArray(f) || f.length !== 3 || !FIELD.test(f[0]) || !['==', '>=', '<='].includes(f[1])) throw new HttpError(400, 'invalid_filters');
    let val = f[2];
    if (typeof val === 'boolean') val = val ? 1 : 0; else if (typeof val === 'string') { if (val.length > 100) throw new HttpError(400, 'invalid_filters'); } else if (typeof val !== 'number' || !Number.isFinite(val)) throw new HttpError(400, 'invalid_filters');
    conds.push('json_extract(data, ?) ' + (f[1] === '==' ? '=' : f[1]) + ' ?'); params.push('$.' + f[0], val);
  }
  const rows = db.prepare('SELECT id,data,v,seq FROM docs WHERE ' + conds.join(' AND ') + ' ORDER BY id LIMIT 20001').all(...params);
  const trunc = rows.length > 20000; if (trunc) rows.pop();
  return { docs: rows.map(r => ({ id: r.id, data: JSON.parse(r.data), v: Number(r.v), seq: Number(r.seq) })), seq: Number(Q.userSeq.get(userId).seq), truncated: trunc };
}
function runWrite(userId, ops) {
  if (!Array.isArray(ops) || !ops.length || ops.length > MAX_OPS) throw new HttpError(400, 'invalid_ops');
  const out = [];
  db.exec('BEGIN IMMEDIATE');
  try {
    let seq = Number(Q.userSeq.get(userId).seq), n = null;
    ops.forEach((o, i) => {
      if (!o || !['set', 'update', 'delete'].includes(o.op) || !COLL.test(o.coll || '') || !DOCID.test(o.id || '')) throw new HttpError(400, 'invalid_ops', { index: i });
      const row = Q.getDoc.get(userId, o.coll, o.id), live = row && !row.deleted;
      let data;
      if (o.op === 'delete') {
        if (!live) return;
        seq++; Q.putDoc.run(userId, o.coll, o.id, '{}', 0, seq, 1, Date.now()); out.push({ coll: o.coll, id: o.id, data: {}, v: 0, seq, deleted: true }); return;
      }
      if (!isObj(o.data)) throw new HttpError(400, 'invalid_data', { index: i });
      cleanJson(o.data, 0);
      if (o.op === 'update') { if (!live) throw new HttpError(404, 'not_found', { index: i }); data = deepMerge(JSON.parse(row.data), o.data); } else data = o.data;
      const txt = JSON.stringify(data);
      if (Buffer.byteLength(txt) > MAX_DOC) throw new HttpError(413, 'doc_too_large', { index: i });
      if (!live) { if (n === null) n = Number(Q.count.get(userId).n); if (++n > MAX_DOCS_USER) throw new HttpError(413, 'quota', { index: i }); }
      seq++; const v = Number(data.v) || 0;
      Q.putDoc.run(userId, o.coll, o.id, txt, v, seq, 0, Date.now()); out.push({ coll: o.coll, id: o.id, data, v, seq, deleted: false });
    });
    Q.setSeq.run(seq, userId);
    db.exec('COMMIT');
    if (out.length) notify(userId);
    return { seq, docs: out };
  } catch (e) { try { db.exec('ROLLBACK'); } catch (x) {} throw e; }
}
async function longPoll(userId, since, waitSec, req) {
  const u = Q.userById.get(userId);
  if (since < Number(u.gc_seq)) return { reset: true, seq: Number(u.seq), changes: [] };
  const deadline = Date.now() + waitSec * 1000; let closed = false;
  req.on('close', () => { closed = true; });
  for (;;) {
    const rows = Q.changes.all(userId, since);
    if (rows.length) { const ch = rows.map(rowDoc); return { seq: ch[ch.length - 1].seq, changes: ch, more: rows.length === 500 }; }
    const left = deadline - Date.now();
    if (left <= 0 || closed) return { seq: Math.max(since, Number(Q.userSeq.get(userId).seq)), changes: [] };
    await new Promise(res => {
      let set = waiters.get(userId); if (!set) { set = new Set(); waiters.set(userId, set); }
      const t = setTimeout(done, left); function done() { clearTimeout(t); set.delete(done); res(); }
      set.add(done); req.once('close', done);
    });
  }
}

/* ---------------- HTTP ---------------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8' };
let cspCache = { file: '', mtime: 0, value: '' };
function cspFor(file) {                                           // CSP com hash dos scripts/estilos embutidos (sem 'unsafe-inline' em scripts)
  const st = fs.statSync(file);
  if (cspCache.file === file && cspCache.mtime === st.mtimeMs) return cspCache.value;
  const html = fs.readFileSync(file, 'utf8'), hs = { script: [], style: [] };
  for (const kind of ['script', 'style']) { const re = new RegExp('<' + kind + '(?![^>]*\\bsrc=)[^>]*>([\\s\\S]*?)</' + kind + '>', 'g'); let m; while ((m = re.exec(html))) hs[kind].push("'sha256-" + crypto.createHash('sha256').update(m[1]).digest('base64') + "'"); }
  const conn = ["'self'"].concat(ALLOWED_ORIGINS).join(' ');
  const v = ["default-src 'self'", 'script-src \'self\' ' + hs.script.join(' '), 'style-src \'self\' ' + hs.style.join(' '), "style-src-attr 'unsafe-inline'", "img-src 'self' data:", 'connect-src ' + conn, "frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'", "form-action 'self'"].join('; ');
  cspCache = { file, mtime: st.mtimeMs, value: v }; return v;
}
function baseHeaders(req, extra) {
  const h = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()', 'Cross-Origin-Opener-Policy': 'same-origin' };
  if (req.socket.encrypted || String(req.headers['x-forwarded-proto'] || '') === 'https') h['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  const o = req.headers.origin;
  if (o && ALLOWED_ORIGINS.includes(o)) { h['Access-Control-Allow-Origin'] = o; h['Vary'] = 'Origin'; h['Access-Control-Allow-Headers'] = 'authorization, content-type'; h['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'; h['Access-Control-Max-Age'] = '600'; }
  return Object.assign(h, extra || {});
}
function sendJson(req, res, status, obj) { const body = JSON.stringify(obj); res.writeHead(status, baseHeaders(req, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body) })); res.end(body); }
function readJson(req) {
  return new Promise((res, rej) => {
    let n = 0, over = false, done = false; const parts = [];
    const fin = (f, v) => { if (!done) { done = true; f(v); } };
    req.on('data', c => {
      n += c.length;
      if (n > MAX_BODY) { over = true; parts.length = 0; if (n > MAX_BODY * 8) req.destroy(); }   // lê (e descarta) para poder responder 413; corta quem insiste
      else if (!over) parts.push(c);
    });
    req.on('end', () => {
      if (over) return fin(rej, new HttpError(413, 'too_large'));
      if (!parts.length) return fin(res, {});
      try { const j = JSON.parse(Buffer.concat(parts).toString('utf8')); fin(res, j && typeof j === 'object' ? j : {}); } catch (e) { fin(rej, new HttpError(400, 'invalid_json')); }
    });
    req.on('close', () => fin(rej, new HttpError(over ? 413 : 400, over ? 'too_large' : 'invalid_request')));
    req.on('error', () => fin(rej, new HttpError(400, 'invalid_request')));
  });
}
async function api(req, res, url) {
  const p = url.pathname, m = req.method;
  if (p === '/api/health' && m === 'GET') return sendJson(req, res, 200, { ok: true, version: VERSION, time: Date.now() });
  if (p === '/api/auth/signup' && m === 'POST') {
    if (!SIGNUP_OPEN) throw new HttpError(403, 'signup_closed');
    if (!limit('su:' + clientIp(req), 20, 3600e3)) throw new HttpError(429, 'rate_limited');
    const b = await readJson(req), email = emailKey(b.email), pw = String(b.password == null ? '' : b.password);
    if (!validEmail(email)) throw new HttpError(400, 'email_invalid');
    if (pw.length < 6 || pw.length > 200) throw new HttpError(400, 'password_short');
    if (Q.userByEmail.get(email)) throw new HttpError(409, 'email_exists');
    const salt = crypto.randomBytes(16).toString('hex'), rsalt = crypto.randomBytes(16).toString('hex'), rec = newRec();
    const [hash, rhash] = await Promise.all([scrypt(pw, salt), scrypt(normRec(rec), rsalt)]);
    let id; try { id = Number(Q.insUser.run(email, salt, hash.toString('hex'), rsalt, rhash.toString('hex'), Date.now()).lastInsertRowid); } catch (e) { throw new HttpError(409, 'email_exists'); }
    log({ ev: 'signup', user: id });
    return sendJson(req, res, 201, { token: createSession(id), user: { id, email }, recovery: rec });
  }
  if (p === '/api/auth/login' && m === 'POST') {
    if (!limit('li:' + clientIp(req), 60, 600e3)) throw new HttpError(429, 'rate_limited');
    const b = await readJson(req), email = emailKey(b.email), pw = String(b.password == null ? '' : b.password);
    if (lockedOut(email)) throw new HttpError(429, 'rate_limited');
    const u = Q.userByEmail.get(email), derived = await scrypt(pw.slice(0, 200), u ? u.salt : 'x'.repeat(32));
    if (!u || !safeEq(derived.toString('hex'), u.hash)) { recordFail(email); log({ ev: 'login_fail' }); throw new HttpError(401, 'bad_credentials'); }
    fails.delete(email);
    return sendJson(req, res, 200, { token: createSession(Number(u.id)), user: { id: Number(u.id), email: u.email } });
  }
  if (p === '/api/auth/reset' && m === 'POST') {
    if (!limit('rs:' + clientIp(req), 20, 3600e3)) throw new HttpError(429, 'rate_limited');
    const b = await readJson(req), email = emailKey(b.email), pw = String(b.password == null ? '' : b.password);
    if (pw.length < 6 || pw.length > 200) throw new HttpError(400, 'password_short');
    if (lockedOut('rc:' + email)) throw new HttpError(429, 'rate_limited');
    const u = Q.userByEmail.get(email), d = await scrypt(normRec(b.code), u ? u.rsalt : 'x'.repeat(32));
    if (!u || !safeEq(d.toString('hex'), u.rhash)) { recordFail('rc:' + email); throw new HttpError(401, 'bad_recovery'); }
    const salt = crypto.randomBytes(16).toString('hex'), rsalt = crypto.randomBytes(16).toString('hex'), rec = newRec();
    const [hash, rhash] = await Promise.all([scrypt(pw, salt), scrypt(normRec(rec), rsalt)]);
    Q.setPass.run(salt, hash.toString('hex'), rsalt, rhash.toString('hex'), u.id); Q.delSessUser.run(u.id);
    log({ ev: 'reset', user: Number(u.id) });
    return sendJson(req, res, 200, { token: createSession(Number(u.id)), user: { id: Number(u.id), email: u.email }, recovery: rec });
  }
  const au = authUser(req);                                       // daqui para baixo: só com sessão válida
  if (p === '/api/auth/logout' && m === 'POST') { Q.delSess.run(au.tokHash); return sendJson(req, res, 200, { ok: true }); }
  if (p === '/api/auth/me' && m === 'GET') return sendJson(req, res, 200, { user: { id: au.id, email: au.email }, seq: Number(Q.userSeq.get(au.id).seq) });
  if (p === '/api/auth/recovery' && m === 'POST') {
    const b = await readJson(req), u = Q.userById.get(au.id), d = await scrypt(String(b.password == null ? '' : b.password).slice(0, 200), u.salt);
    if (!safeEq(d.toString('hex'), u.hash)) throw new HttpError(403, 'bad_credentials');   // 403 (e não 401) para o app não achar que a sessão caiu
    const rsalt = crypto.randomBytes(16).toString('hex'), rec = newRec(); Q.setRec.run(rsalt, (await scrypt(normRec(rec), rsalt)).toString('hex'), au.id);
    return sendJson(req, res, 200, { recovery: rec });
  }
  if (p === '/api/docs/query' && m === 'POST') { const b = await readJson(req); return sendJson(req, res, 200, runQuery(au.id, String(b.coll || ''), b.filters || [])); }
  if (p === '/api/docs/get' && m === 'POST') {
    const b = await readJson(req); if (!COLL.test(String(b.coll || '')) || !DOCID.test(String(b.id || ''))) throw new HttpError(400, 'invalid_ops');
    const r = Q.getDoc.get(au.id, b.coll, b.id);
    return sendJson(req, res, 200, r && !r.deleted ? { exists: true, doc: { id: b.id, data: JSON.parse(r.data), v: Number(r.v), seq: Number(r.seq) } } : { exists: false });
  }
  if (p === '/api/docs/write' && m === 'POST') { const b = await readJson(req); return sendJson(req, res, 200, runWrite(au.id, b.ops)); }
  if (p === '/api/changes' && m === 'GET') {
    const since = Math.max(0, parseInt(url.searchParams.get('since'), 10) || 0), wait = Math.min(25, Math.max(0, parseInt(url.searchParams.get('wait'), 10) || 0));
    return sendJson(req, res, 200, await longPoll(au.id, since, wait, req));
  }
  throw new HttpError(404, 'not_found_route');
}
function serveStatic(req, res, url) {
  if (url.pathname === '/config.js') { const body = 'window.CEASA_API = "";\n'; res.writeHead(200, baseHeaders(req, { 'Content-Type': MIME['.js'], 'Cache-Control': 'no-cache' })); return res.end(req.method === 'HEAD' ? undefined : body); }
  let rel; try { rel = decodeURIComponent(url.pathname); } catch (e) { rel = ''; }
  if (rel.includes('\0') || rel.split('/').some(s => s.startsWith('.'))) { res.writeHead(404, baseHeaders(req)); return res.end(); }
  if (rel.endsWith('/')) rel += 'index.html';
  const file = path.resolve(PUBLIC_DIR, '.' + path.sep + rel.replace(/^\/+/, ''));
  if (!file.startsWith(PUBLIC_DIR + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404, baseHeaders(req, { 'Content-Type': 'text/plain; charset=utf-8' })); return res.end('Não encontrado'); }
  const ext = path.extname(file).toLowerCase(), isHtml = ext === '.html', st = fs.statSync(file), etag = '"' + st.size.toString(16) + '-' + Math.floor(st.mtimeMs).toString(16) + '"';
  const h = baseHeaders(req, { 'Content-Type': MIME[ext] || 'application/octet-stream', 'ETag': etag, 'Cache-Control': ['.png', '.svg', '.ico'].includes(ext) ? 'public, max-age=86400' : 'no-cache' });
  if (isHtml) h['Content-Security-Policy'] = cspFor(file);
  if (req.headers['if-none-match'] === etag) { res.writeHead(304, h); return res.end(); }
  let body = fs.readFileSync(file);
  if (/\b(gzip)\b/.test(String(req.headers['accept-encoding'] || '')) && ['.html', '.js', '.css', '.json', '.webmanifest', '.svg', '.txt'].includes(ext)) { body = zlib.gzipSync(body); h['Content-Encoding'] = 'gzip'; h['Vary'] = (h['Vary'] ? h['Vary'] + ', ' : '') + 'Accept-Encoding'; }
  h['Content-Length'] = body.length; res.writeHead(200, h); res.end(req.method === 'HEAD' ? undefined : body);
}
const server = http.createServer(async (req, res) => {
  const t0 = Date.now(); let url;
  try {
    url = new URL(req.url, 'http://x');
    if (req.method === 'OPTIONS') { res.writeHead(204, baseHeaders(req)); return res.end(); }
    if (url.pathname.startsWith('/api/')) { if (req.method !== 'GET' && req.method !== 'POST') throw new HttpError(405, 'method_not_allowed'); await api(req, res, url); }
    else if (req.method === 'GET' || req.method === 'HEAD') serveStatic(req, res, url);
    else throw new HttpError(405, 'method_not_allowed');
  } catch (e) {
    if (res.headersSent) return res.destroy();
    if (e instanceof HttpError) sendJson(req, res, e.status, Object.assign({ error: e.code }, e.extra));
    else { log({ ev: 'erro', msg: String(e && e.message) }); sendJson(req, res, 500, { error: 'server_error' }); }
  }
  if (url && url.pathname.startsWith('/api/') && url.pathname !== '/api/changes' && url.pathname !== '/api/health') log({ ev: 'req', m: req.method, p: url.pathname, s: res.statusCode, ms: Date.now() - t0 });
});
server.requestTimeout = 0; server.headersTimeout = 15000; server.keepAliveTimeout = 65000;

/* ---------------- comandos de administração ---------------- */
async function cli(args) {
  const [cmd, a] = args;
  if (cmd === 'backup') { const f = path.resolve(a || path.join(DATA_DIR, 'backup-' + new Date().toISOString().slice(0, 10) + '.db')); db.exec("VACUUM INTO '" + f.replace(/'/g, "''") + "'"); console.log('Cópia criada em ' + f); return true; }
  if (cmd === 'reset-password') {
    const u = Q.userByEmail.get(emailKey(a)); if (!u) { console.error('Conta não encontrada'); process.exitCode = 1; return true; }
    const pw = crypto.randomBytes(9).toString('base64url'), salt = crypto.randomBytes(16).toString('hex'), rsalt = crypto.randomBytes(16).toString('hex'), rec = newRec();
    Q.setPass.run(salt, (await scrypt(pw, salt)).toString('hex'), rsalt, (await scrypt(normRec(rec), rsalt)).toString('hex'), u.id); Q.delSessUser.run(u.id);
    console.log('Senha temporária: ' + pw + '\nNovo código de recuperação: ' + rec); return true;
  }
  if (cmd === 'stats') { console.log(JSON.stringify({ contas: Number(db.prepare('SELECT COUNT(*) n FROM users').get().n), registros: Number(db.prepare('SELECT COUNT(*) n FROM docs WHERE deleted=0').get().n) })); return true; }
  if (cmd === 'export') {
    const u = Q.userByEmail.get(emailKey(a)); if (!u) { console.error('Conta não encontrada'); process.exitCode = 1; return true; }
    console.log(JSON.stringify({ app: 'controle-ceasa', v: 1, conta: u.email, docs: db.prepare('SELECT coll,id,data FROM docs WHERE user_id=? AND deleted=0').all(u.id).map(r => ({ coll: r.coll, id: r.id, data: JSON.parse(r.data) })) })); return true;
  }
  return false;
}
if (require.main === module) {
  cli(process.argv.slice(2)).then(handled => {
    if (handled) { db.close(); return; }
    gc(); setInterval(gc, 6 * 3600e3).unref();
    server.listen(PORT, HOST, () => log({ ev: 'ligado', porta: PORT, versao: VERSION, dados: DATA_DIR, publico: PUBLIC_DIR }));
    const stop = () => { log({ ev: 'desligando' }); server.close(() => { try { db.close(); } catch (e) {} process.exit(0); }); setTimeout(() => process.exit(0), 5000).unref(); };
    process.on('SIGTERM', stop); process.on('SIGINT', stop);
  });
}
module.exports = { server, db };
