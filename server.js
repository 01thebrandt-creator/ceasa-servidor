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
const { execFile } = require('node:child_process');

const VERSION = '1.1.0';
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
const ADMIN_HASHES_FIXED = [];   // sha256('ceasa-admin|' + e-mail) do administrador: o e-mail não fica exposto no código
const VIP_HASHES_FIXED = [];     // sha256('ceasa-vip|' + e-mail): acesso vitalício gratuito (ex.: amigos da família), sem expor o e-mail
const log = o => { if (!LOG_QUIET) console.log(JSON.stringify(Object.assign({ t: new Date().toISOString() }, o))); };

/* ---------------- banco ---------------- */
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'ceasa.db'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL, rsalt TEXT NOT NULL, rhash TEXT NOT NULL, seq INTEGER NOT NULL DEFAULT 0, gc_seq INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(tok TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created INTEGER NOT NULL, last INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS docs(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, coll TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, v INTEGER NOT NULL DEFAULT 0, seq INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, ts INTEGER NOT NULL, PRIMARY KEY(user_id, coll, id));
CREATE INDEX IF NOT EXISTS docs_seq ON docs(user_id, seq);
CREATE INDEX IF NOT EXISTS docs_coll ON docs(user_id, coll, deleted);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS payments(id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, provider TEXT NOT NULL, ext_id TEXT, status TEXT NOT NULL, amount INTEGER NOT NULL, days INTEGER NOT NULL, created INTEGER NOT NULL, checked INTEGER NOT NULL DEFAULT 0, done INTEGER NOT NULL DEFAULT 0, info TEXT);
CREATE INDEX IF NOT EXISTS payments_user ON payments(user_id, created);
CREATE UNIQUE INDEX IF NOT EXISTS payments_ext ON payments(provider, ext_id) WHERE ext_id IS NOT NULL;`);
/* colunas de assinatura (contas antigas ganham o teste grátis a partir de agora) */
const TRIAL_HOURS = Number(process.env.TRIAL_HOURS || 24);
for (const [col, def] of [['trial_until', 'INTEGER NOT NULL DEFAULT 0'], ['paid_until', 'INTEGER NOT NULL DEFAULT 0'], ['lifetime', 'INTEGER NOT NULL DEFAULT 0']]) {
  let added = false; try { db.exec('ALTER TABLE users ADD COLUMN ' + col + ' ' + def); added = true; } catch (e) { /* já existe */ }
  if (added && col === 'trial_until') db.prepare('UPDATE users SET trial_until=?').run(Date.now() + TRIAL_HOURS * 3600e3);
}
const Q = {
  userByEmail: db.prepare('SELECT * FROM users WHERE email=?'),
  userById: db.prepare('SELECT * FROM users WHERE id=?'),
  insUser: db.prepare('INSERT INTO users(email,salt,hash,rsalt,rhash,created,trial_until) VALUES(?,?,?,?,?,?,?)'),
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
  oldSess: db.prepare('DELETE FROM sessions WHERE last<?'),
  getSetting: db.prepare('SELECT v FROM settings WHERE k=?'),
  putSetting: db.prepare('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v'),
  setLifetime: db.prepare('UPDATE users SET lifetime=? WHERE id=?'),
  setPaid: db.prepare('UPDATE users SET paid_until=? WHERE id=?'),
  freshTrials: db.prepare('UPDATE users SET trial_until=? WHERE trial_until<? AND paid_until<?'),
  insPay: db.prepare('INSERT INTO payments(id,user_id,provider,ext_id,status,amount,days,created,info) VALUES(?,?,?,?,?,?,?,?,?)'),
  payById: db.prepare('SELECT * FROM payments WHERE id=?'),
  payByExt: db.prepare('SELECT * FROM payments WHERE provider=? AND ext_id=?'),
  payOpen: db.prepare("SELECT * FROM payments WHERE user_id=? AND provider=? AND status='pending' AND done=0 AND created>? ORDER BY created DESC LIMIT 1"),
  payStatus: db.prepare('UPDATE payments SET status=?, checked=? WHERE id=?'),
  payDone: db.prepare("UPDATE payments SET status='approved', done=1, checked=? WHERE id=? AND done=0"),
  payPending: db.prepare("SELECT p.id,p.amount,p.created,p.checked,p.status,p.provider,u.email FROM payments p JOIN users u ON u.id=p.user_id WHERE p.status IN ('pending','avisado') AND p.done=0 AND p.provider='manual' AND p.created>? ORDER BY (p.status='avisado') DESC, p.created DESC LIMIT 100"),
  lifetimeList: db.prepare('SELECT email FROM users WHERE lifetime=1 ORDER BY email LIMIT 500'),
  allEmails: db.prepare('SELECT email FROM users ORDER BY email LIMIT 20000'),
  planCounts: db.prepare('SELECT COUNT(*) AS n, SUM(lifetime) AS life, SUM(CASE WHEN paid_until>? THEN 1 ELSE 0 END) AS paid, SUM(CASE WHEN paid_until<=? AND trial_until>? AND lifetime=0 THEN 1 ELSE 0 END) AS trial FROM users')
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

/* ---------------- assinatura: teste grátis, Pix (manual ou Mercado Pago), acesso vitalício ---------------- */
const PRICE_CENTS = Number(process.env.PRICE_CENTS || 2990);
const PERIOD_DAYS = Number(process.env.PERIOD_DAYS || 30);
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '').split(',').map(emailKey).filter(Boolean);
const ADMIN_HASHES = new Set((process.env.ADMIN_HASHES || '').split(',').map(s => s.trim()).filter(Boolean).concat(ADMIN_HASHES_FIXED));
const VIP_EMAILS = (process.env.LIFETIME_EMAILS || '').split(',').map(emailKey).filter(Boolean);
const VIP_HASHES = new Set((process.env.LIFETIME_HASHES || '').split(',').map(s => s.trim()).filter(Boolean).concat(VIP_HASHES_FIXED));
const MP_TOKEN = process.env.MP_ACCESS_TOKEN || '';
const MP_API = (process.env.MP_API || 'https://api.mercadopago.com').replace(/\/+$/, '');
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/+$/, '');
const getSet = k => { const r = Q.getSetting.get(k); return r ? r.v : null; };
const setSet = (k, v) => Q.putSetting.run(k, String(v));
const billingOn = () => (getSet('billing_on') ?? (process.env.BILLING === '1' ? '1' : '0')) === '1';
const emailHash = e => sha256('ceasa-admin|' + emailKey(e));
const isAdmin = u => !!u && (ADMIN_EMAILS.includes(u.email) || ADMIN_HASHES.has(emailHash(u.email)));
const isVip = u => !!u && (VIP_EMAILS.includes(u.email) || VIP_HASHES.has(sha256('ceasa-vip|' + emailKey(u.email))));
function planOf(u) {
  if (isAdmin(u)) return { status: 'admin' };
  if (Number(u.lifetime) || isVip(u)) return { status: 'lifetime' };
  if (!billingOn()) return { status: 'free' };
  const now = Date.now(), paid = Number(u.paid_until) || 0, trial = Number(u.trial_until) || 0;
  if (paid > now) return { status: 'active', until: paid };
  if (trial > now) return { status: 'trial', until: trial };
  return { status: 'expired', since: Math.max(paid, trial) };
}
const canWrite = pl => pl.status !== 'expired';
const pixCfg = () => ({ key: getSet('pix_key') || '', name: getSet('pix_name') || '', city: getSet('pix_city') || '' });
function payInfo() { const px = pixCfg(); return { price: PRICE_CENTS, days: PERIOD_DAYS, trialHours: TRIAL_HOURS, auto: !!MP_TOKEN, manual: !!px.key }; }
/* Pix "copia e cola" (BR Code, padrão do Banco Central) com valor e identificador da cobrança */
const asciiUp = (s, max) => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^A-Za-z0-9 .\-]/g, '').replace(/\s+/g, ' ').trim().toUpperCase().slice(0, max).trim();
function crc16(str) { let c = 0xFFFF; for (const b of Buffer.from(str, 'utf8')) { c ^= b << 8; for (let i = 0; i < 8; i++) c = (c & 0x8000) ? ((c << 1) ^ 0x1021) & 0xFFFF : (c << 1) & 0xFFFF; } return c.toString(16).toUpperCase().padStart(4, '0'); }
function brCode(key, name, city, cents, txid) {
  const f = (id, v) => id + String(v.length).padStart(2, '0') + v;
  const body = f('00', '01') + f('26', f('00', 'br.gov.bcb.pix') + f('01', key)) + f('52', '0000') + f('53', '986') + f('54', (cents / 100).toFixed(2)) + f('58', 'BR') + f('59', asciiUp(name, 25) || 'RECEBEDOR') + f('60', asciiUp(city, 15) || 'BRASIL') + f('62', f('05', txid.replace(/[^A-Za-z0-9]/g, '').slice(0, 25) || '***')) + '6304';
  return body + crc16(body);
}
function activate(row) {                                          // libera os dias pagos (uma vez só por pagamento)
  db.exec('BEGIN IMMEDIATE');
  try {
    const cur = Q.payById.get(row.id);
    if (!cur || cur.done) { db.exec('COMMIT'); return false; }
    const u = Q.userById.get(cur.user_id), base = Math.max(Date.now(), Number(u.paid_until) || 0);
    Q.setPaid.run(base + Number(cur.days) * 864e5, cur.user_id); Q.payDone.run(Date.now(), cur.id);
    db.exec('COMMIT'); log({ ev: 'pagamento', user: Number(cur.user_id), id: cur.id }); notify(Number(cur.user_id)); return true;
  } catch (e) { try { db.exec('ROLLBACK'); } catch (x) {} throw e; }
}
async function mpCall(method, p, body, idem) {
  const ac = new AbortController(), t = setTimeout(() => ac.abort(), 15000);
  try {
    const r = await fetch(MP_API + p, { method, headers: Object.assign({ Authorization: 'Bearer ' + MP_TOKEN, 'Content-Type': 'application/json' }, idem ? { 'X-Idempotency-Key': idem } : {}), body: body ? JSON.stringify(body) : undefined, signal: ac.signal });
    const j = await r.json().catch(() => null);
    if (!r.ok) { log({ ev: 'mp_erro', status: r.status }); throw new HttpError(502, 'payment_provider'); }
    return j || {};
  } catch (e) { if (e instanceof HttpError) throw e; throw new HttpError(502, 'payment_provider'); } finally { clearTimeout(t); }
}
async function mpCheck(row) {                                     // confere no próprio Mercado Pago (nunca confia só no aviso)
  if (!MP_TOKEN || row.provider !== 'mp' || !row.ext_id || row.done) return row;
  const j = await mpCall('GET', '/v1/payments/' + encodeURIComponent(row.ext_id));
  const ok = j.status === 'approved' && j.external_reference === row.id && j.currency_id === 'BRL' && Math.round(Number(j.transaction_amount) * 100) >= row.amount;
  Q.payStatus.run(ok ? 'pending' : j.status === 'approved' ? 'divergente' : String(j.status || 'pending').replace(/[^a-z_]/g, '').slice(0, 20) || 'pending', Date.now(), row.id);   // aprovado mas com valor/referência errados: NÃO libera
  if (ok) activate(row);
  return Q.payById.get(row.id);
}
function publicBase(req) {
  if (PUBLIC_URL) return PUBLIC_URL;
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  return host && /^[A-Za-z0-9.-]+(:\d+)?$/.test(host) ? 'https://' + host : '';
}
async function startPayment(req, u) {
  const pl = planOf(u);
  if (['admin', 'lifetime', 'free'].includes(pl.status)) throw new HttpError(400, 'not_needed');
  if (!limit('pay:' + u.id, 20, 3600e3)) throw new HttpError(429, 'rate_limited');
  const recent = Date.now() - 20 * 60e3;
  if (MP_TOKEN) {
    let row = Q.payOpen.get(u.id, 'mp', recent);
    if (row && row.info) return JSON.parse(row.info);
    const id = 'p' + crypto.randomBytes(9).toString('base64url').replace(/[^A-Za-z0-9]/g, '');
    const base = publicBase(req);
    const j = await mpCall('POST', '/v1/payments', Object.assign({ transaction_amount: PRICE_CENTS / 100, description: 'Controle Ceasa - ' + PERIOD_DAYS + ' dias', payment_method_id: 'pix', payer: { email: u.email }, external_reference: id }, base.startsWith('https://') ? { notification_url: base + '/api/pay/webhook' } : {}), id);
    const td = (j.point_of_interaction && j.point_of_interaction.transaction_data) || {};
    const out = { id, provider: 'mp', amount: PRICE_CENTS, days: PERIOD_DAYS, code: String(td.qr_code || ''), qrImg: String(td.qr_code_base64 || '') };
    Q.insPay.run(id, u.id, 'mp', String(j.id), 'pending', PRICE_CENTS, PERIOD_DAYS, Date.now(), JSON.stringify(out));
    return out;
  }
  const px = pixCfg();
  if (!px.key) throw new HttpError(503, 'pix_not_configured');
  let row = Q.payOpen.get(u.id, 'manual', recent);
  if (!row) { const id = 'p' + crypto.randomBytes(9).toString('base64url').replace(/[^A-Za-z0-9]/g, ''); Q.insPay.run(id, u.id, 'manual', null, 'pending', PRICE_CENTS, PERIOD_DAYS, Date.now(), null); row = Q.payById.get(id); }
  return { id: row.id, provider: 'manual', amount: PRICE_CENTS, days: PERIOD_DAYS, code: brCode(px.key, px.name, px.city, PRICE_CENTS, row.id), key: px.key, name: px.name };
}
function adminOverview() {
  const now = Date.now(), c = Q.planCounts.get(now, now, now), px = pixCfg();
  return { billing: billingOn(), pix: px, info: payInfo(), pending: Q.payPending.all(now - 30 * 864e5).map(r => ({ id: r.id, email: r.email, amount: Number(r.amount), created: Number(r.created), claimed: r.status === 'avisado' ? Number(r.checked) : 0 })), lifetime: Q.lifetimeList.all().map(r => r.email), lifetimeFixed: (VIP_EMAILS.length || VIP_HASHES.size) ? Q.allEmails.all().map(r => r).filter(isVip).map(r => r.email) : [], counts: { contas: Number(c.n) || 0, vitalicias: Number(c.life) || 0, pagas: Number(c.paid) || 0, teste: Number(c.trial) || 0 } };
}
function adminUser(email) { const u = Q.userByEmail.get(emailKey(email)); if (!u) throw new HttpError(404, 'no_user'); return u; }

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
    const woke = await new Promise(res => {
      let set = waiters.get(userId); if (!set) { set = new Set(); waiters.set(userId, set); }
      const t = setTimeout(() => done(false), left); function done(w) { clearTimeout(t); set.delete(wake); res(w); } function wake() { done(true); }
      set.add(wake); req.once('close', () => done(false));
    });
    if (woke && !Q.changes.all(userId, since).length) return { seq: Math.max(since, Number(Q.userSeq.get(userId).seq)), changes: [] };   // acordou sem dado novo (ex.: pagamento liberado): responde já, com a situação da conta
  }
}

/* ---------------- HTTP ---------------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8' };
let cspCache = { file: '', mtime: 0, value: '' };
function cspFor(file, self) {                                           // CSP com hash dos scripts/estilos embutidos (sem 'unsafe-inline' em scripts)
  const st = fs.statSync(file);
  if (cspCache.file === file && cspCache.mtime === st.mtimeMs && cspCache.self === self) return cspCache.value;
  const html = fs.readFileSync(file, 'utf8'), hs = { script: [], style: [] };
  for (const kind of ['script', 'style']) { const re = new RegExp('<' + kind + '(?![^>]*\\bsrc=)[^>]*>([\\s\\S]*?)</' + kind + '>', 'g'); let m; while ((m = re.exec(html))) hs[kind].push("'sha256-" + crypto.createHash('sha256').update(m[1]).digest('base64') + "'"); }
  const conn = ["'self'"].concat(self ? [self] : [], ALLOWED_ORIGINS).join(' ');
  const v = ["default-src 'self'", 'script-src \'self\' ' + hs.script.join(' '), 'style-src \'self\' ' + hs.style.join(' '), "style-src-attr 'unsafe-inline'", "img-src 'self' data:", 'connect-src ' + conn, "frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'", "form-action 'self'"].join('; ');
  cspCache = { file, mtime: st.mtimeMs, self, value: v }; return v;
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
    let id; try { id = Number(Q.insUser.run(email, salt, hash.toString('hex'), rsalt, rhash.toString('hex'), Date.now(), Date.now() + TRIAL_HOURS * 3600e3).lastInsertRowid); } catch (e) { throw new HttpError(409, 'email_exists'); }
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
  if (p === '/api/pay/webhook' && m === 'POST') {                 // aviso do Mercado Pago: só serve de gatilho; o status é conferido na API dele
    if (!limit('wh:' + clientIp(req), 120, 60e3)) throw new HttpError(429, 'rate_limited');
    let b = {}; try { b = await readJson(req); } catch (e) { b = {}; }
    const extId = String(url.searchParams.get('data.id') || url.searchParams.get('id') || (b && b.data && b.data.id) || '').replace(/[^0-9A-Za-z_-]/g, '').slice(0, 40);
    sendJson(req, res, 200, { ok: true });
    if (extId) { const row = Q.payByExt.get('mp', extId); if (row && !row.done) mpCheck(row).catch(() => {}); }
    return;
  }
  const au = authUser(req);                                       // daqui para baixo: só com sessão válida
  if (p === '/api/auth/logout' && m === 'POST') { Q.delSess.run(au.tokHash); return sendJson(req, res, 200, { ok: true }); }
  if (p === '/api/auth/me' && m === 'GET') { const u = Q.userById.get(au.id); return sendJson(req, res, 200, { user: { id: au.id, email: au.email }, seq: Number(Q.userSeq.get(au.id).seq), plan: planOf(u), admin: isAdmin(u), pay: payInfo() }); }
  if (p === '/api/pay/start' && m === 'POST') return sendJson(req, res, 200, await startPayment(req, Q.userById.get(au.id)));
  if (p === '/api/pay/claim' && m === 'POST') {                   // cliente avisa "já paguei" (Pix manual): aparece em destaque para o administrador
    const b = await readJson(req), row = Q.payById.get(String(b.id || ''));
    if (!row || Number(row.user_id) !== au.id || row.provider !== 'manual') throw new HttpError(404, 'not_found');
    if (!row.done && row.status !== 'rejected') Q.payStatus.run('avisado', Date.now(), row.id);
    return sendJson(req, res, 200, { status: row.done ? 'approved' : Q.payById.get(row.id).status });
  }
  if (p === '/api/pay/status' && m === 'GET') {
    const row = Q.payById.get(String(url.searchParams.get('id') || ''));
    if (!row || Number(row.user_id) !== au.id) throw new HttpError(404, 'not_found');
    let cur = row; if (row.provider === 'mp' && !row.done && Date.now() - Number(row.checked) > 4000) { try { cur = await mpCheck(row); } catch (e) {} }
    return sendJson(req, res, 200, { status: cur.done ? 'approved' : cur.status, plan: planOf(Q.userById.get(au.id)) });
  }
  if (p.startsWith('/api/admin/')) {                              // administração: só e-mails e situação das contas; nunca os lançamentos
    const me = Q.userById.get(au.id); if (!isAdmin(me)) throw new HttpError(403, 'forbidden');
    if (p === '/api/admin/overview' && m === 'GET') return sendJson(req, res, 200, adminOverview());
    if (p === '/api/admin/settings' && m === 'POST') {
      const b = await readJson(req);
      if (b.pix_key !== undefined) { const k = String(b.pix_key == null ? '' : b.pix_key).trim(); if (k.length > 77 || /\s/.test(k)) throw new HttpError(400, 'pix_key_invalid'); setSet('pix_key', k); }
      if (b.pix_name !== undefined) setSet('pix_name', asciiUp(b.pix_name, 25));
      if (b.pix_city !== undefined) setSet('pix_city', asciiUp(b.pix_city, 15));
      if (b.billing !== undefined) { const on = !!b.billing; if (on && !billingOn()) { const now = Date.now(), t = now + TRIAL_HOURS * 3600e3; Q.freshTrials.run(t, t, now); } setSet('billing_on', on ? '1' : '0'); }
      log({ ev: 'admin', kind: 'settings' });
      return sendJson(req, res, 200, adminOverview());
    }
    if (p === '/api/admin/grant' && m === 'POST') {
      const b = await readJson(req), u = adminUser(b.email), kind = String(b.kind || '');
      if (kind === 'lifetime') Q.setLifetime.run(1, u.id);
      else if (kind === 'unlifetime') Q.setLifetime.run(0, u.id);
      else if (kind === 'days') { const d = Math.max(1, Math.min(3660, parseInt(b.days, 10) || PERIOD_DAYS)); Q.setPaid.run(Math.max(Date.now(), Number(u.paid_until) || 0) + d * 864e5, u.id); }
      else throw new HttpError(400, 'invalid_kind');
      notify(Number(u.id)); log({ ev: 'admin', kind, user: Number(u.id) });
      return sendJson(req, res, 200, Object.assign(adminOverview(), { done: { email: u.email, plan: planOf(Q.userById.get(u.id)) } }));
    }
    if (p === '/api/admin/confirm' && m === 'POST') {
      const b = await readJson(req), row = Q.payById.get(String(b.id || ''));
      if (!row || row.provider !== 'manual') throw new HttpError(404, 'not_found');
      if (b.reject) Q.payStatus.run('rejected', Date.now(), row.id); else activate(row);
      return sendJson(req, res, 200, adminOverview());
    }
    throw new HttpError(404, 'not_found_route');
  }

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
  if (p === '/api/docs/write' && m === 'POST') { const pl = planOf(Q.userById.get(au.id)); if (!canWrite(pl)) throw new HttpError(402, 'payment_required', { plan: pl }); const b = await readJson(req); return sendJson(req, res, 200, runWrite(au.id, b.ops)); }
  if (p === '/api/changes' && m === 'GET') {
    const since = Math.max(0, parseInt(url.searchParams.get('since'), 10) || 0), wait = Math.min(25, Math.max(0, parseInt(url.searchParams.get('wait'), 10) || 0));
    const out = await longPoll(au.id, since, wait, req); out.plan = planOf(Q.userById.get(au.id));
    return sendJson(req, res, 200, out);
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
  if (isHtml) { const host = String(req.headers.host || ''); h['Content-Security-Policy'] = cspFor(file, /^[A-Za-z0-9.-]+(:\d+)?$/.test(host) ? (req.socket.encrypted || TRUST_PROXY ? 'https://' : 'http://') + host : ''); }
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
/* ---------------- atualização automática: se houver versão nova no GitHub, reinicia para pegá-la ---------------- */
const AUTO_UPDATE = process.env.AUTO_UPDATE !== '0' && fs.existsSync(path.join(__dirname, '.git'));
function checkUpdate(stop) {
  const g = (args, cb) => execFile('git', ['-C', __dirname].concat(args), { timeout: 60000, maxBuffer: 8 * 1024 * 1024 }, cb);
  g(['fetch', '-q', 'origin'], err => {
    if (err) return;
    g(['rev-parse', 'HEAD', '@{u}'], (e2, out) => {
      if (e2) return;
      const [a, b] = String(out).trim().split('\n');
      if (!a || !b || a === b) return;
      const mark = path.join(DATA_DIR, '.atualizacao-tentada');
      let tried = ''; try { tried = fs.readFileSync(mark, 'utf8').trim(); } catch (x) {}
      if (tried === b) return;                                     // já reiniciou para esta versão e não pegou: não fica reiniciando sem parar
      g(['merge-base', '--is-ancestor', 'HEAD', '@{u}'], e5 => {   // só versões que o "git pull --ff-only" consegue aplicar
      if (e5) return;
      g(['show', '@{u}:server.js'], (e3, src) => {                 // só reinicia se a versão nova pelo menos compila
        if (e3) return;
        const tmp = path.join(DATA_DIR, '.server-novo.js');
        try { fs.writeFileSync(tmp, src); } catch (x) { return; }
        execFile(process.execPath, ['--check', tmp], { timeout: 30000 }, e4 => {
          try { fs.unlinkSync(tmp); } catch (x) {}
          if (e4) { log({ ev: 'atualizacao_recusada', para: b.slice(0, 7) }); return; }
          try { fs.writeFileSync(mark, b); } catch (x) {}
          log({ ev: 'atualizando', de: a.slice(0, 7), para: b.slice(0, 7) }); stop();
        });
      });
      });
    });
  });
}
if (require.main === module) {
  cli(process.argv.slice(2)).then(handled => {
    if (handled) { db.close(); return; }
    gc(); setInterval(gc, 6 * 3600e3).unref();
    server.listen(PORT, HOST, () => log({ ev: 'ligado', porta: PORT, versao: VERSION, dados: DATA_DIR, publico: PUBLIC_DIR, cobranca: billingOn(), mp: !!MP_TOKEN, autoatualizar: AUTO_UPDATE }));
    const stop = () => { log({ ev: 'desligando' }); server.close(() => { try { db.close(); } catch (e) {} process.exit(0); }); setTimeout(() => process.exit(0), 5000).unref(); };
    process.on('SIGTERM', stop); process.on('SIGINT', stop);
    if (AUTO_UPDATE) { setTimeout(() => checkUpdate(stop), (Number(process.env.AUTO_UPDATE_FIRST_S) || 120) * 1e3).unref(); setInterval(() => checkUpdate(stop), (Number(process.env.AUTO_UPDATE_EVERY_S) || 600) * 1e3).unref(); }
  });
}
module.exports = { server, db };
