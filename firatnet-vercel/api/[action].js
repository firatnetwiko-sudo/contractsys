'use strict';
const crypto = require('crypto');

const RURL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const RTOK = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const SECRET = process.env.SESSION_SECRET || RTOK || '';
const P = 'fn:';
const CH = 450 * 1024;
const MAX_FILE = 10 * 1048576;
const SESSION_SECS = 12 * 3600;

/* ---------- Redis (Upstash REST) ---------- */
async function cmd(...a) {
  const r = await fetch(RURL, { method: 'POST', headers: { Authorization: 'Bearer ' + RTOK }, body: JSON.stringify(a) });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}
async function pipe(list) {
  if (!list.length) return [];
  const r = await fetch(RURL + '/pipeline', { method: 'POST', headers: { Authorization: 'Bearer ' + RTOK }, body: JSON.stringify(list) });
  const j = await r.json();
  return j.map(x => { if (x.error) throw new Error(x.error); return x.result; });
}
async function hall(key) {
  const flat = (await cmd('HGETALL', P + key)) || [];
  const out = [];
  for (let i = 1; i < flat.length; i += 2) { try { out.push(JSON.parse(flat[i])); } catch (e) {} }
  return out;
}

/* ---------- passwords & sessions ---------- */
function hashPw(pw, salt) { return crypto.scryptSync(String(pw), salt, 32).toString('hex'); }
function makeCred(pw) { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: hashPw(pw, salt) }; }
function safeEq(a, b) { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); }
function sign(s) { return crypto.createHmac('sha256', SECRET).update(s).digest('base64url'); }
function makeToken(uid) { const exp = Math.floor(Date.now() / 1000) + SESSION_SECS; const b = uid + '.' + exp; return b + '.' + sign(b); }
function readToken(req) {
  const m = /(?:^|;\s*)fn_s=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const p = decodeURIComponent(m[1]).split('.');
  if (p.length !== 3) return null;
  if (!safeEq(sign(p[0] + '.' + p[1]), p[2])) return null;
  if (parseInt(p[1], 10) < Date.now() / 1000) return null;
  return p[0];
}
const cookie = (v, age) => `fn_s=${encodeURIComponent(v)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${age}`;
async function authUser(req) {
  const uid = readToken(req);
  if (!uid) return null;
  const raw = await cmd('HGET', P + 'users', uid);
  if (!raw) return null;
  const u = JSON.parse(raw);
  return u.active ? u : null;
}
const pub = u => ({ id: u.id, user: u.user, role: u.role, perms: u.perms, active: u.active, created: u.created });
const can = (u, a) => u.role === 'admin' || !!(u.perms && u.perms[a]);
const normPerms = (role, p) => { const o = {}; ['view', 'create', 'edit', 'delete'].forEach(k => { o[k] = (role === 'admin' || (p && p[k])) ? 1 : 0; }); if (!o.view) { o.create = 0; o.edit = 0; o.delete = 0; } return o; };

/* ---------- handler ---------- */
module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const send = (code, obj) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.end(JSON.stringify(obj)); };
  try {
    if (!RURL || !RTOK) return send(500, { error: 'storage_not_configured' });
    const action = (req.query && req.query.action) || '';
    const body = req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body) ? req.body : {};

    /* ----- login ----- */
    if (action === 'login' && req.method === 'POST') {
      const ip = String(req.headers['x-forwarded-for'] || 'x').split(',')[0].trim();
      const rl = P + 'rl:' + ip;
      const [, n] = await pipe([['SET', rl, 0, 'EX', 300, 'NX'], ['INCR', rl]]);
      if (n > 10) { const ttl = await cmd('TTL', rl); return send(429, { error: 'locked', retry: Math.max(1, ttl) }); }
      const name = String(body.user || '').trim(), pw = String(body.pw || '');
      if (!name || !pw) return send(400, { error: 'fill' });
      let users = await hall('users');
      if (!users.length && process.env.ADMIN_USER && process.env.ADMIN_PASSWORD &&
          safeEq(name.toLowerCase(), process.env.ADMIN_USER.trim().toLowerCase()) && safeEq(pw, process.env.ADMIN_PASSWORD)) {
        const u = { id: 'u' + crypto.randomBytes(6).toString('hex'), user: process.env.ADMIN_USER.trim(), ...makeCred(pw), role: 'admin', perms: normPerms('admin'), active: true, created: Date.now() };
        await cmd('HSET', P + 'users', u.id, JSON.stringify(u));
        users = [u];
      }
      const u = users.find(x => x.user.toLowerCase() === name.toLowerCase());
      let ok = false;
      if (u) ok = safeEq(hashPw(pw, u.salt), u.hash); else hashPw(pw, 'x'.repeat(32));
      if (!ok) return send(401, { error: 'bad' });
      if (!u.active) return send(403, { error: 'disabled' });
      await cmd('DEL', rl);
      res.setHeader('Set-Cookie', cookie(makeToken(u.id), SESSION_SECS));
      return send(200, { ok: true });
    }
    if (action === 'logout') { res.setHeader('Set-Cookie', cookie('', 0)); return send(200, { ok: true }); }

    const me = await authUser(req);
    if (!me) return send(401, { error: 'auth' });

    /* ----- state ----- */
    if (action === 'state' && req.method === 'GET') {
      const [invoices, contracts] = await Promise.all([hall('invoices'), hall('contracts')]);
      const out = { me: pub(me), invoices: can(me, 'view') ? invoices : [], contracts: can(me, 'view') ? contracts : [] };
      if (me.role === 'admin') out.users = (await hall('users')).map(pub);
      return send(200, out);
    }

    /* ----- sync (upsert / delete records) ----- */
    if (action === 'sync' && req.method === 'POST') {
      const c = body.c;
      if (c !== 'invoices' && c !== 'contracts') return send(400, { error: 'bad' });
      const up = Array.isArray(body.up) ? body.up.slice(0, 50) : [], del = Array.isArray(body.del) ? body.del.slice(0, 50) : [];
      const key = P + c, cmds = [];
      for (const r of up) {
        if (!r || typeof r !== 'object' || !/^[\w-]{1,40}$/.test(String(r.id || ''))) return send(400, { error: 'bad' });
        const s = JSON.stringify(r);
        if (s.length > 200000) return send(400, { error: 'big' });
        const exists = await cmd('HEXISTS', key, r.id);
        if (!can(me, exists ? 'edit' : 'create')) return send(403, { error: 'perm' });
        cmds.push(['HSET', key, r.id, s]);
      }
      for (const id of del) {
        if (!/^[\w-]{1,40}$/.test(String(id))) return send(400, { error: 'bad' });
        if (!can(me, 'delete')) return send(403, { error: 'perm' });
        cmds.push(['HDEL', key, id]);
      }
      await pipe(cmds);
      return send(200, { ok: true });
    }

    /* ----- users ----- */
    if (action === 'users' && req.method === 'POST') {
      const op = body.op;
      if (op === 'password') {
        const pw = String(body.pw || '');
        if (pw.length < 6) return send(400, { error: 'short' });
        if (!safeEq(hashPw(String(body.cur || ''), me.salt), me.hash)) return send(400, { error: 'cur' });
        await cmd('HSET', P + 'users', me.id, JSON.stringify({ ...me, ...makeCred(pw) }));
        return send(200, { ok: true });
      }
      if (me.role !== 'admin') return send(403, { error: 'perm' });
      const users = await hall('users');
      const list = () => hall('users').then(a => a.map(pub));
      const lastAdminOk = (arr) => arr.filter(x => x.role === 'admin' && x.active).length >= 1;
      if (op === 'create' || op === 'update') {
        const name = String(body.user || '').trim(), role = body.role === 'admin' ? 'admin' : 'user', pw = String(body.pw || '');
        const active = body.active !== false;
        if (name.length < 3 || name.length > 40) return send(400, { error: 'user' });
        if (users.some(x => x.id !== body.id && x.user.toLowerCase() === name.toLowerCase())) return send(400, { error: 'taken' });
        if ((op === 'create' && pw.length < 6) || (pw && pw.length < 6)) return send(400, { error: 'short' });
        let u;
        if (op === 'create') u = { id: 'u' + crypto.randomBytes(6).toString('hex'), created: Date.now() };
        else { u = users.find(x => x.id === body.id); if (!u) return send(404, { error: 'none' }); if (u.id === me.id && !active) return send(400, { error: 'self' }); }
        const nu = { ...u, user: name, role, perms: normPerms(role, body.perms), active, ...(pw ? makeCred(pw) : (op === 'create' ? {} : { salt: u.salt, hash: u.hash })) };
        const next = users.filter(x => x.id !== nu.id).concat(nu);
        if (!lastAdminOk(next)) return send(400, { error: 'lastadmin' });
        await cmd('HSET', P + 'users', nu.id, JSON.stringify(nu));
        return send(200, { users: await list() });
      }
      if (op === 'delete') {
        const u = users.find(x => x.id === body.id);
        if (!u) return send(404, { error: 'none' });
        if (u.id === me.id) return send(400, { error: 'self' });
        if (!lastAdminOk(users.filter(x => x.id !== u.id))) return send(400, { error: 'lastadmin' });
        await cmd('HDEL', P + 'users', u.id);
        return send(200, { users: await list() });
      }
      return send(400, { error: 'bad' });
    }

    /* ----- file chunks ----- */
    if (action === 'file') {
      const id = String((req.query && req.query.id) || '');
      if (!/^f[a-z0-9]{4,40}$/.test(id)) return send(400, { error: 'bad' });
      if (req.method === 'POST') {
        if (!can(me, 'edit') && !can(me, 'create')) return send(403, { error: 'perm' });
        const i = parseInt(req.query.i, 10);
        if (!(i >= 0) || i >= Math.ceil(MAX_FILE / CH)) return send(400, { error: 'bad' });
        const buf = Buffer.isBuffer(req.body) ? req.body : null;
        if (!buf || !buf.length || buf.length > CH) return send(400, { error: 'bad' });
        await cmd('SET', P + 'file:' + id + ':' + i, buf.toString('base64'));
        return send(200, { ok: true });
      }
      if (req.method === 'GET') {
        if (!can(me, 'view')) return send(403, { error: 'perm' });
        const i = parseInt(req.query.i, 10);
        if (!(i >= 0)) return send(400, { error: 'bad' });
        const v = await cmd('GET', P + 'file:' + id + ':' + i);
        if (!v) return send(404, { error: 'none' });
        res.statusCode = 200; res.setHeader('Content-Type', 'application/octet-stream');
        return res.end(Buffer.from(v, 'base64'));
      }
      if (req.method === 'DELETE') {
        if (!can(me, 'delete')) return send(403, { error: 'perm' });
        const n = Math.min(parseInt(req.query.n, 10) || 1, Math.ceil(MAX_FILE / CH));
        await pipe(Array.from({ length: n }, (_, k) => ['DEL', P + 'file:' + id + ':' + k]));
        return send(200, { ok: true });
      }
    }
    return send(404, { error: 'unknown' });
  } catch (e) {
    return send(500, { error: 'server' });
  }
};
module.exports.config = { api: { bodyParser: { sizeLimit: '1mb' } } };
