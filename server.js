// بطولات حفل تقاعد الأستاذ محمد صائغ — ملف السيرفر (بدون أي مكتبات خارجية)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const clean1 = v => String(v || '').trim().replace(/^["']|["']$/g, '');
const PASS_LIST = ['ADMIN_KEY', 'ADMIN_PASSWORD', 'ADMIN_PASS', 'ADMIN_SECRET', 'ADMIN_TOKEN', 'KEY', 'PASSWORD', 'ADMIN', 'SECRET'].map(k => clean1(process.env[k])).filter(Boolean);
if (!PASS_LIST.length) PASS_LIST.push('admin123');
const ADMIN_PASSWORD = PASS_LIST[0];
const SECRET = process.env.SECRET || ('s_' + ADMIN_PASSWORD);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const FILE = path.join(DATA_DIR, 'state.json');
const TIDS = ['belot', 'domino', 'tennis'];

fs.mkdirSync(DATA_DIR, { recursive: true });
let state = { regs: {}, draws: {} };
try { state = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
function save() { const tmp = FILE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(state)); fs.renameSync(tmp, FILE); }

const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
function makeToken() { const exp = Date.now() + 3 * 24 * 3600 * 1000; return exp + '.' + sign('admin:' + exp); }
function okToken(t) {
  if (!t) return false;
  const [exp, sig] = String(t).split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const good = sign('admin:' + exp);
  return sig.length === good.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good));
}
const cleanName = n => String(n || '').trim().slice(0, 40);
const norm = s => String(s || '').trim().replace(/\s+/g, ' ');
const triple = s => norm(s).split(' ').filter(Boolean).length >= 3;
function validate(t, b) {
  if (!TIDS.includes(t)) return null;
  if (t === 'tennis') {
    const n = norm(cleanName(b.team || b.name)), p1 = norm(cleanName(b.p1)), p2 = norm(cleanName(b.p2));
    if (!n || !triple(p1) || !triple(p2) || p1 === p2) return null;
    return { n, t, p1, p2 };
  }
  const n = norm(cleanName(b.name));
  return triple(n) ? { n, t } : null;
}
const namesOf = r => r.t === 'tennis' ? [r.p1, r.p2] : [r.n];
function taken(rec, exceptId) {
  const used = new Set();
  for (const [id, r] of Object.entries(state.regs)) if (id !== exceptId) namesOf(r).forEach(x => used.add(norm(x)));
  return namesOf(rec).some(x => used.has(norm(x)));
}
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(obj)); };

function readBody(req) {
  return new Promise(resolve => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > 200000) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch (e) { resolve({}); } });
  });
}

console.log('عدد كلمات السر المقبولة: ' + PASS_LIST.length);

http.createServer(async (req, res) => {
  const url = req.url.split('?')[0].replace(/\/+$/, '') || '/';
  const m = req.method;

  if (m === 'GET' && (url === '/' || url === '/admin')) {
    try {
      const html = fs.readFileSync(path.join(__dirname, 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(html);
    } catch (e) { res.writeHead(500); return res.end('index.html غير موجود بجانب server.js'); }
  }
  if (m === 'GET' && url === '/api/state') return send(res, 200, state);

  if (m === 'POST' && url === '/api/register') {
    const b = await readBody(req);
    const rec = validate(b.t, b);
    if (!/^[a-z0-9]{8,40}$/i.test(b.cid || '') || !rec) return send(res, 400, { error: 'bad' });
    const id = 'c_' + b.cid;
    if (state.regs[id]) return send(res, 409, { error: 'already' });
    if (taken(rec, id)) return send(res, 409, { error: 'dup' });
    rec.ts = Date.now(); state.regs[id] = rec; save(); return send(res, 200, { ok: true });
  }

  if (m === 'POST' && url === '/api/admin/login') {
    const b = await readBody(req);
    const pw = clean1(b.password);
    if (PASS_LIST.some(p => p.toLowerCase() === pw.toLowerCase())) return send(res, 200, { token: makeToken() });
    return setTimeout(() => send(res, 401, { error: 'wrong' }), 600);
  }

  if (url.startsWith('/api/admin/')) {
    if (!okToken((req.headers.authorization || '').replace('Bearer ', ''))) return send(res, 401, { error: 'unauthorized' });
    const parts = url.split('/'); // ['', 'api', 'admin', kind, id]
    const kind = parts[3], id = decodeURIComponent(parts[4] || '');
    const b = (m === 'POST' || m === 'PATCH' || m === 'PUT') ? await readBody(req) : {};

    if (kind === 'reg' && m === 'POST') {
      const rec = validate(b.t, b);
      if (!rec) return send(res, 400, { error: 'bad' });
      if (taken(rec, null)) return send(res, 409, { error: 'dup' });
      rec.ts = Date.now();
      state.regs['m_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6)] = rec;
      save(); return send(res, 200, { ok: true });
    }
    if (kind === 'reg' && m === 'PATCH') {
      const r = state.regs[id];
      if (!r) return send(res, 400, { error: 'bad' });
      const rec = validate(r.t, { name: b.name, team: b.name, p1: b.p1, p2: b.p2 });
      if (!rec) return send(res, 400, { error: 'bad' });
      if (taken(rec, id)) return send(res, 409, { error: 'dup' });
      rec.ts = r.ts; state.regs[id] = rec; save(); return send(res, 200, { ok: true });
    }
    if (kind === 'reset' && m === 'POST') { state = { regs: {}, draws: {} }; save(); return send(res, 200, { ok: true }); }
    if (kind === 'reg' && m === 'DELETE') { delete state.regs[id]; save(); return send(res, 200, { ok: true }); }
    if (kind === 'draw' && m === 'PUT') {
      if (!TIDS.includes(id) || typeof b.r !== 'string') return send(res, 400, { error: 'bad' });
      state.draws[id] = { r: b.r, ts: Date.now() }; save(); return send(res, 200, { ok: true });
    }
    if (kind === 'draw' && m === 'DELETE') { delete state.draws[id]; save(); return send(res, 200, { ok: true }); }
  }
  send(res, 404, { error: 'not found' });
}).listen(PORT, () => console.log('Running on port ' + PORT));
