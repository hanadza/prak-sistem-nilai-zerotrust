'use strict';
// POLICY ENFORCEMENT POINT (PEP). Setiap request ke resource melewati langkah berikut:
//  1. token valid  2. device terdaftar (untuk user)  3. keputusan Policy Engine  4. audit  5. teruskan / tolak
const db = require('../shared/db');
const tokens = require('./tokens');
const policy = require('./policy');
const audit = require('./audit');

module.exports = function pep(req, res, next) {
  const finish = (subject, role, d) => {
    audit.record({ subject, role, req, result: d.allow ? 'allow' : 'deny', reason: d.reason });
    if (d.allow) return next();
    return res.status(d.status || 403).json({ error: 'Akses ditolak', reason: d.reason });
  };

  // 1. Autentikasi token
  const m = /^Bearer (.+)$/.exec(req.get('Authorization') || '');
  if (!m) return finish('anonymous', null, { allow: false, status: 401, reason: 'access token tidak ada' });
  let claims;
  try { claims = tokens.verify(m[1]); } catch (e) {
    return finish('anonymous', null, { allow: false, status: 401, reason: `token tidak valid: ${e.name}` });
  }
  if (!['access', 'service'].includes(claims.typ)) {
    return finish('anonymous', null, { allow: false, status: 401, reason: 'jenis token tidak dikenal' });
  }
  const subject = { sub: String(claims.sub), role: claims.role, typ: claims.typ };
  const label = subject.typ === 'service' ? `service:${subject.sub}` : `user:${subject.sub}`;

  // 2. Verifikasi konteks (khusus user): akun masih ada dan device terdaftar
  let user = null;
  if (subject.typ === 'access') {
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(subject.sub);
    if (!user || user.role !== subject.role) {
      return finish(label, subject.role, { allow: false, status: 401, reason: 'akun tidak ditemukan atau role tidak sesuai' });
    }
    const deviceId = req.get('X-Device-ID');
    if (!deviceId) return finish(label, subject.role, { allow: false, status: 403, reason: 'header X-Device-ID tidak ada' });
    const dev = db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?').get(user.id, deviceId);
    if (!dev) return finish(label, subject.role, { allow: false, status: 403, reason: `device ${deviceId} tidak terdaftar untuk user` });
  }

  // 3. Keputusan Policy Engine
  const decision = policy.decide({
    subject, user, method: req.method, path: req.originalUrl.split('?')[0], query: req.query,
  });
  // 4 + 5. Audit lalu teruskan atau tolak
  return finish(label, subject.role, decision);
};
