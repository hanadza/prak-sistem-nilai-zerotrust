'use strict';
// Verifikasi di sisi service (zero trust: service tidak percaya begitu saja pada jaringan).
//  1. X-Gateway-Secret harus cocok  -> service tidak dapat diakses langsung.
//  2. Access token / token service diverifikasi ulang (tanda tangan RS256, masa berlaku, issuer, audience).
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cfg = require('../config');

const publicKey = cfg.readKey('public'); // service hanya memegang kunci PUBLIK, tidak bisa menerbitkan token

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function serviceGuard(req, res, next) {
  if (!safeEqual(req.get('X-Gateway-Secret'), cfg.gatewaySecret)) {
    return res.status(403).json({ error: 'Akses langsung ditolak: X-Gateway-Secret tidak valid' });
  }
  const m = /^Bearer (.+)$/.exec(req.get('Authorization') || '');
  if (!m) return res.status(401).json({ error: 'Token tidak ada' });
  let claims;
  try {
    claims = jwt.verify(m[1], publicKey, {
      algorithms: ['RS256'], issuer: cfg.jwt.issuer, audience: cfg.jwt.audience,
    });
  } catch (e) {
    return res.status(401).json({ error: 'Token tidak valid atau kedaluwarsa' });
  }
  if (!['access', 'service'].includes(claims.typ) || !claims.sub || !claims.role) {
    return res.status(401).json({ error: 'Klaim token tidak lengkap' });
  }
  req.auth = { sub: String(claims.sub), role: claims.role, typ: claims.typ };
  next();
}

const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.auth.role) ? next() : res.status(403).json({ error: 'Role tidak diizinkan di service' });

module.exports = { serviceGuard, requireRole };
