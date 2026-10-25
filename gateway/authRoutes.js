'use strict';
// Endpoint /auth/* ditangani langsung oleh gateway (Policy Engine / Policy Administrator).
const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../shared/db');
const cfg = require('../config');
const tokens = require('./tokens');
const audit = require('./audit');

const router = express.Router();
router.use(express.json({ limit: '10kb' }));

const DUMMY_HASH = bcrypt.hashSync('dummy-password', 10); // menyamakan waktu respons saat user tidak ada
const MAX_FAIL = 5, WINDOW_MS = 60 * 1000;
const fails = new Map(); // pembatas brute force sederhana per username

const isLocked = (u) => {
  const f = fails.get(u);
  if (!f) return false;
  if (Date.now() > f.until) { fails.delete(u); return false; }
  return f.count >= MAX_FAIL;
};
const addFail = (u) => {
  const f = fails.get(u) && Date.now() <= fails.get(u).until ? fails.get(u) : { count: 0, until: Date.now() + WINDOW_MS };
  f.count += 1; fails.set(u, f);
};

const log = (req, subject, role, result, reason) => audit.record({ subject, role, req, result, reason });

const issueRefresh = (userId, deviceId) => {
  const token = tokens.newRefreshToken();
  db.prepare(`INSERT INTO refresh_tokens (user_id, token_hash, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`)
    .run(userId, tokens.hashRefresh(token), deviceId, Date.now() + cfg.jwt.refreshTtlMs, new Date().toISOString());
  return token;
};

// POST /auth/login : kredensial valid DAN device terdaftar
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const device = req.get('X-Device-ID');
  if (typeof username !== 'string' || typeof password !== 'string' || !device) {
    log(req, 'anonymous', null, 'deny', 'input tidak lengkap (username, password, X-Device-ID)');
    return res.status(400).json({ error: 'username, password, dan header X-Device-ID wajib diisi' });
  }
  if (isLocked(username)) {
    log(req, `user:${username}`, null, 'deny', 'terlalu banyak percobaan login gagal');
    return res.status(429).json({ error: 'Terlalu banyak percobaan, coba lagi nanti' });
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  const ok = bcrypt.compareSync(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok) {
    addFail(username);
    log(req, `user:${username}`, null, 'deny', 'kredensial salah');
    return res.status(401).json({ error: 'Kredensial tidak valid' });
  }
  const dev = db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?').get(user.id, device);
  if (!dev) {
    log(req, `user:${user.id}`, user.role, 'deny', `device ${device} tidak terdaftar`);
    return res.status(403).json({ error: 'Device tidak terdaftar untuk user ini' });
  }
  fails.delete(username);
  log(req, `user:${user.id}`, user.role, 'allow', 'login berhasil');
  res.json({
    token_type: 'Bearer',
    access_token: tokens.signAccess(user),
    expires_in: 600,
    refresh_token: issueRefresh(user.id, device),
  });
});

// POST /auth/refresh : refresh token valid, belum dicabut, belum kedaluwarsa, device masih terdaftar
router.post('/refresh', (req, res) => {
  const t = (req.body || {}).refresh_token;
  if (typeof t !== 'string') {
    log(req, 'anonymous', null, 'deny', 'refresh_token tidak ada');
    return res.status(400).json({ error: 'refresh_token wajib diisi' });
  }
  const row = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(tokens.hashRefresh(t));
  const deny = (subject, role, reason) => {
    log(req, subject, role, 'deny', reason);
    return res.status(401).json({ error: 'Refresh token tidak valid' });
  };
  if (!row) return deny('anonymous', null, 'refresh token tidak dikenal');
  const subject = `user:${row.user_id}`;
  if (row.revoked) return deny(subject, null, 'refresh token sudah dicabut (kemungkinan dipakai ulang)');
  if (Date.now() > row.expires_at) return deny(subject, null, 'refresh token kedaluwarsa');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(row.user_id);
  const dev = user && db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?').get(user.id, row.device_id);
  if (!user || !dev) return deny(subject, null, 'user atau device sudah tidak terdaftar');

  // Rotasi: token lama dicabut, token baru diterbitkan.
  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?').run(row.id);
  log(req, subject, user.role, 'allow', 'refresh berhasil, refresh token dirotasi');
  res.json({
    token_type: 'Bearer',
    access_token: tokens.signAccess(user),
    expires_in: 600,
    refresh_token: issueRefresh(user.id, row.device_id),
  });
});

// POST /auth/logout : mencabut refresh token
router.post('/logout', (req, res) => {
  const t = (req.body || {}).refresh_token;
  const row = typeof t === 'string'
    ? db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(tokens.hashRefresh(t)) : null;
  if (!row || row.revoked || Date.now() > row.expires_at) {
    log(req, row ? `user:${row.user_id}` : 'anonymous', null, 'deny', 'refresh token tidak valid untuk logout');
    return res.status(401).json({ error: 'Refresh token tidak valid' });
  }
  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?').run(row.id);
  log(req, `user:${row.user_id}`, null, 'allow', 'logout, refresh token dicabut');
  res.json({ message: 'Logout berhasil, refresh token dicabut' });
});

// POST /auth/service : hanya Service Nilai dengan client ID + secret valid
router.post('/service', (req, res) => {
  const { client_id, client_secret } = req.body || {};
  const c = typeof client_id === 'string'
    ? db.prepare('SELECT * FROM service_clients WHERE client_id = ?').get(client_id) : null;
  const ok = bcrypt.compareSync(typeof client_secret === 'string' ? client_secret : '', c ? c.secret_hash : DUMMY_HASH);
  if (!c || !ok) {
    log(req, `service:${client_id || '?'}`, 'service', 'deny', 'client ID atau secret tidak valid');
    return res.status(401).json({ error: 'Kredensial service tidak valid' });
  }
  log(req, `service:${c.client_id}`, 'service', 'allow', 'token service diterbitkan');
  res.json({ token_type: 'Bearer', access_token: tokens.signService(c.client_id), expires_in: 300 });
});

module.exports = router;
