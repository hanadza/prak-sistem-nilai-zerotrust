'use strict';
// Policy Administrator: penerbitan token. Hanya gateway yang memegang kunci privat.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cfg = require('../config');

const privateKey = cfg.readKey('private');
const publicKey = cfg.readKey('public');
const base = { algorithm: 'RS256', issuer: cfg.jwt.issuer, audience: cfg.jwt.audience };

exports.signAccess = (user) =>
  jwt.sign({ sub: String(user.id), role: user.role, typ: 'access' }, privateKey,
    { ...base, expiresIn: cfg.jwt.accessTtl });

exports.signService = (clientId) =>
  jwt.sign({ sub: clientId, role: 'service', typ: 'service' }, privateKey,
    { ...base, expiresIn: cfg.jwt.serviceTtl });

exports.verify = (token) =>
  jwt.verify(token, publicKey, { algorithms: ['RS256'], issuer: cfg.jwt.issuer, audience: cfg.jwt.audience });

exports.newRefreshToken = () => crypto.randomBytes(48).toString('base64url');
// Refresh token disimpan sebagai hash, sehingga kebocoran database tidak membocorkan token aktif.
exports.hashRefresh = (t) => crypto.createHash('sha256').update(t).digest('hex');
