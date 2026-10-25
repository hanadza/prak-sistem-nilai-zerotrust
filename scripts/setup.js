'use strict';
// Membuat pasangan kunci RS256 dan .env berisi rahasia acak (tidak ada rahasia di kode), lalu seed database.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const root = path.join(__dirname, '..');

const keyDir = path.join(root, 'keys');
fs.mkdirSync(keyDir, { recursive: true });
if (!fs.existsSync(path.join(keyDir, 'private.pem'))) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  fs.writeFileSync(path.join(keyDir, 'private.pem'), privateKey, { mode: 0o600 });
  fs.writeFileSync(path.join(keyDir, 'public.pem'), publicKey);
  console.log('Kunci RS256 dibuat di keys/');
}

const envPath = path.join(root, '.env');
if (!fs.existsSync(envPath)) {
  const env = [
    `GATEWAY_SECRET=${crypto.randomBytes(32).toString('hex')}`,
    `NILAI_CLIENT_ID=service-nilai`,
    `NILAI_CLIENT_SECRET=${crypto.randomBytes(32).toString('hex')}`,
    `ACCESS_START_HOUR=7`,
    `ACCESS_END_HOUR=21`,
    '',
  ].join('\n');
  fs.writeFileSync(envPath, env, { mode: 0o600 });
  console.log('.env dibuat dengan rahasia acak');
}
require('./seed');
