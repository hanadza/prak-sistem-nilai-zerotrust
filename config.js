'use strict';
// Konfigurasi terpusat. Semua rahasia dibaca dari .env / environment, tidak ditulis di kode.
const path = require('path');
const fs = require('fs');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const int = (v, d) => (v === undefined || v === '' ? d : parseInt(v, 10));
const ports = {
  gateway: int(process.env.GATEWAY_PORT, 3000),
  nilai: int(process.env.NILAI_PORT, 3001),
  transkrip: int(process.env.TRANSKRIP_PORT, 3002),
};

const config = {
  ports,
  urls: {
    gateway: `http://127.0.0.1:${ports.gateway}`,
    nilai: `http://127.0.0.1:${ports.nilai}`,
    transkrip: `http://127.0.0.1:${ports.transkrip}`,
  },
  dbPath: process.env.DB_PATH || path.join(__dirname, 'data', 'sistem.db'),
  gatewaySecret: process.env.GATEWAY_SECRET,
  serviceClient: {
    id: process.env.NILAI_CLIENT_ID || 'service-nilai',
    secret: process.env.NILAI_CLIENT_SECRET,
  },
  jwt: {
    issuer: 'zt-gateway',
    audience: 'sistem-nilai',
    accessTtl: '10m',            // access token user: 10 menit
    serviceTtl: '5m',            // token service: 5 menit
    refreshTtlMs: 24 * 60 * 60 * 1000, // refresh token: 1 hari
  },
  // Jam akses perubahan/finalisasi nilai (jam lokal server). Dapat diubah agar mudah didemokan.
  access: {
    startHour: int(process.env.ACCESS_START_HOUR, 7),
    endHour: int(process.env.ACCESS_END_HOUR, 21),
  },
  keyPaths: {
    private: path.join(__dirname, 'keys', 'private.pem'),
    public: path.join(__dirname, 'keys', 'public.pem'),
  },
  readKey(kind) { return fs.readFileSync(this.keyPaths[kind]); },
  requireSecrets() {
    if (!this.gatewaySecret) {
      throw new Error('GATEWAY_SECRET belum diatur. Jalankan "npm run setup" terlebih dahulu.');
    }
  },
};

module.exports = config;
