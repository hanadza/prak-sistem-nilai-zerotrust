'use strict';
// API GATEWAY (PEP) - port 3000. Satu-satunya pintu masuk ke Service Nilai dan Service Transkrip.
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cfg = require('../config');
const audit = require('./audit');
const pep = require('./pep');
const authRoutes = require('./authRoutes');

cfg.requireSecrets();
const app = express();
app.disable('x-powered-by');

app.get('/health', (req, res) => res.json({ status: 'ok', role: 'gateway' }));
app.use('/auth', authRoutes);

// Gateway menambahkan X-Gateway-Secret; nilai kiriman klien selalu ditimpa.
const forward = (target) => createProxyMiddleware({
  target,
  // Express memotong prefix mount (/nilai, /kelas, ...); kembalikan path asli ke service.
  pathRewrite: (path, req) => req.originalUrl,
  on: {
    proxyReq: (proxyReq) => proxyReq.setHeader('X-Gateway-Secret', cfg.gatewaySecret),
    error: (err, req, res) => {
      console.error('[PROXY ERROR]', err.message);
      if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Service tidak dapat dihubungi' }));
    },
  },
});

app.use('/nilai', pep, forward(cfg.urls.nilai));
app.use('/kelas', pep, forward(cfg.urls.nilai));
app.use('/transkrip', pep, forward(cfg.urls.transkrip));

// Selain di atas: ditolak (default deny)
app.use((req, res) => {
  audit.record({ subject: 'anonymous', role: null, req, result: 'deny', reason: 'endpoint tidak dikenal' });
  res.status(404).json({ error: 'Endpoint tidak ditemukan' });
});

app.listen(cfg.ports.gateway, () => console.log(`[gateway] PEP berjalan di port ${cfg.ports.gateway}`));
