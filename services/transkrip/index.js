'use strict';
// SERVICE TRANSKRIP - port 3002 (resource). Tidak dapat diakses langsung.
const express = require('express');
const cfg = require('../../config');
const db = require('../../shared/db');
const { serviceGuard, requireRole } = require('../../shared/serviceAuth');

cfg.requireSecrets();
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(serviceGuard);

// GET /transkrip/:nim : mahasiswa hanya NIM sendiri; admin semua NIM
app.get('/transkrip/:nim', requireRole('mahasiswa', 'admin'), (req, res) => {
  const mhs = db.prepare(`SELECT id, nim, nama FROM users WHERE nim = ? AND role = 'mahasiswa'`).get(req.params.nim);
  if (req.auth.role === 'mahasiswa' && (!mhs || String(mhs.id) !== req.auth.sub)) {
    return res.status(403).json({ error: 'Hanya boleh melihat transkrip sendiri' });
  }
  if (!mhs) return res.status(404).json({ error: 'Mahasiswa tidak ditemukan' });
  const rows = db.prepare(`SELECT k.kode, k.nama AS mata_kuliah, t.nilai, t.updated_at
                           FROM transkrip t JOIN kelas k ON k.id = t.kelas_id
                           WHERE t.mahasiswa_id = ? ORDER BY k.kode`).all(mhs.id);
  const rata = rows.length ? rows.reduce((s, r) => s + r.nilai, 0) / rows.length : null;
  res.json({ nim: mhs.nim, nama: mhs.nama, transkrip: rows, rata_rata: rata });
});

// POST /transkrip/sinkron : HANYA token service (jenis token diperiksa ulang di sini)
app.post('/transkrip/sinkron', (req, res) => {
  if (req.auth.typ !== 'service' || req.auth.role !== 'service') {
    return res.status(403).json({ error: 'Hanya token service yang diizinkan' });
  }
  const { kelas_id, items } = req.body || {};
  if (!Number.isInteger(kelas_id) || !Array.isArray(items) || items.length === 0 || items.length > 500) {
    return res.status(400).json({ error: 'kelas_id dan items wajib valid' });
  }
  if (!db.prepare('SELECT 1 FROM kelas WHERE id = ?').get(kelas_id)) return res.status(404).json({ error: 'Kelas tidak ditemukan' });
  for (const it of items) {
    if (!Number.isInteger(it.mahasiswa_id) || typeof it.nilai !== 'number' || it.nilai < 0 || it.nilai > 100) {
      return res.status(400).json({ error: 'item tidak valid' });
    }
  }
  const up = db.prepare(`INSERT INTO transkrip (mahasiswa_id, kelas_id, nilai, updated_at) VALUES (?, ?, ?, ?)
                         ON CONFLICT (mahasiswa_id, kelas_id) DO UPDATE SET nilai = excluded.nilai, updated_at = excluded.updated_at`);
  const now = new Date().toISOString();
  try {
    db.transaction(() => items.forEach((it) => up.run(it.mahasiswa_id, kelas_id, it.nilai, now)))();
  } catch (e) {
    return res.status(400).json({ error: 'Data mahasiswa tidak valid' });
  }
  res.json({ message: 'Transkrip disinkronkan', kelas_id, jumlah: items.length });
});

app.use((req, res) => res.status(404).json({ error: 'Tidak ditemukan' }));
app.listen(cfg.ports.transkrip, '127.0.0.1', () => console.log(`[transkrip] Service Transkrip berjalan di port ${cfg.ports.transkrip}`));
