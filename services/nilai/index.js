'use strict';
// SERVICE NILAI - port 3001 (resource). Tidak dapat diakses langsung: wajib X-Gateway-Secret + token valid.
const express = require('express');
const cfg = require('../../config');
const db = require('../../shared/db');
const { serviceGuard, requireRole } = require('../../shared/serviceAuth');

cfg.requireSecrets();
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use(serviceGuard);

// ---- Token service untuk memanggil Service Transkrip melalui gateway -----------------------------
let cached = { token: null, exp: 0 };
async function getServiceToken() {
  if (cached.token && Date.now() < cached.exp - 30_000) return cached.token;
  const r = await fetch(`${cfg.urls.gateway}/auth/service`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: cfg.serviceClient.id, client_secret: cfg.serviceClient.secret }),
  });
  if (!r.ok) throw new Error(`gagal mengambil token service (${r.status})`);
  const j = await r.json();
  cached = { token: j.access_token, exp: Date.now() + j.expires_in * 1000 };
  return cached.token;
}

const isOwnClass = (kelasId, dosenId) => {
  const k = db.prepare('SELECT dosen_id FROM kelas WHERE id = ?').get(kelasId);
  return !!k && k.dosen_id === Number(dosenId);
};

// GET /nilai : mahasiswa -> hanya nilai miliknya; dosen -> hanya kelas yang diampu
app.get('/nilai', requireRole('mahasiswa', 'dosen'), (req, res) => {
  const base = `SELECT n.id, k.id AS kelas_id, k.kode, k.nama AS kelas, u.nim, u.nama AS mahasiswa, n.nilai, n.final
                FROM nilai n JOIN kelas k ON k.id = n.kelas_id JOIN users u ON u.id = n.mahasiswa_id`;
  let rows;
  if (req.auth.role === 'mahasiswa') {
    rows = db.prepare(`${base} WHERE n.mahasiswa_id = ?`).all(req.auth.sub);
  } else if (req.query.kelas_id !== undefined) {
    rows = db.prepare(`${base} WHERE k.dosen_id = ? AND k.id = ?`).all(req.auth.sub, req.query.kelas_id);
  } else {
    rows = db.prepare(`${base} WHERE k.dosen_id = ?`).all(req.auth.sub);
  }
  res.json({ data: rows });
});

// PUT /nilai/:id : body { "nilai": 0..100 }
app.put('/nilai/:id', requireRole('dosen'), (req, res) => {
  const n = db.prepare('SELECT * FROM nilai WHERE id = ?').get(req.params.id);
  if (!n) return res.status(404).json({ error: 'Nilai tidak ditemukan' });
  if (!isOwnClass(n.kelas_id, req.auth.sub)) return res.status(403).json({ error: 'Bukan kelas yang diampu' });
  if (n.final) return res.status(403).json({ error: 'Nilai sudah final' });
  const v = req.body && req.body.nilai;
  if (typeof v !== 'number' || !Number.isFinite(v) || v < 0 || v > 100) {
    return res.status(400).json({ error: 'nilai harus angka 0 sampai 100' });
  }
  db.prepare('UPDATE nilai SET nilai = ? WHERE id = ?').run(v, n.id);
  res.json({ message: 'Nilai diperbarui', id: n.id, nilai: v });
});

// POST /kelas/:id/finalisasi : finalisasi lalu sinkron ke Service Transkrip LEWAT GATEWAY
app.post('/kelas/:id/finalisasi', requireRole('dosen'), async (req, res) => {
  const kelasId = Number(req.params.id);
  if (!isOwnClass(kelasId, req.auth.sub)) return res.status(403).json({ error: 'Bukan kelas yang diampu' });

  const pending = db.prepare('SELECT id FROM nilai WHERE kelas_id = ? AND final = 0').all(kelasId).map((r) => r.id);
  const mark = db.prepare('UPDATE nilai SET final = ? WHERE id = ?');
  db.transaction((ids, val) => ids.forEach((id) => mark.run(val, id)))(pending, 1);

  try {
    const items = db.prepare('SELECT mahasiswa_id, nilai FROM nilai WHERE kelas_id = ?').all(kelasId);
    const token = await getServiceToken();
    const r = await fetch(`${cfg.urls.gateway}/transkrip/sinkron`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ kelas_id: kelasId, items }),
    });
    if (!r.ok) throw new Error(`sinkron transkrip ditolak (${r.status})`);
    res.json({ message: 'Kelas difinalisasi dan transkrip tersinkron', kelas_id: kelasId, jumlah_nilai: items.length });
  } catch (e) {
    // Konsistensi: bila sinkron gagal, finalisasi dibatalkan
    db.transaction((ids) => ids.forEach((id) => mark.run(0, id)))(pending);
    res.status(502).json({ error: 'Finalisasi dibatalkan', detail: e.message });
  }
});

app.use((req, res) => res.status(404).json({ error: 'Tidak ditemukan' }));
app.listen(cfg.ports.nilai, '127.0.0.1', () => console.log(`[nilai] Service Nilai berjalan di port ${cfg.ports.nilai}`));
