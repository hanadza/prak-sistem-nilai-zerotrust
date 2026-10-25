'use strict';
// Data awal: 1 admin, 2 dosen, 3 mahasiswa, 2 kelas (dosen berbeda), tiap user 1 device terdaftar.
const bcrypt = require('bcryptjs');
const cfg = require('../config');
const db = require('../shared/db');

if (!cfg.serviceClient.secret) throw new Error('NILAI_CLIENT_SECRET belum ada. Jalankan "npm run setup".');
db.resetSchema();

const hash = (p) => bcrypt.hashSync(p, 10);
const addUser = db.prepare('INSERT INTO users (username, password_hash, role, nama, nim) VALUES (?, ?, ?, ?, ?)');
const addDev = db.prepare('INSERT INTO devices (user_id, device_id) VALUES (?, ?)');

const users = [
  ['admin',  'Admin#2026',  'admin',     'Admin Prodi',        null,      'DEV-ADMIN-01'],
  ['dosen1', 'Dosen1#2026', 'dosen',     'Dr. Budi Santoso',   null,      'DEV-DOSEN-01'],
  ['dosen2', 'Dosen2#2026', 'dosen',     'Dr. Sari Lestari',   null,      'DEV-DOSEN-02'],
  ['mhs1',   'Mhs1#2026',   'mahasiswa', 'Andi Pratama',       '247001',  'DEV-MHS-01'],
  ['mhs2',   'Mhs2#2026',   'mahasiswa', 'Bella Anggraini',    '247002',  'DEV-MHS-02'],
  ['mhs3',   'Mhs3#2026',   'mahasiswa', 'Citra Dewi',         '247003',  'DEV-MHS-03'],
];
const id = {};
db.transaction(() => {
  for (const [u, p, role, nama, nim, dev] of users) {
    id[u] = addUser.run(u, hash(p), role, nama, nim).lastInsertRowid;
    addDev.run(id[u], dev);
  }
  const addKelas = db.prepare('INSERT INTO kelas (kode, nama, dosen_id) VALUES (?, ?, ?)');
  const k1 = addKelas.run('IF301', 'Keamanan Informasi', id.dosen1).lastInsertRowid;
  const k2 = addKelas.run('IF302', 'Basis Data', id.dosen2).lastInsertRowid;
  const addNilai = db.prepare('INSERT INTO nilai (kelas_id, mahasiswa_id, nilai) VALUES (?, ?, ?)');
  addNilai.run(k1, id.mhs1, 80); addNilai.run(k1, id.mhs2, 75); addNilai.run(k1, id.mhs3, 90);
  addNilai.run(k2, id.mhs1, 85); addNilai.run(k2, id.mhs3, 70);
  db.prepare('INSERT INTO service_clients (client_id, secret_hash) VALUES (?, ?)')
    .run(cfg.serviceClient.id, hash(cfg.serviceClient.secret));
})();
console.log('Seed selesai. Lihat README untuk daftar akun dan device ID.');
