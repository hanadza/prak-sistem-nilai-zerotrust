'use strict';
// POLICY ENGINE (PE). Menerima konteks permintaan lalu mengembalikan { allow, reason, status }.
// Atribut kepemilikan (kelas yang diampu, NIM milik mahasiswa, status final) dibaca dari database,
// bukan dari isi token, karena token tidak boleh dipercaya untuk data yang bisa berubah.
// Prinsip: DEFAULT DENY. Endpoint tanpa aturan otomatis ditolak.
const db = require('../shared/db');
const cfg = require('../config');

const allow = (reason) => ({ allow: true, reason });
const deny = (reason, status = 403) => ({ allow: false, reason, status });

// Verifikasi konteks: jam akses (rentang dari konfigurasi)
function withinAccessHours(now = new Date()) {
  const h = now.getHours() + now.getMinutes() / 60;
  return h >= cfg.access.startHour && h < cfg.access.endHour;
}
const hoursReason = () => `di luar jam akses ${String(cfg.access.startHour).padStart(2, '0')}.00-${String(cfg.access.endHour).padStart(2, '0')}.00`;

const getKelas = (id) => db.prepare('SELECT * FROM kelas WHERE id = ?').get(id);
const getNilai = (id) => db.prepare('SELECT * FROM nilai WHERE id = ?').get(id);

// ---- Aturan per endpoint (Tabel 3) -------------------------------------------------------------
const rules = [
  {
    method: 'GET', re: /^\/nilai\/?$/,
    decide({ subject, user, query }) {
      if (subject.role === 'mahasiswa') {
        if (query.nim && query.nim !== user.nim) return deny('mahasiswa hanya boleh melihat nilai miliknya sendiri');
        return allow('mahasiswa melihat nilai miliknya');
      }
      if (subject.role === 'dosen') {
        if (query.kelas_id !== undefined) {
          const k = getKelas(query.kelas_id);
          if (!k || k.dosen_id !== user.id) return deny('kelas bukan kelas yang diampu dosen');
        }
        return allow('dosen melihat nilai kelas yang diampunya');
      }
      return deny(`role ${subject.role} tidak diizinkan melihat nilai`);
    },
  },
  {
    method: 'PUT', re: /^\/nilai\/(\d+)\/?$/,
    decide({ subject, user, params, now }) {
      if (subject.role !== 'dosen') return deny(`role ${subject.role} tidak boleh mengubah nilai`);
      const n = getNilai(params[0]);
      if (!n) return deny('data nilai tidak ditemukan', 404);
      const k = getKelas(n.kelas_id);
      if (!k || k.dosen_id !== user.id) return deny('nilai bukan milik kelas yang diampu dosen');
      if (n.final) return deny('nilai sudah final dan tidak dapat diubah');
      if (!withinAccessHours(now)) return deny(`ubah nilai ${hoursReason()}`);
      return allow('dosen mengubah nilai kelas yang diampu, belum final, dalam jam akses');
    },
  },
  {
    method: 'POST', re: /^\/kelas\/(\d+)\/finalisasi\/?$/,
    decide({ subject, user, params, now }) {
      if (subject.role !== 'dosen') return deny(`role ${subject.role} tidak boleh memfinalisasi nilai`);
      const k = getKelas(params[0]);
      if (!k) return deny('kelas tidak ditemukan', 404);
      if (k.dosen_id !== user.id) return deny('kelas bukan kelas yang diampu dosen');
      if (!withinAccessHours(now)) return deny(`finalisasi ${hoursReason()}`);
      return allow('dosen memfinalisasi kelas yang diampu dalam jam akses');
    },
  },
  {
    method: 'GET', re: /^\/transkrip\/([A-Za-z0-9]+)\/?$/,
    decide({ subject, user, params }) {
      if (subject.role === 'admin') return allow('admin melihat transkrip seluruh mahasiswa');
      if (subject.role === 'mahasiswa') {
        return user.nim === params[0]
          ? allow('mahasiswa melihat transkrip miliknya')
          : deny('mahasiswa hanya boleh melihat transkrip dengan NIM sendiri');
      }
      return deny(`role ${subject.role} tidak diizinkan melihat transkrip`);
    },
  },
  {
    method: 'POST', re: /^\/transkrip\/sinkron\/?$/,
    decide({ subject }) {
      if (subject.typ !== 'service' || subject.role !== 'service') {
        return deny('sinkron transkrip hanya untuk token service, token user ditolak');
      }
      if (subject.sub !== cfg.serviceClient.id) return deny('service tidak dikenal');
      return allow('Service Nilai menyinkronkan transkrip');
    },
  },
];

exports.decide = ({ subject, user, method, path, query, now = new Date() }) => {
  for (const r of rules) {
    if (r.method !== method) continue;
    const m = r.re.exec(path);
    if (m) return r.decide({ subject, user, params: m.slice(1), query, now });
  }
  return deny('tidak ada kebijakan untuk endpoint ini (default deny)', 404);
};
exports.withinAccessHours = withinAccessHours;
