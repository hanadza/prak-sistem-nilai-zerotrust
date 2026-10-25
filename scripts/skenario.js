'use strict';
// Uji skenario otomatis terhadap gateway yang sedang berjalan (jalankan "npm run seed" dulu agar data bersih).
// Hasil yang diharapkan untuk jam akses dihitung dari konfigurasi yang sama dengan server.
const cfg = require('../config');
const policy = require('../gateway/policy');

const GW = cfg.urls.gateway;
const inHours = policy.withinAccessHours();
let pass = 0, failN = 0;

async function call(method, path, { token, device, body, headers = {}, base = GW } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  if (device) h['X-Device-ID'] = device;
  if (body) h['Content-Type'] = 'application/json';
  const r = await fetch(base + path, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
  let j = null; try { j = await r.json(); } catch (e) { /* kosong */ }
  return { status: r.status, body: j };
}
function check(nama, cond, info = '') {
  cond ? pass++ : failN++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${nama}${cond ? '' : '  -> ' + info}`);
}
const login = async (u, p, d) => (await call('POST', '/auth/login', { body: { username: u, password: p }, device: d }));

(async () => {
  console.log(`Jam akses ${cfg.access.startHour}-${cfg.access.endHour}, sekarang ${inHours ? 'DI DALAM' : 'DI LUAR'} jam akses\n`);

  // ---- Autentikasi dan device
  let r = await login('mhs1', 'Mhs1#2026', 'DEV-MHS-01'); const mhs1 = r.body;
  check('login mahasiswa dengan device terdaftar', r.status === 200 && mhs1.access_token && mhs1.refresh_token, JSON.stringify(r));
  r = await login('mhs1', 'salah', 'DEV-MHS-01'); check('login password salah ditolak (401)', r.status === 401, r.status);
  r = await login('mhs1', 'Mhs1#2026', 'DEV-MHS-02'); check('login dari device tidak terdaftar ditolak (403)', r.status === 403, r.status);
  r = await login('mhs1', 'Mhs1#2026', undefined); check('login tanpa X-Device-ID ditolak (400)', r.status === 400, r.status);
  const dosen1 = (await login('dosen1', 'Dosen1#2026', 'DEV-DOSEN-01')).body;
  const dosen2 = (await login('dosen2', 'Dosen2#2026', 'DEV-DOSEN-02')).body;
  const admin = (await login('admin', 'Admin#2026', 'DEV-ADMIN-01')).body;
  const mhs2 = (await login('mhs2', 'Mhs2#2026', 'DEV-MHS-02')).body;

  // ---- Zero trust di gateway dan service
  r = await call('GET', '/nilai'); check('tanpa token ditolak (401)', r.status === 401, r.status);
  r = await call('GET', '/nilai', { token: mhs1.access_token + 'x', device: 'DEV-MHS-01' }); check('token dirusak ditolak (401)', r.status === 401, r.status);
  r = await call('GET', '/nilai', { token: mhs1.access_token, device: 'DEV-MHS-02' }); check('token sah tapi device milik orang lain ditolak (403)', r.status === 403, r.status);
  r = await call('GET', '/nilai', { token: mhs1.access_token }); check('request user tanpa X-Device-ID ditolak (403)', r.status === 403, r.status);
  r = await call('GET', '/nilai', { base: cfg.urls.nilai, token: mhs1.access_token }); check('akses langsung ke Service Nilai tanpa gateway secret ditolak (403)', r.status === 403, r.status);
  r = await call('GET', '/nilai', { base: cfg.urls.nilai, headers: { 'X-Gateway-Secret': cfg.gatewaySecret } }); check('gateway secret tanpa token tetap ditolak (401)', r.status === 401, r.status);
  r = await call('GET', '/nilai', { base: cfg.urls.nilai, headers: { 'X-Gateway-Secret': cfg.gatewaySecret }, token: 'a.b.c' }); check('gateway secret + token palsu ditolak (401)', r.status === 401, r.status);
  r = await call('GET', '/transkrip/247001', { base: cfg.urls.transkrip }); check('akses langsung ke Service Transkrip ditolak (403)', r.status === 403, r.status);
  r = await call('GET', '/nilai', { token: mhs1.access_token, device: 'DEV-MHS-01', headers: { 'X-Gateway-Secret': 'palsu' } });
  check('X-Gateway-Secret kiriman klien ditimpa gateway (request sah tetap 200)', r.status === 200, r.status);

  // ---- GET /nilai
  r = await call('GET', '/nilai', { token: mhs1.access_token, device: 'DEV-MHS-01' });
  check('mahasiswa hanya melihat nilai miliknya', r.status === 200 && r.body.data.length === 2 && r.body.data.every((x) => x.nim === '247001'), JSON.stringify(r.body));
  r = await call('GET', '/nilai?nim=247002', { token: mhs1.access_token, device: 'DEV-MHS-01' }); check('mahasiswa meminta nilai NIM lain ditolak (403)', r.status === 403, r.status);
  r = await call('GET', '/nilai', { token: dosen1.access_token, device: 'DEV-DOSEN-01' });
  check('dosen hanya melihat kelas yang diampu (IF301, 3 baris)', r.status === 200 && r.body.data.length === 3 && r.body.data.every((x) => x.kode === 'IF301'), JSON.stringify(r.body));
  r = await call('GET', '/nilai?kelas_id=2', { token: dosen1.access_token, device: 'DEV-DOSEN-01' }); check('dosen meminta kelas yang tidak diampu ditolak (403)', r.status === 403, r.status);
  r = await call('GET', '/nilai', { token: admin.access_token, device: 'DEV-ADMIN-01' }); check('admin tidak boleh GET /nilai (403)', r.status === 403, r.status);

  // ---- PUT /nilai/:id
  const list1 = (await call('GET', '/nilai', { token: dosen1.access_token, device: 'DEV-DOSEN-01' })).body.data;
  const target = list1.find((x) => x.nim === '247001').id;
  r = await call('PUT', `/nilai/${target}`, { token: mhs1.access_token, device: 'DEV-MHS-01', body: { nilai: 100 } }); check('mahasiswa mengubah nilai ditolak (403)', r.status === 403, r.status);
  r = await call('PUT', `/nilai/${target}`, { token: dosen2.access_token, device: 'DEV-DOSEN-02', body: { nilai: 100 } }); check('dosen lain mengubah nilai kelas yang bukan miliknya ditolak (403)', r.status === 403, r.status);
  r = await call('PUT', `/nilai/${target}`, { token: dosen1.access_token, device: 'DEV-DOSEN-01', body: { nilai: 88 } });
  check(inHours ? 'dosen mengubah nilai di dalam jam akses diizinkan (200)' : 'dosen mengubah nilai di luar jam akses ditolak (403)',
    inHours ? r.status === 200 : r.status === 403, `${r.status} ${JSON.stringify(r.body)}`);

  // ---- Finalisasi dan sinkron transkrip
  r = await call('POST', '/kelas/1/finalisasi', { token: dosen2.access_token, device: 'DEV-DOSEN-02' }); check('dosen lain memfinalisasi kelas yang bukan miliknya ditolak (403)', r.status === 403, r.status);
  r = await call('POST', '/kelas/1/finalisasi', { token: mhs1.access_token, device: 'DEV-MHS-01' }); check('mahasiswa memfinalisasi ditolak (403)', r.status === 403, r.status);
  r = await call('POST', '/kelas/1/finalisasi', { token: dosen1.access_token, device: 'DEV-DOSEN-01' });
  check(inHours ? 'finalisasi kelas sendiri di dalam jam akses berhasil (200)' : 'finalisasi di luar jam akses ditolak (403)',
    inHours ? r.status === 200 : r.status === 403, `${r.status} ${JSON.stringify(r.body)}`);
  if (inHours) {
    r = await call('PUT', `/nilai/${target}`, { token: dosen1.access_token, device: 'DEV-DOSEN-01', body: { nilai: 50 } }); check('nilai yang sudah final tidak dapat diubah (403)', r.status === 403, r.status);
  }

  // ---- GET /transkrip/:nim
  r = await call('GET', '/transkrip/247001', { token: mhs1.access_token, device: 'DEV-MHS-01' });
  check('mahasiswa melihat transkrip sendiri (200)', r.status === 200, r.status);
  if (inHours) check('transkrip berisi nilai hasil sinkron dari finalisasi', r.body.transkrip.some((t) => t.kode === 'IF301' && t.nilai === 88), JSON.stringify(r.body));
  r = await call('GET', '/transkrip/247002', { token: mhs1.access_token, device: 'DEV-MHS-01' }); check('mahasiswa melihat transkrip NIM lain ditolak (403)', r.status === 403, r.status);
  r = await call('GET', '/transkrip/247002', { token: admin.access_token, device: 'DEV-ADMIN-01' }); check('admin melihat transkrip semua NIM (200)', r.status === 200, r.status);
  r = await call('GET', '/transkrip/247001', { token: dosen1.access_token, device: 'DEV-DOSEN-01' }); check('dosen melihat transkrip ditolak (403)', r.status === 403, r.status);

  // ---- POST /transkrip/sinkron hanya token service
  const syncBody = { kelas_id: 1, items: [{ mahasiswa_id: 4, nilai: 100 }] };
  for (const [nama, who, dev] of [['admin', admin, 'DEV-ADMIN-01'], ['dosen', dosen1, 'DEV-DOSEN-01'], ['mahasiswa', mhs2, 'DEV-MHS-02']]) {
    r = await call('POST', '/transkrip/sinkron', { token: who.access_token, device: dev, body: syncBody });
    check(`token user (${nama}) pada /transkrip/sinkron ditolak (403)`, r.status === 403, r.status);
  }
  r = await call('POST', '/auth/service', { body: { client_id: cfg.serviceClient.id, client_secret: 'salah' } }); check('/auth/service dengan secret salah ditolak (401)', r.status === 401, r.status);
  r = await call('POST', '/auth/service', { body: { client_id: cfg.serviceClient.id, client_secret: cfg.serviceClient.secret } });
  check('/auth/service dengan kredensial benar menerbitkan token service', r.status === 200 && r.body.expires_in === 300, JSON.stringify(r));
  const svc = r.body && r.body.access_token;
  r = await call('POST', '/transkrip/sinkron', { token: svc, body: { kelas_id: 1, items: [{ mahasiswa_id: 4, nilai: 88 }] } }); check('token service pada /transkrip/sinkron diizinkan (200)', r.status === 200, `${r.status} ${JSON.stringify(r.body)}`);
  r = await call('GET', '/nilai', { token: svc }); check('token service tidak dapat dipakai pada endpoint user (403)', r.status === 403, r.status);

  // ---- Refresh dan logout
  r = await call('POST', '/auth/refresh', { body: { refresh_token: mhs1.refresh_token } });
  check('refresh token valid menerbitkan access token baru', r.status === 200 && r.body.access_token, r.status);
  const rotated = r.body;
  r = await call('POST', '/auth/refresh', { body: { refresh_token: mhs1.refresh_token } }); check('refresh token lama (sudah dirotasi) ditolak (401)', r.status === 401, r.status);
  r = await call('POST', '/auth/logout', { body: { refresh_token: rotated.refresh_token } }); check('logout mencabut refresh token (200)', r.status === 200, r.status);
  r = await call('POST', '/auth/refresh', { body: { refresh_token: rotated.refresh_token } }); check('refresh setelah logout ditolak (401)', r.status === 401, r.status);

  // ---- Default deny
  r = await call('GET', '/admin/rahasia', { token: admin.access_token, device: 'DEV-ADMIN-01' }); check('endpoint tanpa kebijakan ditolak (default deny)', r.status === 404, r.status);

  console.log(`\nRingkasan: ${pass} lulus, ${failN} gagal`);
  process.exit(failN ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
