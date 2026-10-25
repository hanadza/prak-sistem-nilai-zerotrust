# Sistem Nilai Zero Trust

Praktikum Zero Trust Security, Keamanan Informasi (KP70065004), Informatika Universitas Siliwangi.
Implementasi API gateway sebagai Policy Enforcement Point (PEP) sesuai NIST SP 800-207, dengan prinsip never trust always verify, least privilege, dan assume breach.

## Arsitektur

Klien hanya berbicara dengan gateway (port 3000). Gateway memeriksa token, device, dan kebijakan, mencatat audit log, lalu meneruskan request ke service dengan header X-Gateway-Secret. Service memverifikasi ulang secret dan token, sehingga tidak bisa diakses langsung. Panggilan Service Nilai ke Service Transkrip juga lewat gateway memakai token service.

| Komponen | Port | Peran NIST | Berkas |
|---|---|---|---|
| API Gateway | 3000 | PEP | gateway/index.js, gateway/pep.js |
| Policy Engine / Administrator | di gateway | PE / PA | gateway/policy.js, gateway/authRoutes.js, gateway/tokens.js |
| Service Nilai | 3001 | Resource | services/nilai/index.js |
| Service Transkrip | 3002 | Resource | services/transkrip/index.js |
| Database SQLite bersama | - | Resource | shared/db.js |
| Audit log | tabel audit_log | Data source | gateway/audit.js |

Keputusan desain: token memakai RS256. Hanya gateway memegang kunci privat, service hanya memegang kunci publik, sehingga service yang jebol tidak dapat memalsukan token. Rahasia (GATEWAY_SECRET, secret client service, kunci) dibuat acak oleh `npm run setup` dan tidak ada di kode maupun repositori.

## Menjalankan

Kebutuhan: Node.js 18 atau lebih baru.

```
npm install
npm run setup     # persiapan pertama kali: kunci, .env, dan data awal
npm start         # jalankan gateway + dua service
```

`npm run setup` membuat kunci dan `.env`, lalu mengisi ulang database. Jalankan hanya saat persiapan pertama kali; untuk memulai ulang server cukup jalankan `npm start`.

Aplikasi ini menyediakan API, bukan halaman web. Untuk mengecek gateway di browser, buka `http://localhost:3000/health`. Pengujian endpoint gunakan `curl` atau Postman; request user harus melalui gateway di port 3000.

Perintah lain: `npm run seed` (menghapus dan membuat ulang data awal), `npm run skenario` (uji otomatis), `npm run audit` (lihat audit log).

Jam akses diatur lewat .env (ACCESS_START_HOUR dan ACCESS_END_HOUR, jam lokal server, bawaan 7 sampai 21). Untuk demo di luar jam, ubah nilainya lalu jalankan ulang, misalnya `ACCESS_START_HOUR=0 ACCESS_END_HOUR=0 npm start` membuat semua ubah/finalisasi ditolak.

## Akun dan device ID (seed)

| Username | Password | Role | Device ID | Catatan |
|---|---|---|---|---|
| admin | Admin#2026 | admin | DEV-ADMIN-01 | |
| dosen1 | Dosen1#2026 | dosen | DEV-DOSEN-01 | mengampu IF301 (kelas id 1) |
| dosen2 | Dosen2#2026 | dosen | DEV-DOSEN-02 | mengampu IF302 (kelas id 2) |
| mhs1 | Mhs1#2026 | mahasiswa | DEV-MHS-01 | NIM 247001, di IF301 dan IF302 |
| mhs2 | Mhs2#2026 | mahasiswa | DEV-MHS-02 | NIM 247002, di IF301 |
| mhs3 | Mhs3#2026 | mahasiswa | DEV-MHS-03 | NIM 247003, di IF301 dan IF302 |

Client service: ID `service-nilai`, secret ada di berkas .env (NILAI_CLIENT_SECRET).

## Contoh pengujian dengan curl

Jalankan contoh berikut di terminal kedua saat server aktif. Login menghasilkan access token dan menyimpannya ke variabel `TOKEN`; gunakan terminal yang sama untuk request berikutnya.

```
# login (device wajib terdaftar)
TOKEN=$(curl -sS -X POST localhost:3000/auth/login \
	-H "Content-Type: application/json" \
	-H "X-Device-ID: DEV-DOSEN-01" \
	-d '{"username":"dosen1","password":"Dosen1#2026"}' \
	| node -pe "JSON.parse(require('fs').readFileSync(0,'utf8')).access_token")

# lihat nilai kelas yang diampu
curl -s localhost:3000/nilai -H "Authorization: Bearer $TOKEN" -H "X-Device-ID: DEV-DOSEN-01"

# ubah nilai
curl -s -X PUT localhost:3000/nilai/1 -H "Authorization: Bearer $TOKEN" -H "X-Device-ID: DEV-DOSEN-01" -H "Content-Type: application/json" -d '{"nilai":88}'

# finalisasi kelas (otomatis sinkron ke transkrip lewat gateway)
curl -s -X POST localhost:3000/kelas/1/finalisasi -H "Authorization: Bearer $TOKEN" -H "X-Device-ID: DEV-DOSEN-01"

# akses langsung ke service harus gagal (403)
curl -s localhost:3001/nilai
```

### Uji otomatis

Uji otomatis mengubah nilai, memfinalisasi kelas, menyinkronkan transkrip, dan menambah audit log. Jalankan pada data yang boleh di-reset:

1. Hentikan server jika sedang berjalan.
2. Dari folder `sistem-nilai-zerotrust`, jalankan `npm run seed`. Perintah ini menghapus data database saat ini dan membuat ulang data awal.
3. Jalankan `npm start`, lalu biarkan server aktif.
4. Buka terminal kedua di folder yang sama dan jalankan `npm run skenario`.

Uji selesai jika ringkasan menunjukkan `0 gagal`. Jam akses dibaca dari konfigurasi `.env`; skenario menyesuaikan hasil uji ubah/finalisasi dengan jam tersebut.

## Pemetaan kebutuhan ke kode (untuk video demo)

| Kebutuhan | Lokasi |
|---|---|
| 4.1 Access token JWT 10 menit, berisi sub dan role | gateway/tokens.js (signAccess) |
| 4.1 Refresh token 1 hari di database, dapat dicabut, logout mencabut | gateway/authRoutes.js (/refresh, /logout), tabel refresh_tokens |
| 4.1 Token service 5 menit, role service | gateway/authRoutes.js (/service), gateway/tokens.js (signService) |
| 4.1 X-Gateway-Secret | gateway/index.js (proxyReq), shared/serviceAuth.js |
| 4.1 Verifikasi ulang token di service | shared/serviceAuth.js |
| 4.2 Kebijakan akses (Tabel 3) | gateway/policy.js (rules), dilengkapi pemeriksaan kepemilikan di service |
| 4.3 Device terdaftar | gateway/pep.js, gateway/authRoutes.js (/login) |
| 4.3 Jam akses dapat dikonfigurasi | config.js, gateway/policy.js (withinAccessHours) |
| 4.4 Audit log | gateway/audit.js, tabel audit_log |
| Finalisasi memanggil Transkrip lewat gateway | services/nilai/index.js (finalisasi) |

## Pengamanan tambahan di luar soal

Default deny untuk endpoint tanpa kebijakan, rotasi refresh token (token lama yang dipakai ulang ditolak), refresh token disimpan sebagai hash SHA-256, pembatas percobaan login (5 kali per menit per username), hash password bcrypt, pesan galat login tidak membedakan user tidak ada dan password salah, serta pembatalan finalisasi bila sinkron transkrip gagal.
