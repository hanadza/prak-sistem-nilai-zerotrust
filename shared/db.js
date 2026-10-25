'use strict';
// Satu database SQLite bersama untuk gateway (Policy Engine, audit), Service Nilai, dan Service Transkrip.
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const cfg = require('../config');

fs.mkdirSync(path.dirname(cfg.dbPath), { recursive: true });
const db = new Database(cfg.dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('mahasiswa','dosen','admin')),
  nama TEXT NOT NULL,
  nim TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  device_id TEXT NOT NULL,
  UNIQUE (user_id, device_id)
);
CREATE TABLE IF NOT EXISTS kelas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kode TEXT UNIQUE NOT NULL,
  nama TEXT NOT NULL,
  dosen_id INTEGER NOT NULL REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS nilai (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kelas_id INTEGER NOT NULL REFERENCES kelas(id),
  mahasiswa_id INTEGER NOT NULL REFERENCES users(id),
  nilai REAL NOT NULL,
  final INTEGER NOT NULL DEFAULT 0,
  UNIQUE (kelas_id, mahasiswa_id)
);
CREATE TABLE IF NOT EXISTS transkrip (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mahasiswa_id INTEGER NOT NULL REFERENCES users(id),
  kelas_id INTEGER NOT NULL REFERENCES kelas(id),
  nilai REAL NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (mahasiswa_id, kelas_id)
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  token_hash TEXT UNIQUE NOT NULL,
  device_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS service_clients (
  client_id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  subject TEXT NOT NULL,
  role TEXT,
  method TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  device TEXT,
  result TEXT NOT NULL CHECK (result IN ('allow','deny')),
  reason TEXT NOT NULL,
  ip TEXT
);
`;

db.initSchema = () => db.exec(SCHEMA);
db.resetSchema = () => {
  db.pragma('foreign_keys = OFF');
  for (const t of ['audit_log', 'service_clients', 'refresh_tokens', 'transkrip', 'nilai', 'kelas', 'devices', 'users']) {
    db.exec(`DROP TABLE IF EXISTS ${t}`);
  }
  db.pragma('foreign_keys = ON');
  db.initSchema();
};
db.initSchema();

module.exports = db;
