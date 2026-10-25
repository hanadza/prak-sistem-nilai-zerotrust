'use strict';
// Menjalankan gateway + dua service sekaligus.
const { spawn } = require('child_process');
const path = require('path');
const root = path.join(__dirname, '..');
const procs = ['services/nilai/index.js', 'services/transkrip/index.js', 'gateway/index.js']
  .map((f) => spawn(process.execPath, [path.join(root, f)], { stdio: 'inherit', cwd: root }));
const stop = () => procs.forEach((p) => p.kill());
process.on('SIGINT', () => { stop(); process.exit(0); });
process.on('SIGTERM', () => { stop(); process.exit(0); });
procs.forEach((p) => p.on('exit', (c) => { if (c) { console.error('Proses berhenti, menutup semua.'); stop(); process.exit(c); } }));
