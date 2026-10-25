'use strict';
// Audit log: setiap keputusan akses dicatat (waktu, subjek, endpoint, device, hasil, alasan).
const db = require('../shared/db');

const stmt = db.prepare(`INSERT INTO audit_log (ts, subject, role, method, endpoint, device, result, reason, ip)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);

exports.record = ({ subject, role, req, result, reason }) => {
  const endpoint = req.originalUrl.split('?')[0];
  stmt.run(new Date().toISOString(), subject, role || null, req.method, endpoint,
    req.get('X-Device-ID') || null, result, reason, req.ip || null);
  console.log(`[AUDIT] ${result.toUpperCase().padEnd(5)} ${subject.padEnd(18)} ${req.method.padEnd(6)} ${endpoint} :: ${reason}`);
};
