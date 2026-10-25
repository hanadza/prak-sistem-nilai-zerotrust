'use strict';
const db = require('../shared/db');
const n = parseInt(process.argv[2] || '30', 10);
console.table(db.prepare('SELECT ts, subject, method, endpoint, device, result, reason FROM audit_log ORDER BY id DESC LIMIT ?').all(n).reverse());
