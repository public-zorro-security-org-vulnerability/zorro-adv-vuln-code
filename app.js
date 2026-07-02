// ADVERSARIAL FIXTURE — intentionally vulnerable. NOT production code.
// Classic Node/Express vulnerabilities for Zorro detection validation.
'use strict';

const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

// VULN 1: SQL Injection (CWE-89) — untrusted input concatenated into query.
function getUser(db, userId) {
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  return db.query(query); // tainted -> SQL sink
}

// VULN 2: OS Command Injection (CWE-78) — untrusted input into shell.
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (err, stdout) => {
    res.send(stdout);
  });
});

// VULN 3: Hardcoded AWS-style credentials (CWE-798) — FAKE/test values.
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

// VULN 4: Weak cryptography (CWE-327) — MD5 for password hashing.
function hashPassword(pw) {
  return crypto.createHash('md5').update(pw).digest('hex');
}

// VULN 5: Path Traversal (CWE-22) — untrusted filename joined to fs read.
app.get('/download', (req, res) => {
  const file = req.query.file;
  const data = fs.readFileSync(path.join('/var/data/', file)); // ../../etc/passwd
  res.send(data);
});

// VULN 6: Insecure deserialization-adjacent eval (CWE-95).
app.get('/calc', (req, res) => {
  res.send(String(eval(req.query.expr)));
});

module.exports = { app, getUser, hashPassword, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY };
