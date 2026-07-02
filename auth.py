# ADVERSARIAL FIXTURE — intentionally vulnerable. NOT production code.
# Classic Python/Flask vulnerabilities for Zorro detection validation.
import hashlib
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

# VULN 1: SQL Injection (CWE-89) — f-string user input into query.
@app.route("/login")
def login():
    username = request.args.get("username")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{username}'")  # injectable
    return str(cur.fetchall())


# VULN 2: Command Injection (CWE-78) — shell=True with user input.
@app.route("/lookup")
def lookup():
    domain = request.args.get("domain")
    out = subprocess.check_output("nslookup " + domain, shell=True)  # injectable
    return out


# VULN 3: Insecure Deserialization (CWE-502) — pickle from request.
@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))  # RCE sink


# VULN 4: Weak crypto (CWE-327) — SHA1 for tokens.
def make_token(secret):
    return hashlib.sha1(secret.encode()).hexdigest()


# VULN 5: Hardcoded secret (CWE-798) — FAKE/test value.
DJANGO_SECRET_KEY = "django-insecure-3kf9s!2j@test-fake-not-real-secret-value-001"

# VULN 6: Disabled TLS verification (CWE-295).
os.environ["PYTHONHTTPSVERIFY"] = "0"
