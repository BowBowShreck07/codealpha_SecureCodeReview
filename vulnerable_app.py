#!/usr/bin/env python3
"""
INTENTIONALLY VULNERABLE FLASK APP — for Task 3 Secure Code Review
DO NOT deploy this in production.
"""

import sqlite3, subprocess, os
from flask import Flask, request, render_template_string

app = Flask(__name__)
SECRET_KEY = "admin123"  # VULN: hardcoded secret

DB = "users.db"
def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','password123')")
    conn.commit(); conn.close()

# ── VULN 1: SQL Injection ─────────────────────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    u = request.form["username"]
    p = request.form["password"]
    conn = sqlite3.connect(DB)
    # BAD: string formatting in SQL
    q = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
    row = conn.execute(q).fetchone()
    conn.close()
    if row:
        return f"Welcome {u}!"
    return "Invalid credentials"

# ── VULN 2: XSS ───────────────────────────────────────────────────────────────
@app.route("/greet")
def greet():
    name = request.args.get("name", "stranger")
    # BAD: user input injected directly into HTML
    return render_template_string(f"<h1>Hello {name}!</h1>")

# ── VULN 3: OS Command Injection ──────────────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # BAD: shell=True with unsanitised user input
    out = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return f"<pre>{out}</pre>"

# ── VULN 4: Path Traversal ────────────────────────────────────────────────────
@app.route("/file")
def read_file():
    filename = request.args.get("name", "readme.txt")
    # BAD: no path validation — allows ../../../etc/passwd
    with open(filename) as f:
        return f"<pre>{f.read()}</pre>"

# ── VULN 5: Sensitive data in response ───────────────────────────────────────
@app.route("/debug")
def debug():
    # BAD: exposes all env vars including secrets
    return str(dict(os.environ))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)   # VULN: debug mode exposes traceback in production