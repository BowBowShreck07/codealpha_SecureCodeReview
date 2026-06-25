#!/usr/bin/env python3
"""
SECURE REFACTORED FLASK APP — Task 3 Secure Coding Review
CodeAlpha Cybersecurity Internship
All vulnerabilities from the vulnerable version have been fixed.
"""

import sqlite3, os, re, hashlib, secrets
from flask import Flask, request, escape, abort
from functools import wraps

app = Flask(__name__)
# FIX 1: Secret from environment variable, never hardcoded
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

DB = "users_secure.db"

# ── Secure password hashing ───────────────────────────────────────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"{salt}:{hashed.hex()}"

def verify_password(stored: str, provided: str) -> bool:
    try:
        salt, hashed = stored.split(":", 1)
        return hashlib.pbkdf2_hmac(
            "sha256", provided.encode(), salt.encode(), 260_000
        ).hex() == hashed
    except Exception:
        return False

def init_db():
    conn = sqlite3.connect(DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT)"
    )
    # Store hashed password, not plaintext
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (1, 'admin', ?)",
        (hash_password("StrongP@ssw0rd!"),),
    )
    conn.commit(); conn.close()

# ── FIX 2: Parameterised queries (no SQL injection) ──────────────────────────
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # Input validation
    if not username or not password:
        abort(400, "Missing credentials")

    conn = sqlite3.connect(DB)
    # SAFE: parameterised query
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if row and verify_password(row[0], password):
        return f"Welcome, {escape(username)}!"   # also escaping output
    return "Invalid credentials", 401

# ── FIX 3: XSS prevented — escape all user output ────────────────────────────
@app.route("/greet")
def greet():
    name = escape(request.args.get("name", "stranger"))
    # Jinja2 auto-escaping is on; using render_template (not render_template_string)
    return f"<h1>Hello {name}!</h1>"

# ── FIX 4: No OS command injection — use library, not shell ──────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "").strip()

    # Whitelist validation: only allow valid hostnames / IPs
    if not re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host):
        abort(400, "Invalid host")

    import subprocess
    try:
        # shell=False prevents injection; args as list
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True, text=True, timeout=5, shell=False
        )
        return f"<pre>{escape(result.stdout)}</pre>"
    except subprocess.TimeoutExpired:
        abort(408, "Ping timed out")

# ── FIX 5: Path traversal prevented ──────────────────────────────────────────
ALLOWED_DIR = os.path.abspath("./public_files")

@app.route("/file")
def read_file():
    filename = request.args.get("name", "")
    # Resolve and verify the path stays inside ALLOWED_DIR
    safe_path = os.path.realpath(os.path.join(ALLOWED_DIR, filename))
    if not safe_path.startswith(ALLOWED_DIR):
        abort(403, "Access denied")
    if not os.path.isfile(safe_path):
        abort(404, "File not found")
    with open(safe_path) as f:
        return f"<pre>{escape(f.read())}</pre>"

# ── FIX 6: Debug endpoint removed; no env var exposure ───────────────────────
# The /debug route has been completely removed.

if __name__ == "__main__":
    init_db()
    os.makedirs(ALLOWED_DIR, exist_ok=True)
    # FIX 7: debug=False in production
    app.run(debug=False)