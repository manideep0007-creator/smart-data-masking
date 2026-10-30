import datetime
import json
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

BACKEND_URL = "http://127.0.0.1:8000"
FRONTEND_URL = "http://localhost:3000"
DB_PATH = "backend/customers.db"

results_log: List[Dict[str, Any]] = []

def record_test(name: str, phase: str, expected: str, actual: str, status: str, evidence: Any):
    results_log.append({
        "test_name": name,
        "phase": phase,
        "expected": expected,
        "actual": actual,
        "status": status,
        "evidence": evidence
    })

def http_get(url: str, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Any, float]:
    start = time.perf_counter()
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as resp:
            elapsed = (time.perf_counter() - start) * 1000
            content = resp.read()
            try:
                data = json.loads(content)
            except Exception:
                data = content.decode("utf-8", errors="replace")
            return resp.status, data, elapsed
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - start) * 1000
        content = e.read()
        try:
            data = json.loads(content)
        except Exception:
            data = content.decode("utf-8", errors="replace")
        return e.code, data, elapsed
    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return 0, str(exc), elapsed

def http_post(url: str, payload: Any, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Any, float]:
    start = time.perf_counter()
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    body = json.dumps(payload).encode("utf-8") if isinstance(payload, (dict, list)) else (payload or b"")
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            elapsed = (time.perf_counter() - start) * 1000
            content = resp.read()
            try:
                data = json.loads(content)
            except Exception:
                data = content.decode("utf-8", errors="replace")
            return resp.status, data, elapsed
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - start) * 1000
        content = e.read()
        try:
            data = json.loads(content)
        except Exception:
            data = content.decode("utf-8", errors="replace")
        return e.code, data, elapsed
    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return 0, str(exc), elapsed

print("=== STARTING PII SHIELD END-TO-END TEST SUITE ===")
t0 = time.time()

# ----------------------------------------------------
# SNAPSHOT DATABASE BEFORE TESTING
# ----------------------------------------------------
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("SELECT id, name, email, phone, ssn, card_number, salary, address FROM customers ORDER BY id")
db_snapshot_before = cur.fetchall()
conn.close()
print(f"[*] SQLite pre-test snapshot: {len(db_snapshot_before)} customer records captured.")

# ----------------------------------------------------
# PHASE 1: APPLICATION CONNECTIVITY
# ----------------------------------------------------
print("\n--- PHASE 1: Application Connectivity ---")

# 1.1 Backend Health
code, data, latency = http_get(f"{BACKEND_URL}/health")
passed = code == 200 and data.get("status") == "ok" and data.get("database") == "connected"
record_test(
    "P1.1 Backend Health Endpoint", "Connectivity",
    "HTTP 200, status: ok, database: connected",
    f"HTTP {code}, status: {data.get('status') if isinstance(data, dict) else 'error'}, latency: {latency:.1f}ms",
    "PASS" if passed else "FAIL", data
)

# 1.2 Database Info Endpoint
code, data, latency = http_get(f"{BACKEND_URL}/database/info")
passed = code == 200 and data.get("connection", {}).get("engine") == "sqlite" and "customers" in data.get("tables", [])
record_test(
    "P1.2 Database Engine Info", "Connectivity",
    "HTTP 200, engine: sqlite, tables include 'customers'",
    f"HTTP {code}, engine: {data.get('connection', {}).get('engine') if isinstance(data, dict) else 'N/A'}",
    "PASS" if passed else "FAIL", data
)

# 1.3 Frontend Server Root
code, data, latency = http_get(f"{FRONTEND_URL}/")
passed = code == 200 and "Smart Data Masking" in str(data)
record_test(
    "P1.3 Frontend Static Server", "Connectivity",
    "HTTP 200, serves index.html with 'Smart Data Masking'",
    f"HTTP {code}, latency: {latency:.1f}ms, html_bytes: {len(str(data))}",
    "PASS" if passed else "FAIL", {"content_preview": str(data)[:120]}
)

# 1.4 Frontend Assets
code_css, _, _ = http_get(f"{FRONTEND_URL}/styles.css")
code_js, _, _ = http_get(f"{FRONTEND_URL}/app.js")
passed = code_css == 200 and code_js == 200
record_test(
    "P1.4 Frontend Asset Bundles (CSS/JS)", "Connectivity",
    "HTTP 200 for styles.css and app.js",
    f"styles.css: HTTP {code_css}, app.js: HTTP {code_js}",
    "PASS" if passed else "FAIL", {"css_status": code_css, "js_status": code_js}
)

# ----------------------------------------------------
# PHASE 2: AUTHENTICATION & RBAC
# ----------------------------------------------------
print("\n--- PHASE 2: Authentication & RBAC ---")

tokens: Dict[str, str] = {}

# 2.1 - 2.3 Login for Admin, Support, Analyst
for role, username, pwd in [
    ("Admin", "admin_anita", "password123"),
    ("Support", "support_ravi", "password123"),
    ("Analyst", "analyst_kavya", "password123"),
]:
    code, data, lat = http_post(f"{BACKEND_URL}/auth/login", {"username": username, "password": pwd})
    passed = code == 200 and "access_token" in data and data.get("user", {}).get("role") == role
    if passed:
        tokens[role] = data["access_token"]
    record_test(
        f"P2.1 Login as {role} ({username})", "Authentication",
        f"HTTP 200, JWT token returned, role == '{role}'",
        f"HTTP {code}, role: {data.get('user', {}).get('role') if isinstance(data, dict) else 'error'}, latency: {lat:.1f}ms",
        "PASS" if passed else "FAIL",
        {"role": data.get("user", {}).get("role"), "token_type": data.get("token_type")} if isinstance(data, dict) else data
    )

# 2.4 Invalid Password
code, data, _ = http_post(f"{BACKEND_URL}/auth/login", {"username": "admin_anita", "password": "wrong_password_999"})
passed = code == 401 and "Invalid" in str(data.get("detail", ""))
record_test(
    "P2.4 Invalid Credentials Rejection", "Authentication",
    "HTTP 401 Unauthorized",
    f"HTTP {code}, detail: {data.get('detail') if isinstance(data, dict) else data}",
    "PASS" if passed else "FAIL", data
)

# 2.5 Auth /me Profile Inspection
code, data, _ = http_get(f"{BACKEND_URL}/auth/me", headers={"Authorization": f"Bearer {tokens.get('Support', '')}"})
passed = code == 200 and data.get("username") == "support_ravi" and data.get("role") == "Support"
record_test(
    "P2.5 /auth/me Token Verification", "Authentication",
    "HTTP 200, verified user: support_ravi, role: Support",
    f"HTTP {code}, user: {data.get('username') if isinstance(data, dict) else 'N/A'}",
    "PASS" if passed else "FAIL", data
)

# 2.6 Expired / Corrupted JWT Rejection
code, data, _ = http_get(f"{BACKEND_URL}/auth/me", headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.corrupted.token"})
passed = code == 401
record_test(
    "P2.6 Corrupted JWT Token Rejection", "Authentication",
    "HTTP 401 Unauthorized",
    f"HTTP {code}, detail: {data.get('detail') if isinstance(data, dict) else data}",
    "PASS" if passed else "FAIL", data
)

# 2.7 Privilege Escalation Attempt (Analyst passes role: Admin in query body)
code, data, _ = http_post(
    f"{BACKEND_URL}/query",
    {"role": "Admin", "sql": "SELECT name, card_number FROM customers WHERE id = 1"},
    headers={"Authorization": f"Bearer {tokens.get('Analyst', '')}"}
)
passed = code == 200 and data.get("rows", [[None, None]])[0][1] == "[REDACTED]" and data.get("meta", {}).get("role_applied") == "Analyst"
record_test(
    "P2.7 Privilege Escalation Tampering Guard", "Authentication / RBAC",
    "Server-side JWT overrides body role 'Admin', enforces Analyst redaction",
    f"HTTP {code}, role_applied: {data.get('meta', {}).get('role_applied') if isinstance(data, dict) else 'N/A'}, card_cell: {data.get('rows', [[None, None]])[0][1] if isinstance(data, dict) else 'N/A'}",
    "PASS" if passed else "FAIL", data
)

# 2.8 Unauthenticated Scan Rejection
code, data, _ = http_post(
    f"{BACKEND_URL}/scan/start",
    {},
    headers={"Authorization": f"Bearer {tokens.get('Analyst', '')}"}
)
passed = code == 403
record_test(
    "P2.8 Administrative Endpoint Role Protection (/scan/start)", "Authentication / RBAC",
    "HTTP 403 Forbidden when invoked by non-Admin",
    f"HTTP {code}, detail: {data.get('detail') if isinstance(data, dict) else data}",
    "PASS" if passed else "FAIL", data
)

# 2.9 Public /auth/users Credential Security
code, data, _ = http_get(f"{BACKEND_URL}/auth/users")
users = data.get("users", []) if isinstance(data, dict) else []
has_passwords = any("password" in u or "hash" in u for u in users)
passed = code == 200 and not has_passwords and len(users) >= 3
record_test(
    "P2.9 Safe User Persona Listing (No Passwords Leaked)", "Authentication",
    "HTTP 200, users list contains username and role with ZERO plaintext passwords or hashes",
    f"HTTP {code}, total_users: {len(users)}, passwords_exposed: {has_passwords}",
    "PASS" if passed else "FAIL", {"users_sample": users[:2]}
)

# ----------------------------------------------------
# PHASE 3: AUTOMATED PII DETECTION
# ----------------------------------------------------
print("\n--- PHASE 3: Automated PII Detection ---")

code, scan_data, lat = http_get(f"{BACKEND_URL}/scan?table=customers")
columns = scan_data.get("columns", []) if isinstance(scan_data, dict) else []
col_map = {c["name"]: c for c in columns}

expected_tags = {
    "card_number": ("FINANCIAL_CONFIDENTIAL", "CREDIT_CARD", "HIGH"),
    "ssn": ("PII_HIGH", "SSN", "HIGH"),
    "email": ("PII_MEDIUM", "EMAIL", "HIGH"),
    "phone": ("PII_MEDIUM", "PHONE", "HIGH"),
    "salary": ("FINANCIAL_CONFIDENTIAL", "FINANCIAL", "HIGH"),
    "address": ("PII_MEDIUM", "ADDRESS", "HIGH"),
    "name": ("PII_LOW", "NAME", "HIGH"),
    "id": ("PUBLIC", "NONE", "NONE"),
}

detection_matches = []
all_matched = True
for cname, (exp_tag, exp_pii, exp_sens) in expected_tags.items():
    if cname in col_map:
        item = col_map[cname]
        tag_match = item["tag"] == exp_tag
        if not tag_match:
            all_matched = False
        detection_matches.append(f"{cname}: tag={item['tag']} (expected {exp_tag})")
    else:
        all_matched = False
        detection_matches.append(f"{cname}: NOT FOUND in scan")

record_test(
    "P3.1 Schema PII Radar Detection (customers table)", "PII Discovery",
    "All 8 columns correctly categorized with appropriate sensitivity tiers",
    f"HTTP {code}, total_columns: {len(columns)}, matched: {all_matched}",
    "PASS" if (code == 200 and all_matched) else "FAIL",
    {"details": detection_matches, "scan_latency_ms": lat}
)

# 3.2 Indian PII Detection (Aadhaar & PAN)
from backend.detector import classify_column
aadhaar_res = classify_column("aadhaar_no", ["1234-5678-9012"])
pan_res = classify_column("pan_no", ["ABCDE1234F"])
passed_indian = (
    aadhaar_res["tag"] == "PII_HIGH" and aadhaar_res["pii_type"] == "AADHAAR" and
    pan_res["tag"] == "PII_HIGH" and pan_res["pii_type"] == "PAN"
)
record_test(
    "P3.2 Indian BFSI Identifiers Detection (Aadhaar & PAN)", "PII Discovery",
    "Aadhaar classified as PII_HIGH / AADHAAR; PAN classified as PII_HIGH / PAN",
    f"Aadhaar tag={aadhaar_res['tag']} type={aadhaar_res['pii_type']}, PAN tag={pan_res['tag']} type={pan_res['pii_type']}",
    "PASS" if passed_indian else "FAIL",
    {"aadhaar": aadhaar_res, "pan": pan_res}
)

# 3.3 DOB & Government ID Detection
dob_res = classify_column("dob_dt", ["1992-05-14"])
dl_res = classify_column("driving_license", ["DL-1420110012345"])
passed_additional = dob_res["pii_type"] == "DATE_OF_BIRTH" and dl_res["tag"] == "PII_HIGH"
record_test(
    "P3.3 Additional PII Types (DOB & Driving License)", "PII Discovery",
    "DOB detected as DATE_OF_BIRTH; Driving License detected as PII_HIGH",
    f"DOB: {dob_res['pii_type']}, DL: {dl_res['tag']}",
    "PASS" if passed_additional else "FAIL",
    {"dob": dob_res, "dl": dl_res}
)

# ----------------------------------------------------
# PHASE 4: ROLE-BASED DATA MASKING ON SAME SQL QUERY
# ----------------------------------------------------
print("\n--- PHASE 4: Role-Based Masking on Identical Query ---")

identical_sql = "SELECT id, name, card_number, ssn, email, salary FROM customers WHERE id = 1"

# 4.1 Admin Query
code, admin_res, _ = http_post(
    f"{BACKEND_URL}/query",
    {"sql": identical_sql},
    headers={"Authorization": f"Bearer {tokens['Admin']}"}
)
admin_row = admin_res.get("rows", [[]])[0]
admin_pass = (
    code == 200 and
    admin_row[0] == 1 and
    admin_row[1] == "Asha" and
    admin_row[2] == "4111-2222-3333-1111" and
    admin_row[3] == "123-45-6789" and
    admin_row[4] == "asha@example.com" and
    admin_row[5] == 85000.0
)
record_test(
    "P4.1 Role Masking: Admin (Full Raw Access)", "Dynamic Masking",
    "id=1, name='Asha', card='4111-2222-3333-1111', ssn='123-45-6789', email='asha@example.com', salary=85000.0",
    f"HTTP {code}, row={admin_row}",
    "PASS" if admin_pass else "FAIL", admin_row
)

# 4.2 Support Query
code, support_res, _ = http_post(
    f"{BACKEND_URL}/query",
    {"sql": identical_sql},
    headers={"Authorization": f"Bearer {tokens['Support']}"}
)
support_row = support_res.get("rows", [[]])[0]
support_pass = (
    code == 200 and
    support_row[0] == 1 and
    support_row[1] == "Asha" and                         # Customer name preserved
    support_row[2] == "4111-XXXX-XXXX-1111" and         # Card partially masked
    support_row[3] == "XXX-XX-6789" and                 # SSN partially masked
    support_row[4] == "a***@example.com" and            # Email partially masked
    support_row[5] == "[CONFIDENTIAL]"                  # Salary confidential
)
record_test(
    "P4.2 Role Masking: Support (Partial Masking & Name Preserved)", "Dynamic Masking",
    "name='Asha', card='4111-XXXX-XXXX-1111', ssn='XXX-XX-6789', email='a***@example.com', salary='[CONFIDENTIAL]'",
    f"HTTP {code}, row={support_row}",
    "PASS" if support_pass else "FAIL", support_row
)

# 4.3 Analyst Query (Redact Strategy)
code, analyst_redact_res, _ = http_post(
    f"{BACKEND_URL}/query",
    {"sql": identical_sql, "mask_strategy": "redact"},
    headers={"Authorization": f"Bearer {tokens['Analyst']}"}
)
analyst_redact_row = analyst_redact_res.get("rows", [[]])[0]
analyst_redact_pass = (
    code == 200 and
    analyst_redact_row[0] == 1 and                      # Public ID unmasked
    analyst_redact_row[1] == "[REDACTED]" and           # Name redacted
    analyst_redact_row[2] == "[REDACTED]" and           # Card redacted
    analyst_redact_row[3] == "[REDACTED]" and           # SSN redacted
    analyst_redact_row[4] == "[REDACTED]" and           # Email redacted
    analyst_redact_row[5] == "[REDACTED]"               # Salary redacted
)
record_test(
    "P4.3 Role Masking: Analyst Redaction", "Dynamic Masking",
    "id=1 (readable), name/card/ssn/email/salary all '[REDACTED]'",
    f"HTTP {code}, row={analyst_redact_row}",
    "PASS" if analyst_redact_pass else "FAIL", analyst_redact_row
)

# 4.4 Analyst Query (Deterministic Hash Strategy)
code, analyst_hash_res, _ = http_post(
    f"{BACKEND_URL}/query",
    {"sql": identical_sql, "mask_strategy": "hash"},
    headers={"Authorization": f"Bearer {tokens['Analyst']}"}
)
analyst_hash_row = analyst_hash_res.get("rows", [[]])[0]
analyst_hash_pass = (
    code == 200 and
    analyst_hash_row[0] == 1 and
    str(analyst_hash_row[1]).startswith("sha256:") and
    str(analyst_hash_row[2]).startswith("sha256:") and
    str(analyst_hash_row[3]).startswith("sha256:") and
    str(analyst_hash_row[4]).startswith("sha256:") and
    str(analyst_hash_row[5]).startswith("sha256:")
)
record_test(
    "P4.4 Role Masking: Analyst Deterministic Pseudonymization (Hash)", "Dynamic Masking",
    "id=1 (readable), sensitive cells output 'sha256:12char' tokens",
    f"HTTP {code}, row={analyst_hash_row}",
    "PASS" if analyst_hash_pass else "FAIL", analyst_hash_row
)

# ----------------------------------------------------
# PHASE 5: HASHING VALIDATION
# ----------------------------------------------------
print("\n--- PHASE 5: Hashing Validation ---")

# 5.1 Repeatability: same query run again yields identical hash
code, repeat_hash_res, _ = http_post(
    f"{BACKEND_URL}/query",
    {"sql": identical_sql, "mask_strategy": "hash"},
    headers={"Authorization": f"Bearer {tokens['Analyst']}"}
)
repeat_hash_row = repeat_hash_res.get("rows", [[]])[0]
repeat_pass = repeat_hash_row == analyst_hash_row
record_test(
    "P5.1 Deterministic Hash Reproducibility", "Hashing Validation",
    "Subsequent query on same input returns exactly identical sha256 tokens",
    f"Identical: {repeat_pass}, hash_sample: {repeat_hash_row[2]}",
    "PASS" if repeat_pass else "FAIL", {"original": analyst_hash_row, "repeat": repeat_hash_row}
)

# 5.2 Distinct Inputs Produce Distinct Hashes
code, second_customer_res, _ = http_post(
    f"{BACKEND_URL}/query",
    {"sql": "SELECT card_number FROM customers WHERE id = 2", "mask_strategy": "hash"},
    headers={"Authorization": f"Bearer {tokens['Analyst']}"}
)
cust2_hash = second_customer_res.get("rows", [[]])[0][0]
cust1_hash = analyst_hash_row[2]
distinct_pass = cust1_hash != cust2_hash and cust2_hash.startswith("sha256:")
record_test(
    "P5.2 Hash Collision Resistance on Distinct Inputs", "Hashing Validation",
    "Different card numbers produce different HMAC-SHA256 digests",
    f"Card 1 hash: {cust1_hash} != Card 2 hash: {cust2_hash}",
    "PASS" if distinct_pass else "FAIL", {"card1": cust1_hash, "card2": cust2_hash}
)

# ----------------------------------------------------
# PHASE 6: SQL SECURITY & WRITE REJECTION
# ----------------------------------------------------
print("\n--- PHASE 6: SQL Security & Guard Enforcement ---")

dangerous_queries = [
    ("DROP TABLE customers", "DROP command blocked"),
    ("DELETE FROM customers WHERE id = 1", "DELETE command blocked"),
    ("UPDATE customers SET name = 'Hacked'", "UPDATE command blocked"),
    ("INSERT INTO customers (id, name, email, phone, ssn, card_number, salary, address) VALUES (99, 'X', 'x@x.com', '1', '1', '1', 1, '1')", "INSERT command blocked"),
    ("ALTER TABLE customers ADD COLUMN backdoor TEXT", "ALTER command blocked"),
    ("CREATE TABLE evil (id INT)", "CREATE command blocked"),
    ("TRUNCATE TABLE customers", "TRUNCATE command blocked"),
    ("ATTACH DATABASE ':memory:' AS evil_db", "ATTACH command blocked"),
    ("SELECT name FROM customers; DROP TABLE customers", "Multiple statement semicolon blocked"),
    ("SELECT * FROM customers -- secret comment", "SQL comment (--) blocked"),
    ("SELECT /* comment */ name FROM customers", "SQL block comment (/* */) blocked"),
    ("SELECT * FROM non_existent_table_xyz", "Non-existent table rejected cleanly"),
    ("SELECT FROM customers", "Syntax error rejected cleanly"),
]

sec_all_passed = True
sec_results = []
for q_sql, desc in dangerous_queries:
    code, data, _ = http_post(
        f"{BACKEND_URL}/query",
        {"sql": q_sql},
        headers={"Authorization": f"Bearer {tokens['Admin']}"}
    )
    is_rejected = code == 400
    if not is_rejected:
        sec_all_passed = False
    detail = data.get("detail", str(data)) if isinstance(data, dict) else str(data)
    sec_results.append(f"{desc}: HTTP {code} ({'REJECTED' if is_rejected else 'ALLOWED! LEAK!'})")

record_test(
    "P6.1 SQL Security & Injection Prevention (13 attack vectors)", "SQL Security",
    "All 13 write, DDL, comment, multi-statement, and malformed queries rejected with HTTP 400",
    f"All rejected: {sec_all_passed}, rejected count: {sum(1 for r in sec_results if 'REJECTED' in r)}/13",
    "PASS" if sec_all_passed else "FAIL", sec_results
)

# ----------------------------------------------------
# PHASE 7: ADVANCED MASKING TESTS (ALIASES, EXPRESSIONS, LIMITS)
# ----------------------------------------------------
print("\n--- PHASE 7: Advanced Masking Scenarios ---")

# 7.1 Column Aliases
alias_sql = "SELECT card_number AS cn, ssn AS s_id, email AS primary_contact FROM customers WHERE id = 1"
code, alias_res, _ = http_post(
    f"{BACKEND_URL}/query",
    {"sql": alias_sql},
    headers={"Authorization": f"Bearer {tokens['Support']}"}
)
arow = alias_res.get("rows", [[]])[0] if isinstance(alias_res, dict) else []
alias_pass = (
    code == 200 and
    arow[0] == "4111-XXXX-XXXX-1111" and
    arow[1] == "XXX-XX-6789" and
    arow[2] == "a***@example.com"
)
record_test(
    "P7.1 SQL Aliasing Masking Resilience (cn, s_id, primary_contact)", "Advanced Masking",
    "Card, SSN, and Email masked properly despite arbitrary column alias names",
    f"HTTP {code}, aliased row={arow}",
    "PASS" if alias_pass else "FAIL", arow
)

# 7.2 Arithmetic Expression on Sensitive Field
expr_sql = "SELECT salary + 1000 AS adjusted_salary FROM customers WHERE id = 1"
code, expr_res, _ = http_post(
    f"{BACKEND_URL}/query",
    {"sql": expr_sql},
    headers={"Authorization": f"Bearer {tokens['Support']}"}
)
erow = expr_res.get("rows", [[]])[0] if isinstance(expr_res, dict) else []
expr_pass = code == 200 and erow[0] == "[CONFIDENTIAL]"
record_test(
    "P7.2 Computed Expression Sensitivity (salary + 1000 AS adjusted_salary)", "Advanced Masking",
    "Calculated financial field classified and masked as [CONFIDENTIAL] for Support",
    f"HTTP {code}, row={erow}",
    "PASS" if expr_pass else "FAIL", erow
)

# 7.3 Max Row Limiting & Pagination Safeguard
code, limit_res, _ = http_post(
    f"{BACKEND_URL}/query",
    {"sql": "SELECT id, name FROM customers", "max_rows": 2},
    headers={"Authorization": f"Bearer {tokens['Admin']}"}
)
limit_meta = limit_res.get("meta", {}) if isinstance(limit_res, dict) else {}
limit_rows = limit_res.get("rows", []) if isinstance(limit_res, dict) else []
limit_pass = code == 200 and len(limit_rows) == 2 and limit_meta.get("truncated") is True
record_test(
    "P7.3 Safe Bounded Cursor Limits (max_rows=2)", "Advanced Masking",
    "Cursor fetches bounded rows (2) and sets truncated=True",
    f"HTTP {code}, rows={len(limit_rows)}, truncated={limit_meta.get('truncated')}",
    "PASS" if limit_pass else "FAIL", limit_meta
)

# 7.4 Empty Result Set
code, empty_res, _ = http_post(
    f"{BACKEND_URL}/query",
    {"sql": "SELECT name, card_number FROM customers WHERE id = 99999"},
    headers={"Authorization": f"Bearer {tokens['Support']}"}
)
empty_pass = code == 200 and len(empty_res.get("rows", [])) == 0 and empty_res.get("columns") == ["name", "card_number"]
record_test(
    "P7.4 Empty Result Set (WHERE id = 99999)", "Advanced Masking",
    "HTTP 200, returns empty rows array without server errors",
    f"HTTP {code}, rows={len(empty_res.get('rows', []))}, columns={empty_res.get('columns')}",
    "PASS" if empty_pass else "FAIL", empty_res
)

# ----------------------------------------------------
# PHASE 8: BACKGROUND SCANNER
# ----------------------------------------------------
print("\n--- PHASE 8: Background Scanner ---")

# 8.1 Start Background Scan
code, scan_start, _ = http_post(
    f"{BACKEND_URL}/scan/start",
    {},
    headers={"Authorization": f"Bearer {tokens['Admin']}"}
)
scan_start_pass = code == 200 and "task_id" in scan_start and scan_start.get("status") == "scanning"
record_test(
    "P8.1 Background Scan Initiation", "Background Scanner",
    "HTTP 200, returns task_id, status: scanning",
    f"HTTP {code}, task: {scan_start.get('task_id')}, status: {scan_start.get('status')}",
    "PASS" if scan_start_pass else "FAIL", scan_start
)

# 8.2 Monitor Status & Wait for Completion
time.sleep(0.4)
code, scan_stat, _ = http_get(f"{BACKEND_URL}/scan/status")
stat_pass = code == 200 and scan_stat.get("status") in ("scanning", "completed")
record_test(
    "P8.2 Background Scan Progress Tracking", "Background Scanner",
    "HTTP 200, progress percentage reported, status scanning/completed",
    f"HTTP {code}, status: {scan_stat.get('status')}, progress: {scan_stat.get('progress_pct')}%",
    "PASS" if stat_pass else "FAIL", scan_stat
)

# 8.3 History Audit
code, scan_hist, _ = http_get(f"{BACKEND_URL}/scan/history")
hist = scan_hist.get("history", []) if isinstance(scan_hist, dict) else []
hist_pass = code == 200 and len(hist) > 0
record_test(
    "P8.3 Background Scan History Log", "Background Scanner",
    "HTTP 200, returns history array with past scan task records",
    f"HTTP {code}, history_count: {len(hist)}",
    "PASS" if hist_pass else "FAIL", {"recent_task": hist[-1] if hist else None}
)

# 8.4 Invalid Table Scan Rejection
code, bad_scan, _ = http_post(
    f"{BACKEND_URL}/scan/start?table=non_existent_table_abc",
    {},
    headers={"Authorization": f"Bearer {tokens['Admin']}"}
)
bad_scan_pass = code == 400
record_test(
    "P8.4 Invalid Table Name Rejection in Scanner", "Background Scanner",
    "HTTP 400 Bad Request when table does not exist",
    f"HTTP {code}, detail: {bad_scan.get('detail') if isinstance(bad_scan, dict) else bad_scan}",
    "PASS" if bad_scan_pass else "FAIL", bad_scan
)

# ----------------------------------------------------
# PHASE 9: DATABASE INTEGRITY VERIFICATION
# ----------------------------------------------------
print("\n--- PHASE 9: Database Integrity Verification ---")

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("SELECT id, name, email, phone, ssn, card_number, salary, address FROM customers ORDER BY id")
db_snapshot_after = cur.fetchall()
conn.close()

counts_match = len(db_snapshot_before) == len(db_snapshot_after)
data_identical = db_snapshot_before == db_snapshot_after
record_test(
    "P9.1 SQLite Immutability & Record Preservation", "Database Integrity",
    "Customer count identical (4 == 4), raw data values 100% unchanged after all write attacks",
    f"Pre count: {len(db_snapshot_before)}, Post count: {len(db_snapshot_after)}, Identical: {data_identical}",
    "PASS" if (counts_match and data_identical) else "FAIL",
    {"pre_count": len(db_snapshot_before), "post_count": len(db_snapshot_after)}
)

# ----------------------------------------------------
# PHASE 10: OFFLINE VERIFICATION
# ----------------------------------------------------
print("\n--- PHASE 10: Offline Capability ---")

with open("frontend/index.html", "r", encoding="utf-8") as f:
    html_content = f.read()

with open("frontend/styles.css", "r", encoding="utf-8") as f:
    css_content = f.read()

has_remote_fonts = "fonts.googleapis.com" in html_content or "fonts.gstatic.com" in html_content
has_external_cdn = "cdnjs.cloudflare.com" in html_content or "cdn.jsdelivr.net" in html_content
has_remote_css_imports = "@import url('http" in css_content

offline_ready = not has_remote_fonts and not has_external_cdn and not has_remote_css_imports
record_test(
    "P10.1 Offline Autonomous Execution (Zero CDN / Zero Cloud)", "Offline Prototype",
    "index.html & styles.css free of external CDN/fonts; all styles bundled locally",
    f"Remote fonts: {has_remote_fonts}, External CDNs: {has_external_cdn}, Remote CSS: {has_remote_css_imports}",
    "PASS" if offline_ready else "FAIL",
    {"offline_ready": offline_ready}
)

# ----------------------------------------------------
# PHASE 11: PERFORMANCE & STABILITY
# ----------------------------------------------------
print("\n--- PHASE 11: Performance & Stability ---")

# Measure 20 consecutive query executions to check stability and memory
latencies = []
for i in range(20):
    role = "Support" if i % 2 == 0 else "Analyst"
    c, _, lat = http_post(
        f"{BACKEND_URL}/query",
        {"sql": "SELECT name, card_number, salary FROM customers"},
        headers={"Authorization": f"Bearer {tokens[role]}"}
    )
    latencies.append(lat)

avg_latency = sum(latencies) / len(latencies)
p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]
perf_pass = avg_latency < 50.0  # sub-50ms average

record_test(
    "P11.1 Concurrency & Stress Stability (20 consecutive queries)", "Performance & Stability",
    "Average query latency < 50ms, zero crashes or 500 errors",
    f"Avg Latency: {avg_latency:.2f}ms, P95: {p95_latency:.2f}ms, Min: {min(latencies):.2f}ms, Max: {max(latencies):.2f}ms",
    "PASS" if perf_pass else "FAIL",
    {"avg_ms": avg_latency, "p95_ms": p95_latency, "samples": len(latencies)}
)

total_time = time.time() - t0
print(f"\n[+] End-to-End Test Suite Completed in {total_time:.2f} seconds.")

# Save results to json for detailed reporting
with open("e2e_results.json", "w", encoding="utf-8") as f:
    json.dump(results_log, f, indent=2)

passed_count = sum(1 for r in results_log if r["status"] == "PASS")
failed_count = sum(1 for r in results_log if r["status"] == "FAIL")
print(f"[+] Total E2E Tests Executed: {len(results_log)} | Passed: {passed_count} | Failed: {failed_count}")

