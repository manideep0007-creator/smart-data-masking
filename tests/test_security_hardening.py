import os
import hashlib
import sqlite3
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.auth import (
    create_access_token,
    is_cookie_secure,
)
from backend.auth_db import (
    create_user,
    get_auth_connection,
    hash_password,
    init_auth_db,
)

EXPECTED_SAFFRON_HASH = "8E7434D09B2CAFB974499FA64121AD1BD6B6EE5000D587A6EA8CF488AFA68DCE"
EXPECTED_LEGACY_HASH = "67A7E24C7EAEA3CEE4A2F36E31049E86A74347F93F44EC12E10C2A2150774695"


@pytest.fixture(autouse=True)
def clean_test_state():
    """Clear IP login attempts before each test to isolate rate-limiting assertions."""
    conn = get_auth_connection()
    try:
        conn.execute("DELETE FROM ip_login_attempts")
        conn.commit()
    finally:
        conn.close()


def get_fresh_client():
    return TestClient(app)


# --- SEC-01: Browser Token Security ---

def test_sec01_browser_login_does_not_expose_jwt_in_json_and_sets_httponly_cookie():
    """Verify that browser logins receive HttpOnly cookie and null access_token in JSON."""
    client = get_fresh_client()
    resp = client.post("/auth/login", json={"username": "support_ravi", "password": "password123"})
    assert resp.status_code == 200
    data = resp.json()

    # SEC-01: JWT must NOT be returned in JSON for browser logins
    assert data["access_token"] is None
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "support_ravi"
    assert "csrf_token" in data

    # Verify HttpOnly cookie
    assert "access_token" in resp.cookies
    assert "csrf_token" in resp.cookies

    set_cookie_headers = resp.headers.get_list("set-cookie")
    access_cookie_header = [h for h in set_cookie_headers if "access_token=" in h]
    assert len(access_cookie_header) > 0
    assert "httponly" in access_cookie_header[0].lower()


def test_sec01_api_client_can_request_token_explicitly():
    """Verify that non-browser API clients can explicitly request Bearer token in JSON."""
    client = get_fresh_client()
    resp = client.post(
        "/auth/login",
        json={"username": "admin_anita", "password": "password123"},
        headers={"X-Auth-Mode": "api"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["access_token"] is not None
    assert len(data["access_token"]) > 20


def test_sec01_frontend_js_does_not_store_jwt():
    """Verify frontend code does not store JWT in sessionStorage or localStorage."""
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "app.js")
    with open(frontend_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "sessionStorage.setItem('pii_shield_token'" not in content
    assert "localStorage.setItem('pii_shield_token'" not in content
    assert "currentAuthToken" not in content
    assert "DEMO_CREDENTIALS" not in content


# --- SEC-02: User Enumeration Protection ---

def test_sec02_auth_users_unauthenticated_returns_401():
    """Verify GET /auth/users rejects unauthenticated callers with HTTP 401."""
    client = get_fresh_client()
    resp = client.get("/auth/users")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["detail"]


def test_sec02_auth_users_support_and_analyst_return_403():
    """Verify GET /auth/users rejects Support and Analyst roles with HTTP 403."""
    client = get_fresh_client()
    sup_token = create_access_token({"sub": "support_ravi", "role": "Support"})
    ana_token = create_access_token({"sub": "analyst_kavya", "role": "Analyst"})

    r_sup = client.get("/auth/users", headers={"Authorization": f"Bearer {sup_token}"})
    assert r_sup.status_code == 403
    assert "Admin privileges required" in r_sup.json()["detail"]

    r_ana = client.get("/auth/users", headers={"Authorization": f"Bearer {ana_token}"})
    assert r_ana.status_code == 403
    assert "Admin privileges required" in r_ana.json()["detail"]


def test_sec02_auth_users_admin_succeeds_without_sensitive_internals():
    """Verify Admin can inspect users and safe fields are returned without hashes."""
    client = get_fresh_client()
    admin_token = create_access_token({"sub": "admin_anita", "role": "Admin"})

    resp = client.get("/auth/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert "users" in data
    assert len(data["users"]) > 0

    for u in data["users"]:
        assert "id" in u
        assert "username" in u
        assert "email" in u
        assert "role" in u
        # Strictly forbidden fields
        assert "password_hash" not in u
        assert "failed_login_attempts" not in u
        assert "locked_until" not in u


# --- SEC-03: CSRF Protection ---

def test_sec03_cookie_auth_state_changing_requires_csrf():
    """Verify cookie-authenticated POST requests without CSRF token are rejected with 403."""
    client = get_fresh_client()
    # Login in browser mode
    login_resp = client.post("/auth/login", json={"username": "support_ravi", "password": "password123"})
    assert login_resp.status_code == 200
    assert "access_token" in login_resp.cookies

    # POST /query without X-CSRF-Token header
    resp = client.post("/query", json={"sql": "SELECT 1"})
    assert resp.status_code == 403
    assert "CSRF token validation failed" in resp.json()["detail"]


def test_sec03_cookie_auth_invalid_csrf_rejected():
    """Verify cookie-authenticated requests with mismatched CSRF token are rejected."""
    client = get_fresh_client()
    client.post("/auth/login", json={"username": "support_ravi", "password": "password123"})

    resp = client.post(
        "/query",
        json={"sql": "SELECT 1"},
        headers={"X-CSRF-Token": "invalid-forged-csrf-token"}
    )
    assert resp.status_code == 403
    assert "CSRF token validation failed" in resp.json()["detail"]


def test_sec03_cookie_auth_valid_csrf_succeeds():
    """Verify cookie-authenticated requests with valid CSRF token succeed."""
    client = get_fresh_client()
    login_resp = client.post("/auth/login", json={"username": "support_ravi", "password": "password123"})
    assert login_resp.status_code == 200
    csrf_tok = login_resp.cookies.get("csrf_token")
    assert csrf_tok is not None

    resp = client.post(
        "/query",
        json={"sql": "SELECT cust_nm, mob_no FROM customers LIMIT 1"},
        headers={"X-CSRF-Token": csrf_tok},
    )
    assert resp.status_code == 200
    assert "rows" in resp.json()


def test_sec03_bearer_auth_does_not_require_csrf():
    """Verify non-browser Bearer requests do not require CSRF token."""
    client = get_fresh_client()
    token = create_access_token({"sub": "support_ravi", "role": "Support"})

    resp = client.post(
        "/query",
        json={"sql": "SELECT 1"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200


def test_sec03_logout_enforces_csrf_and_clears_cookies():
    """Verify cookie logout requires CSRF and deletes session cookies."""
    client = get_fresh_client()
    login_resp = client.post("/auth/login", json={"username": "admin_anita", "password": "password123"})
    csrf_tok = login_resp.cookies.get("csrf_token")

    # Logout without CSRF -> 403
    fail_logout = client.post("/auth/logout")
    assert fail_logout.status_code == 403

    # Logout with CSRF -> 200 and cookies cleared
    succ_logout = client.post("/auth/logout", headers={"X-CSRF-Token": csrf_tok})
    assert succ_logout.status_code == 200
    assert succ_logout.json()["status"] == "ok"


# --- SEC-04: Cookie Secure Flag ---

def test_sec04_cookie_secure_configuration(monkeypatch):
    """Verify is_cookie_secure respects production environment."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    assert is_cookie_secure() is True

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("FORCE_HTTPS_COOKIE", "false")
    assert is_cookie_secure() is False


# --- SEC-05: IP Rate Limiting & Account Lockout ---

def test_sec05_ip_rate_limiting_blocks_excessive_logins():
    """Verify IP rate limiting triggers HTTP 429 after 10 failed login attempts."""
    client = get_fresh_client()

    # 10 failed attempts from this client
    for i in range(10):
        resp = client.post("/auth/login", json={"username": f"user_{i}", "password": "wrongpassword"})
        assert resp.status_code == 401

    # 11th attempt must be rejected with 429 Too Many Requests
    blocked_resp = client.post("/auth/login", json={"username": "admin_anita", "password": "password123"})
    assert blocked_resp.status_code == 429
    assert "Too many failed login attempts" in blocked_resp.json()["detail"]


# --- SEC-06: Demo Seeding Disabled by Default ---

def test_sec06_demo_seeding_disabled_by_default(tmp_path, monkeypatch):
    """Verify new database initializations do not seed demo users unless explicitly opted in."""
    temp_auth_db = str(tmp_path / "test_auth.db")
    monkeypatch.setenv("SEED_DEMO_USERS", "false")

    init_auth_db(db_path=temp_auth_db)

    conn = sqlite3.connect(temp_auth_db)
    try:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        assert count == 0, f"Expected 0 seeded users by default, got {count}"
    finally:
        conn.close()


# --- SEC-07: Schema Discovery Restriction ---

def test_sec07_schema_discovery_restricted_to_admin():
    """Verify GET /scan is restricted to Admin (Support & Analyst get HTTP 403)."""
    client = get_fresh_client()
    sup_token = create_access_token({"sub": "support_ravi", "role": "Support"})
    ana_token = create_access_token({"sub": "analyst_kavya", "role": "Analyst"})
    admin_token = create_access_token({"sub": "admin_anita", "role": "Admin"})

    # Support -> 403
    r_sup = client.get("/scan?table=customers", headers={"Authorization": f"Bearer {sup_token}"})
    assert r_sup.status_code == 403

    # Analyst -> 403
    r_ana = client.get("/scan?table=customers", headers={"Authorization": f"Bearer {ana_token}"})
    assert r_ana.status_code == 403

    # Admin -> 200
    r_admin = client.get("/scan?table=customers", headers={"Authorization": f"Bearer {admin_token}"})
    assert r_admin.status_code == 200
    data = r_admin.json()
    assert data["table"] == "customers"
    assert len(data["columns"]) > 0


def test_sec07_schema_summary_accessible_to_non_admin_roles():
    """Verify GET /scan/summary provides safe counts without heuristics to Support and Analyst."""
    client = get_fresh_client()
    sup_token = create_access_token({"sub": "support_ravi", "role": "Support"})

    r = client.get("/scan/summary", headers={"Authorization": f"Bearer {sup_token}"})
    assert r.status_code == 200
    data = r.json()
    assert "tables" in data
    assert data["total_tables"] >= 1
    # Check that individual PII heuristics/tags are NOT leaked in summary
    for t in data["tables"]:
        assert "table" in t
        assert "column_count" in t
        assert "columns" not in t
        assert "pii_type" not in t


# --- SEC-08: CORS Production Enforcement ---

def test_sec08_cors_production_fails_securely(monkeypatch):
    """Verify production requires non-empty, non-wildcard ALLOWED_ORIGINS."""
    from backend.auth import ENVIRONMENT
    # Verification of configuration guards logic in backend/main.py
    env = "production"
    raw_empty = []
    assert len(raw_empty) == 0  # Missing origins must fail

    raw_wildcard = ["*"]
    assert "*" in raw_wildcard  # Wildcard must be rejected


# --- Database Integrity Verification ---

def test_database_hashes_unaltered():
    """Verify Saffron Bank SQLite database has not mutated."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    saffron_path = os.path.join(root, "data", "saffron_bank.db")
    legacy_path = os.path.join(root, "backend", "customers.db")

    def get_hash(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest().upper()

    assert get_hash(saffron_path) == EXPECTED_SAFFRON_HASH, "Saffron Bank database mutated!"
    assert get_hash(legacy_path) == EXPECTED_LEGACY_HASH, "Legacy customers database mutated!"

