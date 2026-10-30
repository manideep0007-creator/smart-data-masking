import os
import hashlib
from datetime import timedelta
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.auth import create_access_token
from backend.auth_db import (
    AUTH_DB_PATH,
    create_user,
    get_auth_connection,
    get_user_by_username,
    hash_password,
    init_auth_db,
    set_user_active_status,
)

EXPECTED_SAFFRON_HASH = "8E7434D09B2CAFB974499FA64121AD1BD6B6EE5000D587A6EA8CF488AFA68DCE"


@pytest.fixture(scope="module", autouse=True)
def setup_phase1_test_environment():
    """Initialize auth database and ensure demo users are seeded."""
    init_auth_db(seed_demo=True)


@pytest.fixture(autouse=True)
def clean_ip_attempts():
    """Clear IP login attempts before each test to isolate rate-limiting assertions."""
    conn = get_auth_connection()
    try:
        conn.execute("DELETE FROM ip_login_attempts")
        conn.commit()
    finally:
        conn.close()


def get_fresh_client():
    """Return a raw TestClient without default headers or cookies."""
    return TestClient(app)


def test_correct_credentials_authenticate():
    client = get_fresh_client()
    personas = [
        ("admin_anita", "password123", "Admin"),
        ("support_ravi", "password123", "Support"),
        ("analyst_kavya", "password123", "Analyst"),
    ]

    for username, password, expected_role in personas:
        # Browser login: HttpOnly cookie issued, access_token omitted from JSON (SEC-01)
        resp = client.post("/auth/login", json={"username": username, "password": password})
        assert resp.status_code == 200, f"Login failed for {username}: {resp.text}"
        data = resp.json()
        assert data["access_token"] is None
        assert data["token_type"] == "bearer"
        assert data["user"]["username"] == username
        assert data["user"]["role"] == expected_role
        assert "access_token" in resp.cookies
        assert "csrf_token" in resp.cookies

        # API client login: X-Auth-Mode: api returns access_token in JSON for non-browser clients
        api_resp = client.post(
            "/auth/login",
            json={"username": username, "password": password},
            headers={"X-Auth-Mode": "api"},
        )
        assert api_resp.status_code == 200
        api_data = api_resp.json()
        assert api_data["access_token"] is not None


def test_incorrect_credentials_rejected():
    client = get_fresh_client()
    # Wrong password
    resp1 = client.post("/auth/login", json={"username": "admin_anita", "password": "wrongpassword999"})
    assert resp1.status_code == 401
    assert "Invalid username or password" in resp1.json()["detail"]

    # Nonexistent username
    resp2 = client.post("/auth/login", json={"username": "nonexistent_hacker", "password": "anypassword"})
    assert resp2.status_code == 401
    # Generic error message: no username enumeration
    assert "Invalid username or password" in resp2.json()["detail"]


def test_user_roles_come_from_database():
    client = get_fresh_client()
    # Verify support_ravi role
    login_resp = client.post(
        "/auth/login",
        json={"username": "support_ravi", "password": "password123"},
        headers={"X-Auth-Mode": "api"},
    )
    token = login_resp.json()["access_token"]

    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["role"] == "Support"

    db_user = get_user_by_username("support_ravi")
    assert db_user is not None
    assert db_user["role"] == "Support"


def test_client_supplied_role_changes_ignored():
    client = get_fresh_client()
    # Authenticate as Support
    login_resp = client.post(
        "/auth/login",
        json={"username": "support_ravi", "password": "password123"},
        headers={"X-Auth-Mode": "api"},
    )
    token = login_resp.json()["access_token"]

    # Client maliciously asks for Admin role in query body
    query_resp = client.post(
        "/query",
        json={"role": "Admin", "sql": "SELECT cust_nm, mob_no FROM customers LIMIT 1"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert query_resp.status_code == 200
    data = query_resp.json()
    # Backend overrides requested role with verified database role
    assert data["meta"]["role_applied"] == "Support"
    assert data["meta"]["auth_source"] == "jwt_verified"
    # Support masking applied (phone masked)
    phone_val = str(data["rows"][0][1])
    assert "XXXXXX" in phone_val or "***" in phone_val


def test_inactive_accounts_cannot_authenticate_or_use_tokens():
    client = get_fresh_client()
    # 1. Create a dedicated test user and deactivate them
    test_user = "test_disabled_user"
    conn = get_auth_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE username = ?", (test_user,))
        conn.commit()
    finally:
        conn.close()

    user_id = create_user(
        username=test_user,
        email="disabled@saffronbank.local",
        full_name="Disabled User",
        password_hash=hash_password("password123"),
        role="Support",
        is_active=1
    )

    # Issue token while active
    token = create_access_token({"sub": test_user, "role": "Support"})

    # Now deactivate account
    set_user_active_status(user_id, is_active=0)

    # Login must fail
    login_resp = client.post("/auth/login", json={"username": test_user, "password": "password123"})
    assert login_resp.status_code == 401
    assert "disabled" in login_resp.json()["detail"].lower()

    # Using existing token must be rejected
    query_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert query_resp.status_code == 401
    assert "deactivated" in query_resp.json()["detail"].lower()


def test_revoked_tokens_cannot_be_reused():
    client = get_fresh_client()
    login_resp = client.post(
        "/auth/login",
        json={"username": "analyst_kavya", "password": "password123"},
        headers={"X-Auth-Mode": "api"},
    )
    token = login_resp.json()["access_token"]

    # Verify token works
    pre_logout = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert pre_logout.status_code == 200

    # Logout and revoke token
    logout_resp = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_resp.status_code == 200
    assert logout_resp.json()["status"] == "ok"

    # Token should now be completely rejected
    post_logout = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert post_logout.status_code == 401
    assert "revoked" in post_logout.json()["detail"].lower()


def test_expired_tokens_are_rejected():
    client = get_fresh_client()
    expired_token = create_access_token(
        {"sub": "admin_anita", "role": "Admin"},
        expires_delta=timedelta(seconds=-30)
    )
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


def test_unauthenticated_requests_rejected():
    client = get_fresh_client()
    # Unauthenticated /query -> 401
    r_query = client.post("/query", json={"sql": "SELECT 1"})
    assert r_query.status_code == 401
    assert "Authentication required" in r_query.json()["detail"]

    # Unauthenticated /scan -> 401
    r_scan = client.get("/scan")
    assert r_scan.status_code == 401

    # Unauthenticated /database/info -> 401
    r_db = client.get("/database/info")
    assert r_db.status_code == 401

    # Unauthenticated /scan/start -> 401
    r_start = client.post("/scan/start")
    assert r_start.status_code == 401

    # Unauthenticated /scan/status -> 401
    r_status = client.get("/scan/status")
    assert r_status.status_code == 401

    # Unauthenticated /scan/history -> 401
    r_history = client.get("/scan/history")
    assert r_history.status_code == 401


def test_rbac_support_and_analyst_cannot_access_admin_operations():
    client = get_fresh_client()
    # 1. Support caller
    sup_login = client.post(
        "/auth/login",
        json={"username": "support_ravi", "password": "password123"},
        headers={"X-Auth-Mode": "api"},
    )
    sup_token = sup_login.json()["access_token"]
    sup_resp = client.post("/scan/start", headers={"Authorization": f"Bearer {sup_token}"})
    assert sup_resp.status_code == 403
    assert "Only administrators" in sup_resp.json()["detail"]

    # 2. Analyst caller
    ana_login = client.post(
        "/auth/login",
        json={"username": "analyst_kavya", "password": "password123"},
        headers={"X-Auth-Mode": "api"},
    )
    ana_token = ana_login.json()["access_token"]
    ana_resp = client.post("/scan/start", headers={"Authorization": f"Bearer {ana_token}"})
    assert ana_resp.status_code == 403
    assert "Only administrators" in ana_resp.json()["detail"]


def test_admin_can_access_authorized_operations():
    client = get_fresh_client()
    admin_login = client.post(
        "/auth/login",
        json={"username": "admin_anita", "password": "password123"},
        headers={"X-Auth-Mode": "api"},
    )
    admin_token = admin_login.json()["access_token"]

    # Admin accesses /scan/start
    start_resp = client.post("/scan/start", headers={"Authorization": f"Bearer {admin_token}"})
    assert start_resp.status_code == 200
    assert "task_id" in start_resp.json()

    # Admin accesses /database/info
    db_resp = client.get("/database/info", headers={"Authorization": f"Bearer {admin_token}"})
    assert db_resp.status_code == 200
    assert db_resp.json()["total_tables"] == 9

    # Admin accesses /query and receives unmasked data
    q_resp = client.post(
        "/query",
        json={"sql": "SELECT cust_nm, mob_no FROM customers LIMIT 1"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert q_resp.status_code == 200
    assert q_resp.json()["meta"]["role_applied"] == "Admin"


def test_account_lockout_after_consecutive_failed_logins():
    client = get_fresh_client()
    target_user = "lockout_test_user"
    conn = get_auth_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE username = ?", (target_user,))
        conn.commit()
    finally:
        conn.close()

    create_user(
        username=target_user,
        email="lockout@saffronbank.local",
        full_name="Lockout Test User",
        password_hash=hash_password("correct_password_123"),
        role="Support"
    )

    # Attempt 5 incorrect logins
    for i in range(5):
        resp = client.post("/auth/login", json={"username": target_user, "password": f"wrong_{i}"})
        assert resp.status_code == 401

    # Attempt with correct password while locked
    locked_resp = client.post("/auth/login", json={"username": target_user, "password": "correct_password_123"})
    assert locked_resp.status_code == 401
    assert "locked" in locked_resp.json()["detail"].lower()


def test_saffron_bank_database_hash_unchanged():
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "saffron_bank.db")
    assert os.path.exists(db_path), f"Database not found at {db_path}"

    hasher = hashlib.sha256()
    with open(db_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    actual_hash = hasher.hexdigest().upper()
    assert actual_hash == EXPECTED_SAFFRON_HASH, f"Saffron Bank database mutated! Got: {actual_hash}"

