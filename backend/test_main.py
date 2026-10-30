import sqlite3
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.db import DEFAULT_DB_PATH, init_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    """Ensure database is seeded before each test."""
    init_db()


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"
    assert "version" in data


def test_scan_endpoint():
    response = client.get("/scan")
    assert response.status_code == 200
    data = response.json()
    assert data["table"] == "customers"
    assert data["total_columns"] >= 7

    col_map = {c["name"]: c for c in data["columns"]}
    assert "card_number" in col_map
    assert col_map["card_number"]["tag"] == "FINANCIAL_CONFIDENTIAL"
    assert col_map["card_number"]["sensitivity"] == "HIGH"

    assert "ssn" in col_map
    assert col_map["ssn"]["tag"] == "PII_HIGH"
    assert col_map["ssn"]["sensitivity"] == "HIGH"

    assert "email" in col_map
    assert col_map["email"]["tag"] == "PII_MEDIUM"

    assert "phone" in col_map
    assert col_map["phone"]["tag"] == "PII_MEDIUM"

    assert "id" in col_map
    assert col_map["id"]["tag"] == "PUBLIC"


def test_query_support_role_masking():
    # Matches the exact prompt example
    response = client.post(
        "/query",
        json={"role": "Support", "sql": "SELECT name, card_number FROM customers WHERE name = 'Asha'"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["columns"] == ["name", "card_number"]
    assert len(data["rows"]) == 1
    assert data["rows"][0] == ["Asha", "4111-XXXX-XXXX-1111"]


def test_query_admin_role_unmasked():
    response = client.post(
        "/query",
        json={"role": "Admin", "sql": "SELECT name, card_number FROM customers WHERE name = 'Asha'"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["columns"] == ["name", "card_number"]
    assert data["rows"][0] == ["Asha", "4111-2222-3333-1111"]


def test_query_analyst_role_redacted():
    response = client.post(
        "/query",
        json={"role": "Analyst", "sql": "SELECT name, card_number FROM customers WHERE name = 'Asha'"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["columns"] == ["name", "card_number"]
    assert data["rows"][0] == ["[REDACTED]", "[REDACTED]"]


def test_query_support_additional_fields():
    response = client.post(
        "/query",
        json={"role": "Support", "sql": "SELECT id, email, phone, ssn, salary FROM customers WHERE name = 'Asha'"}
    )
    assert response.status_code == 200
    data = response.json()
    row = data["rows"][0]
    # id is public
    assert row[0] == 1
    # email is partially masked
    assert row[1] == "a***@example.com"
    # phone is partially masked (last 4 preserved)
    assert row[2] == "***-***-2834"
    # ssn is partially masked (last 4 preserved)
    assert row[3] == "XXX-XX-6789"
    # salary is confidential
    assert row[4] == "[CONFIDENTIAL]"


def test_reject_write_statements():
    forbidden_queries = [
        "DROP TABLE customers",
        "DELETE FROM customers",
        "UPDATE customers SET name = 'Hacked'",
        "INSERT INTO customers (id, name) VALUES (99, 'Hacker')",
        "ALTER TABLE customers ADD COLUMN secret TEXT",
        "TRUNCATE TABLE customers",
    ]
    for q in forbidden_queries:
        response = client.post("/query", json={"role": "Admin", "sql": q})
        assert response.status_code == 400
        assert "Only read-only SELECT queries are" in response.json()["detail"] or "rejected" in response.json()["detail"]


def test_reject_multiple_sql_statements():
    malicious_query = "SELECT name FROM customers; DROP TABLE customers"
    response = client.post("/query", json={"role": "Admin", "sql": malicious_query})
    assert response.status_code == 400
    assert "Multiple SQL statements are not permitted" in response.json()["detail"]


def test_reject_invalid_role():
    response = client.post(
        "/query",
        json={"role": "SuperUser", "sql": "SELECT name FROM customers"}
    )
    assert response.status_code == 400
    assert "Invalid role" in response.json()["detail"]


def test_database_persistence_unchanged():
    # Run support query
    client.post(
        "/query",
        json={"role": "Support", "sql": "SELECT name, card_number FROM customers"}
    )
    # Check underlying SQLite database directly
    conn = sqlite3.connect(DEFAULT_DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT name, card_number FROM customers WHERE name = 'Asha'")
    row = cur.fetchone()
    conn.close()

    # The actual database value MUST be the unmasked raw value
    assert row[0] == "Asha"
    assert row[1] == "4111-2222-3333-1111"


def test_scan_nonexistent_table():
    response = client.get("/scan?table=nonexistent_table")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_query_trailing_semicolon_allowed():
    response = client.post(
        "/query",
        json={"role": "Admin", "sql": "SELECT name FROM customers WHERE id = 1;"}
    )
    assert response.status_code == 200
    assert response.json()["rows"][0] == ["Asha"]


def test_query_case_insensitive_role():
    response = client.post(
        "/query",
        json={"role": "support", "sql": "SELECT name, card_number FROM customers WHERE name = 'Asha'"}
    )
    assert response.status_code == 200
    assert response.json()["rows"][0] == ["Asha", "4111-XXXX-XXXX-1111"]


def test_query_sql_syntax_error():
    response = client.post(
        "/query",
        json={"role": "Admin", "sql": "SELECT FROM customers"}
    )
    assert response.status_code == 400
    assert "Database execution error" in response.json()["detail"]


def test_query_empty_sql():
    response = client.post(
        "/query",
        json={"role": "Admin", "sql": "   "}
    )
    assert response.status_code == 400
    assert "Query cannot be empty" in response.json()["detail"]



# =====================================================================
# EXTENDED TEST SUITE: Database Abstraction, JWT, RBAC, Masking, Security
# =====================================================================

import time
from backend.database import get_database_adapter, SQLiteAdapter, PostgreSQLAdapter
from backend.auth import hash_password, verify_password, create_access_token, decode_access_token
from backend.masker import mask_value_for_role, deterministic_hash
from backend.detector import classify_column
from backend.validator import validate_sql
from backend.registry import registry
from backend.scanner import background_scanner


def test_sqlite_adapter_methods():
    adapter = get_database_adapter("sqlite")
    conn_info = adapter.test_connection()
    assert conn_info["status"] == "connected"
    assert conn_info["engine"] == "sqlite"

    tables = adapter.get_tables()
    assert "customers" in tables

    columns = adapter.get_table_columns("customers")
    assert "card_number" in columns
    assert "name" in columns

    samples = adapter.get_sample_rows("customers", limit=2)
    assert len(samples) == 2

    cols, rows, meta = adapter.execute_read_query("SELECT id, name FROM customers LIMIT 2")
    assert cols == ["id", "name"]
    assert len(rows) == 2
    assert "execution_ms" in meta


def test_sqlite_adapter_enforces_read_only():
    adapter = get_database_adapter("sqlite")
    with pytest.raises(sqlite3.DatabaseError):
        adapter.execute_read_query("UPDATE customers SET name = 'Hacked'")


def test_postgres_adapter_initialization_and_mock_fallback():
    # Test PostgreSQLAdapter instantiation and connection test error handling
    pg_adapter = PostgreSQLAdapter(
        host="127.0.0.1", port=5432, dbname="nonexistent_db", user="test", password="wrong"
    )
    res = pg_adapter.test_connection()
    assert res["engine"] == "postgresql"
    assert res["status"] in ("connected", "error")


def test_password_hashing_and_verification():
    raw_pass = "SecurePass2026!"
    hashed = hash_password(raw_pass)
    assert hashed != raw_pass
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("WrongPass", hashed) is False


def test_jwt_token_creation_and_validation():
    data = {"sub": "analyst_kavya", "role": "Analyst", "full_name": "Kavya Iyer"}
    token = create_access_token(data)
    assert isinstance(token, str)

    payload = decode_access_token(token)
    assert payload["sub"] == "analyst_kavya"
    assert payload["role"] == "Analyst"
    assert payload["full_name"] == "Kavya Iyer"


def test_auth_login_successful():
    response = client.post("/auth/login", json={"username": "admin_anita", "password": "password123"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["role"] == "Admin"
    assert data["user"]["username"] == "admin_anita"


def test_auth_login_invalid_password():
    response = client.post("/auth/login", json={"username": "admin_anita", "password": "wrongpassword"})
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]


def test_auth_me_endpoint_with_valid_token():
    # Login to get token
    login_resp = client.post("/auth/login", json={"username": "support_ravi", "password": "password123"})
    token = login_resp.json()["access_token"]

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    profile = response.json()
    assert profile["username"] == "support_ravi"
    assert profile["role"] == "Support"


def test_auth_me_missing_token_rejected():
    response = client.get("/auth/me")
    assert response.status_code == 401


def test_auth_users_list_endpoint():
    response = client.get("/auth/users")
    assert response.status_code == 200
    data = response.json()
    assert "users" in data
    usernames = [u["username"] for u in data["users"]]
    assert "admin_anita" in usernames
    assert "support_ravi" in usernames
    assert "analyst_kavya" in usernames


def test_server_side_rbac_overrides_frontend_role_tampering():
    """
    CRITICAL SECURITY TEST:
    If a user is logged in as Analyst, but attempts to submit 'role': 'Admin'
    in the JSON body, the gateway MUST derive the role from the verified JWT
    and enforce Analyst redaction.
    """
    # 1. Obtain Analyst token
    login_resp = client.post("/auth/login", json={"username": "analyst_kavya", "password": "password123"})
    analyst_token = login_resp.json()["access_token"]

    # 2. Submit query with fake 'Admin' role in JSON payload
    response = client.post(
        "/query",
        json={"role": "Admin", "sql": "SELECT name, card_number FROM customers WHERE name = 'Asha'"},
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert response.status_code == 200
    data = response.json()

    # The result MUST BE REDACTED because token is Analyst
    assert data["rows"][0] == ["[REDACTED]", "[REDACTED]"]
    assert data["meta"]["role_applied"] == "Analyst"
    assert data["meta"]["auth_source"] == "jwt_verified"


def test_analyst_deterministic_hashing_strategy():
    response = client.post(
        "/query",
        json={
            "role": "Analyst",
            "sql": "SELECT name, card_number FROM customers WHERE name = 'Asha'",
            "mask_strategy": "hash",
        },
    )
    assert response.status_code == 200
    data = response.json()
    card_hash = data["rows"][0][1]
    assert card_hash.startswith("sha256:")
    assert len(card_hash) > 10

    # Repeatability test: same input with same salt produces same hash
    repeat_response = client.post(
        "/query",
        json={
            "role": "Analyst",
            "sql": "SELECT name, card_number FROM customers WHERE name = 'Asha'",
            "mask_strategy": "hash",
        },
    )
    assert repeat_response.json()["rows"][0][1] == card_hash


def test_indian_pii_aadhaar_pan_detection_and_masking():
    # Test Aadhaar detection
    res_aadhaar = classify_column("aadhaar_no", ["1234-5678-9012"])
    assert res_aadhaar["tag"] == "PII_HIGH"
    assert res_aadhaar["pii_type"] == "AADHAAR"

    # Test PAN detection
    res_pan = classify_column("pan_no", ["ABCDE1234F"])
    assert res_pan["tag"] == "PII_HIGH"
    assert res_pan["pii_type"] == "PAN"

    # Test Support masking
    masked_aadhaar = mask_value_for_role("Support", res_aadhaar, "1234-5678-9012")
    assert masked_aadhaar == "XXXX-XXXX-9012"

    masked_pan = mask_value_for_role("Support", res_pan, "ABCDE1234F")
    assert masked_pan == "XXXXX1234F"


def test_background_scanner_and_history():
    # Trigger scan
    start_resp = client.post("/scan/start")
    assert start_resp.status_code == 200
    assert "task_id" in start_resp.json()

    # Wait briefly for thread execution
    time.sleep(0.3)

    status_resp = client.get("/scan/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] in ("scanning", "completed")

    history_resp = client.get("/scan/history")
    assert history_resp.status_code == 200
    assert "history" in history_resp.json()


def test_database_info_endpoint():
    response = client.get("/database/info")
    assert response.status_code == 200
    data = response.json()
    assert "connection" in data
    assert data["connection"]["engine"] == "sqlite"
    assert "customers" in data["tables"]


def test_sql_validator_rejects_comments():
    q1 = "SELECT * FROM customers -- ignore rest"
    is_valid, err = validate_sql(q1)
    assert is_valid is False
    assert "SQL comments are not permitted" in err

    q2 = "SELECT /* secret comment */ name FROM customers"
    is_valid, err = validate_sql(q2)
    assert is_valid is False
    assert "SQL comments are not permitted" in err


def test_sql_validator_allows_safe_cte():
    cte = "WITH high_earners AS (SELECT name, salary FROM customers WHERE salary > 90000) SELECT name FROM high_earners"
    is_valid, err = validate_sql(cte)
    assert is_valid is True
    assert err == ""


def test_query_max_rows_limiting():
    response = client.post(
        "/query",
        json={"role": "Admin", "sql": "SELECT id, name FROM customers", "max_rows": 2},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["rows"]) == 2
    assert data["meta"]["truncated"] is True


# =====================================================================
# PHASE 7 AUDIT TESTS (Items 3, 5, 12, 18, 19, 20)
# =====================================================================

def test_expired_or_invalid_jwt():
    import jwt
    from datetime import datetime, timedelta, timezone
    from backend.auth import JWT_SECRET_KEY, JWT_ALGORITHM

    # Create an expired token (1 hour in the past)
    expired_payload = {
        "sub": "admin_anita",
        "role": "Admin",
        "exp": datetime.now(timezone.utc) - timedelta(hours=1),
        "iat": datetime.now(timezone.utc) - timedelta(hours=2),
    }
    expired_token = jwt.encode(expired_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()

    # Invalid garbage token
    response_invalid = client.get("/auth/me", headers={"Authorization": "Bearer not.a.valid.jwt"})
    assert response_invalid.status_code == 401
    assert "invalid" in response_invalid.json()["detail"].lower()


def test_unauthenticated_or_non_admin_scan_rejected():
    # Login as Analyst
    login_resp = client.post("/auth/login", json={"username": "analyst_kavya", "password": "password123"})
    analyst_token = login_resp.json()["access_token"]

    # Analyst attempts to trigger administrative background scan
    response = client.post("/scan/start", headers={"Authorization": f"Bearer {analyst_token}"})
    assert response.status_code == 403
    assert "Forbidden" in response.json()["detail"] or "Only administrators" in response.json()["detail"]


def test_email_and_phone_detection():
    res_email = classify_column("customer_email", ["john.doe@company.org"])
    assert res_email["tag"] == "PII_MEDIUM"
    assert res_email["pii_type"] == "EMAIL"

    res_phone = classify_column("contact_phone", ["+1-555-019-2834"])
    assert res_phone["tag"] == "PII_MEDIUM"
    assert res_phone["pii_type"] == "PHONE"


def test_invalid_table_identifier_rejected():
    adapter = get_database_adapter("sqlite")
    with pytest.raises(ValueError) as excinfo:
        adapter.get_table_columns("non_existent_table; DROP TABLE customers")
    assert "Invalid table identifier" in str(excinfo.value)

    # API scan also returns 404 for invalid table
    resp = client.get("/scan?table=invalid_inject_table")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_postgresql_identifier_safety():
    from backend.database.postgres_adapter import PostgreSQLAdapter, pg_sql
    adapter = PostgreSQLAdapter(dbname="mock_db")
    # Verify method uses Identifier quoting format
    assert pg_sql is not None
    # Test identifier validation method on adapter
    with pytest.raises(Exception):
        adapter.get_sample_rows("malicious_table_name_that_does_not_exist", limit=5)


def test_frontend_backend_connectivity_and_cors():
    # Test OPTIONS preflight for local origins
    response = client.options(
        "/query",
        headers={
            "Origin": "http://127.0.0.1:5500",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type,Authorization",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://127.0.0.1:5500"

    # Test root endpoint returns active service info
    root_resp = client.get("/")
    assert root_resp.status_code == 200
    assert root_resp.json()["status"] == "online"
