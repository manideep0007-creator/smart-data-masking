import sqlite3
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.db import DEFAULT_DB_PATH, init_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database(monkeypatch):
    """Ensure database is seeded before each test and runs against demo db for legacy test assertions."""
    monkeypatch.setenv("DB_PATH", DEFAULT_DB_PATH)
    init_db(DEFAULT_DB_PATH)


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


# =====================================================================
# SAFFRON BANK PII DETECTION & AUDIT TESTS (STEP 3, 3.1 & 3.2)
# =====================================================================

def test_saffron_bank_positive_pii_detection():
    from backend.detector import classify_column

    # 1. Names (Customer, Parent, Nominee, Cardholder)
    for col in ["cust_nm", "pita_nm", "nominee_nm", "name_on_card", "NAME_ON_CARD"]:
        res = classify_column(col)
        assert res["tag"] == "PII_LOW", f"Expected PII_LOW for {col}, got {res['tag']}"
        assert res["pii_type"] == "NAME", f"Expected NAME for {col}, got {res['pii_type']}"

    # 2. Contact details
    for col in ["mob_no", "alt_mob", "us_phone"]:
        res = classify_column(col)
        assert res["tag"] == "PII_MEDIUM", f"Expected PII_MEDIUM for {col}, got {res['tag']}"
        assert res["pii_type"] == "PHONE", f"Expected PHONE for {col}, got {res['pii_type']}"

    res_email = classify_column("emailid")
    assert res_email["tag"] == "PII_MEDIUM", f"Expected PII_MEDIUM for emailid, got {res_email['tag']}"
    assert res_email["pii_type"] == "EMAIL", f"Expected EMAIL for emailid, got {res_email['pii_type']}"

    # 3. Addresses
    for col in ["addr_line1", "addr_line2", "addr", "us_addr", "city", "us_city", "state", "us_state", "pincode", "us_zip"]:
        res = classify_column(col)
        assert res["tag"] == "PII_MEDIUM", f"Expected PII_MEDIUM for {col}, got {res['tag']}"
        assert res["pii_type"] == "ADDRESS", f"Expected ADDRESS for {col}, got {res['pii_type']}"

    # 4. Government IDs
    res_pan = classify_column("pan_no")
    assert res_pan["tag"] == "PII_HIGH" and res_pan["pii_type"] == "PAN"

    res_aadhaar = classify_column("aadhaar_no")
    assert res_aadhaar["tag"] == "PII_HIGH" and res_aadhaar["pii_type"] == "AADHAAR"

    res_ssn = classify_column("ssn")
    assert res_ssn["tag"] == "PII_HIGH" and res_ssn["pii_type"] == "SSN"

    # 5. Financial accounts, cards, and balances
    res_card = classify_column("CARD_NO")
    assert res_card["tag"] == "FINANCIAL_CONFIDENTIAL" and res_card["pii_type"] == "CREDIT_CARD"

    for col in ["account_no", "linked_acct", "curr_bal", "credit_limit", "outstanding_amt", "declared_income_inr", "sanctioned_amt_inr", "credit_score", "amount_inr", "bal_after"]:
        res = classify_column(col)
        assert res["tag"] == "FINANCIAL_CONFIDENTIAL", f"Expected FINANCIAL_CONFIDENTIAL for {col}, got {res['tag']}"
        assert res["pii_type"] == "FINANCIAL", f"Expected FINANCIAL for {col}, got {res['pii_type']}"

    # 6. Personal Date of Birth
    res_dob = classify_column("dob_dt")
    assert res_dob["tag"] == "PII_MEDIUM" and res_dob["pii_type"] == "DATE_OF_BIRTH"


def test_saffron_bank_false_positive_exclusions():
    from backend.detector import classify_column

    # Technical references, audit fields, and organizational/public entities must NOT be flagged as PII
    non_pii_cols = [
        "txn_id", "transaction_id", "ref_no", "rrn", "branch_code", "card_ref",
        "ticket_id", "app_id", "kyc_id", "customer_id", "cif", "cust_id", "id",
        "card_network", "card_type", "card_variant", "card_status",
        "acct_status", "kyc_status", "txn_status", "acct_type", "loan_type",
        "ovd_type", "status", "gender", "occupation", "segment", "risk_cat",
        "preferred_lang", "priority", "channel", "decision", "emp_type",
        "open_dt", "last_txn_dt", "applied_on", "created_ts", "resolved_ts",
        "issued_on", "verified_on", "next_review_dt", "opened_on", "customer_since",
        "last_login_ts", "txn_ts", "fatca_reported_on", "exp_mm", "exp_yyyy",
        "branch_nm", "tenure_mths", "roi_pct", "int_rate_pct", "ifsc",
        "branch_phone", "branch_email", "employer_nm", "counterparty",
        "verified_by", "assigned_to"
    ]

    for col in non_pii_cols:
        sample_vals = ["7306089151955450"] if "id" in col or "ref" in col else ["ACTIVE"]
        res = classify_column(col, sample_vals)
        assert res["tag"] == "PUBLIC", f"Expected PUBLIC for {col}, but got {res['tag']} ({res['pii_type']})"
        assert res["pii_type"] == "NONE", f"Expected NONE for {col}, but got {res['pii_type']}"


def test_saffron_bank_precision_audit_cases():
    """Targeted tests for Step 3.1 & 3.2 PII Classification Precision Audit."""
    from backend.detector import classify_column

    # 1. Branch organizational contact channels & locations (Public vs Personal PII)
    res_bphone = classify_column("branch_phone", ["+91-361-2345678"])
    assert res_bphone["tag"] == "PUBLIC"
    assert res_bphone["pii_type"] == "NONE"

    res_bemail = classify_column("branch_email", ["guwahati.neelgiri@saffronbank.example"])
    assert res_bemail["tag"] == "PUBLIC"
    assert res_bemail["pii_type"] == "NONE"

    # Branch directory addresses with table context
    res_baddr = classify_column("addr", ["Ground Floor, 214 Palm Road"], table_name="branches")
    assert res_baddr["tag"] == "PUBLIC"
    assert res_baddr["pii_type"] == "NONE"

    res_bcity = classify_column("city", ["Bengaluru"], table_name="branches")
    assert res_bcity["tag"] == "PUBLIC"

    # 2. Employer name & Counterparty (Organizational entity vs Individual PII)
    res_emp = classify_column("employer_nm", ["Municipal Corporation", "Kaveri Cements Ltd", "Pragati Engineering Co"])
    assert res_emp["tag"] == "PUBLIC"
    assert res_emp["pii_type"] == "NONE"

    res_cp = classify_column("counterparty", ["MUNICIPAL CORPORATION", "SAFFRON RETAIL GROUP", "ELECTRICITY BOARD"])
    assert res_cp["tag"] == "PUBLIC"
    assert res_cp["pii_type"] == "NONE"

    # 3. Operational routing & employee IDs
    res_assigned = classify_column("assigned_to", ["nri_desk_14", "cc_agent_02"])
    assert res_assigned["tag"] == "PUBLIC"
    assert res_assigned["pii_type"] == "NONE"

    res_verified = classify_column("verified_by", ["E414683", "E293428"])
    assert res_verified["tag"] == "PUBLIC"
    assert res_verified["pii_type"] == "NONE"

    # 4. Demographic attributes (Public categorical)
    assert classify_column("gender", ["Male", "Female"])["tag"] == "PUBLIC"
    assert classify_column("occupation", ["Salaried - Private", "Business Owner"])["tag"] == "PUBLIC"

    # 5. Unstructured text & semi-structured payloads (Column-level flag verification)
    for col in ["ticket_text", "notes", "remarks", "extra_info", "kyc_meta"]:
        res_text = classify_column(col, ["Customer support note or KYC JSON"])
        assert res_text["tag"] == "PII_MEDIUM"
        assert res_text["pii_type"] == "UNSTRUCTURED_TEXT"
        assert "column-level flag; not inline NLP extraction" in res_text["heuristic"]

    # 6. col_7 PAN sample-value detection precision (Positive and Negative verification)
    # Positive PAN samples
    pan_positives = ["AHLPP0000O", "AKZPS0000Q", "BNZPG0000Z", "DFCPS0000K"]
    res_pan_pos = classify_column("col_7", pan_positives)
    assert res_pan_pos["tag"] == "PII_HIGH"
    assert res_pan_pos["pii_type"] == "PAN"

    # Negative non-PAN samples (IFSC, transaction references, amounts, status words)
    assert classify_column("col_7", ["SAFF0027168"])["tag"] == "PUBLIC"  # IFSC (SAFF + 0 + 6 digits)
    assert classify_column("col_7", ["TXN9988776655"])["tag"] == "PUBLIC"  # Alphanumeric txn ID
    assert classify_column("col_7", ["ACTIVE", "PENDING", "APPROVED"])["tag"] == "PUBLIC"  # Status words
    assert classify_column("col_7", ["50000.00", "125000.50"])["tag"] == "PUBLIC"  # Financial amounts
    assert classify_column("col_7", ["98765432109876"])["tag"] == "PUBLIC"  # 14-digit account number


# =====================================================================
# STEP 5A: CORE PII MASKING IMPROVEMENTS & PRECISION TESTS
# =====================================================================

def test_step5a_account_and_linked_account_masking():
    from backend.masker import mask_account_support, mask_value_for_role

    # Direct helper verification
    assert mask_account_support("123456789012") == "********9012"
    assert mask_account_support("987654321098") == "********1098"
    assert mask_account_support("12345678") == "****5678"
    assert mask_account_support("12") == "********"

    # Role-based dispatch for account_no and LINKED_ACCT
    acct_meta = {"name": "account_no", "tag": "FINANCIAL_CONFIDENTIAL", "pii_type": "FINANCIAL"}
    linked_meta = {"name": "LINKED_ACCT", "tag": "FINANCIAL_CONFIDENTIAL", "pii_type": "FINANCIAL"}
    bal_meta = {"name": "curr_bal", "tag": "FINANCIAL_CONFIDENTIAL", "pii_type": "FINANCIAL"}

    # Support role
    assert mask_value_for_role("Support", acct_meta, "123456789012") == "********9012"
    assert mask_value_for_role("Support", linked_meta, "987654321098") == "********1098"
    assert mask_value_for_role("Support", bal_meta, "54200.50") == "[CONFIDENTIAL]"

    # Analyst role: redaction & hashing
    assert mask_value_for_role("Analyst", acct_meta, "123456789012", mask_strategy="redact") == "[REDACTED]"
    analyst_hash = mask_value_for_role("Analyst", acct_meta, "123456789012", mask_strategy="hash")
    assert analyst_hash.startswith("sha256:")
    assert len(analyst_hash) == 39  # sha256: (7) + 32 hex chars = 39

    # Admin role: unmasked
    assert mask_value_for_role("Admin", acct_meta, "123456789012") == "123456789012"


def test_step5a_dob_masking():
    from backend.masker import mask_dob_support, mask_value_for_role

    # Direct helper verification
    assert mask_dob_support("1995-08-14") == "1995-**-**"
    assert mask_dob_support("1982/11/25") == "1982-**-**"
    assert mask_dob_support("2001-01-01 12:00:00") == "2001-**-**"
    assert mask_dob_support("invalid-dob") == "****-**-**"

    dob_meta = {"name": "dob_dt", "tag": "PII_MEDIUM", "pii_type": "DATE_OF_BIRTH"}

    # Support role
    assert mask_value_for_role("Support", dob_meta, "1995-08-14") == "1995-**-**"

    # Analyst role: never receives original DOB
    assert mask_value_for_role("Analyst", dob_meta, "1995-08-14", mask_strategy="redact") == "[REDACTED]"
    analyst_dob_hash = mask_value_for_role("Analyst", dob_meta, "1995-08-14", mask_strategy="hash")
    assert analyst_dob_hash.startswith("sha256:")
    assert "1995" not in analyst_dob_hash

    # Admin role: unmasked
    assert mask_value_for_role("Admin", dob_meta, "1995-08-14") == "1995-08-14"


def test_step5a_pincode_masking():
    from backend.masker import mask_pincode_support, mask_value_for_role

    # Direct helper verification
    assert mask_pincode_support("560083") == "560***"
    assert mask_pincode_support("781004") == "781***"
    assert mask_pincode_support("10001") == "10***"
    assert mask_pincode_support("12") == "******"

    pin_meta = {"name": "pincode", "tag": "PII_MEDIUM", "pii_type": "ADDRESS"}
    zip_meta = {"name": "us_zip", "tag": "PII_MEDIUM", "pii_type": "ADDRESS"}
    addr_meta = {"name": "addr_line1", "tag": "PII_MEDIUM", "pii_type": "ADDRESS"}

    # Support role
    assert mask_value_for_role("Support", pin_meta, "560083") == "560***"
    assert mask_value_for_role("Support", zip_meta, "10001") == "10***"
    assert mask_value_for_role("Support", addr_meta, "Flat 402, Neelgiri") == "***, Neelgiri"

    # Analyst role
    assert mask_value_for_role("Analyst", pin_meta, "560083") == "[REDACTED]"


def test_step5a_hmac_determinism_length_and_idempotence():
    from backend.masker import deterministic_hash, MaskedToken, mask_value_for_role

    # Length test: 32 hex chars (128 bits) + 7 chars for "sha256:" = 39 total
    token = deterministic_hash("cust_secret_123")
    assert token.startswith("sha256:")
    assert len(token) == 39
    hex_digest = token.split("sha256:")[1]
    assert len(hex_digest) == 32
    assert all(c in "0123456789abcdef" for c in hex_digest)

    # Determinism test
    token2 = deterministic_hash("cust_secret_123")
    assert token == token2

    # Distinctness test
    token_diff = deterministic_hash("cust_secret_456")
    assert token != token_diff

    # Idempotence: MaskedToken is not re-hashed
    assert isinstance(token, MaskedToken)
    token_rehashed = deterministic_hash(token)
    assert token_rehashed == token
    assert token_rehashed is token

    # Verification that raw string matching sha256: pattern IS safely hashed (not falsely bypassed)
    raw_spoofed_str = "sha256:spoofed_fake_token_not_masked_yet"
    hashed_spoof = deterministic_hash(raw_spoofed_str)
    assert hashed_spoof != raw_spoofed_str
    assert hashed_spoof.startswith("sha256:")

    # Pipeline idempotence via mask_value_for_role
    acct_meta = {"name": "account_no", "tag": "FINANCIAL_CONFIDENTIAL", "pii_type": "FINANCIAL"}
    m1 = mask_value_for_role("Support", acct_meta, "123456789012")
    m2 = mask_value_for_role("Support", acct_meta, m1)
    assert m1 == m2 == "********9012"


def test_step5a_null_empty_and_unexpected_types():
    from backend.masker import (
        mask_account_support,
        mask_dob_support,
        mask_pincode_support,
        deterministic_hash,
        mask_value_for_role,
    )

    # Nulls return safe empty strings
    assert mask_account_support(None) == ""
    assert mask_dob_support(None) == ""
    assert mask_pincode_support(None) == ""
    assert deterministic_hash(None) == ""

    # Empty and whitespace
    assert mask_account_support("") == ""
    assert mask_account_support("   ") == ""
    assert mask_dob_support("") == ""
    assert mask_dob_support("   ") == ""
    assert mask_pincode_support("") == ""
    assert mask_pincode_support("   ") == ""
    assert deterministic_hash("") == ""
    assert deterministic_hash("   ") == ""

    # Integer / numeric inputs
    assert mask_account_support(123456789012) == "********9012"
    assert mask_pincode_support(560083) == "560***"
    int_hash = deterministic_hash(999888777)
    assert int_hash.startswith("sha256:")

    # mask_value_for_role with None raw_value returns None
    meta = {"name": "account_no", "tag": "FINANCIAL_CONFIDENTIAL", "pii_type": "FINANCIAL"}
    assert mask_value_for_role("Support", meta, None) is None
    assert mask_value_for_role("Analyst", meta, None) is None
    assert mask_value_for_role("Admin", meta, None) is None


# =====================================================================
# STEP 5B: CONTEXT-AWARE UNSTRUCTURED TEXT & JSON PII PROTECTION TESTS
# =====================================================================

def test_step5b_unstructured_text_inline_masking():
    from backend.masker import mask_unstructured_text_support

    # 1. Email embedded in ticket text
    s1 = "Customer submitted query from user.support@testcorp.org asking for statement."
    m1 = mask_unstructured_text_support(s1)
    assert "[EMAIL]" in m1
    assert "user.support@testcorp.org" not in m1
    assert "Customer submitted query from [EMAIL] asking for statement." == m1

    # 2. Phone embedded in notes
    s2 = "Agent followed up on mobile 9876543210 regarding issue."
    m2 = mask_unstructured_text_support(s2)
    assert "[PHONE]" in m2
    assert "9876543210" not in m2

    # 3. PAN and Aadhaar embedded in text
    s3 = "Identity verified via PAN ABCDE1234F and Aadhaar 1234-5678-9012 at branch."
    m3 = mask_unstructured_text_support(s3)
    assert "[PAN]" in m3
    assert "[AADHAAR]" in m3
    assert "ABCDE1234F" not in m3
    assert "1234-5678-9012" not in m3

    # 4. Payment card and SSN embedded in text
    s4 = "Charge dispute for card 4111-2222-3333-4444 and SSN 123-45-6789."
    m4 = mask_unstructured_text_support(s4)
    assert "[CREDIT_CARD]" in m4
    assert "[SSN]" in m4
    assert "4111-2222-3333-4444" not in m4
    assert "123-45-6789" not in m4

    # 5. Bank account embedded in extra_info
    s5 = "Old a/c no 015808857442 migrated from legacy CBS"
    m5 = mask_unstructured_text_support(s5)
    assert "[ACCOUNT]" in m5
    assert "015808857442" not in m5

    # 6. Ordinary dates, amounts, and transaction references preserved intact
    s6 = "Transaction SAFF0027168 on date 2026-04-12 for Rs 1500.50 processed successfully."
    m6 = mask_unstructured_text_support(s6)
    assert m6 == s6  # Completely preserved without over-masking!


def test_step5b_kyc_meta_json_masking():
    import json
    from backend.masker import mask_kyc_meta_support

    # 1. Valid nested JSON with sensitive keys
    kyc_payload = {
        "src": "IN-PERSON",
        "ovd": "Aadhaar",
        "name_match": 95,
        "officer": {
            "maker": "E742666",
            "checker": "E768060",
            "father_name": "Synthetic Relative Name"
        },
        "contacts": [
            {"alt_email": "demo.user@synmail.example", "prev_mobile": "9999988888"}
        ],
        "identifiers": {
            "pan": "ABCDE1234F",
            "uid": "1234-5678-9012"
        }
    }
    raw_json = json.dumps(kyc_payload)
    masked_json_str = mask_kyc_meta_support(raw_json)

    # Must remain valid JSON
    parsed = json.loads(masked_json_str)

    # Sensitive fields protected
    assert parsed["officer"]["father_name"] == "[CONFIDENTIAL]"
    assert parsed["contacts"][0]["alt_email"] == "d***@synmail.example"
    assert parsed["contacts"][0]["prev_mobile"] == "***-***-8888"
    assert parsed["identifiers"]["pan"] == "XXXXX1234F"
    assert parsed["identifiers"]["uid"] == "XXXX-XXXX-9012"

    # Non-sensitive audit fields preserved
    assert parsed["src"] == "IN-PERSON"
    assert parsed["ovd"] == "Aadhaar"
    assert parsed["name_match"] == 95
    assert parsed["officer"]["maker"] == "E742666"
    assert parsed["officer"]["checker"] == "E768060"

    # 2. Invalid JSON handling: fallback without leaking raw payload
    invalid_json = "{bad json: father_name: Synthetic Name"
    fallback_res = mask_kyc_meta_support(invalid_json)
    assert fallback_res == "[PROTECTED_METADATA]"
    assert "Synthetic Name" not in fallback_res

    # 3. Null and empty inputs
    assert mask_kyc_meta_support(None) == ""
    assert mask_kyc_meta_support("") == ""
    assert mask_kyc_meta_support("   ") == ""


def test_step5b_role_based_unstructured_protection_and_idempotence():
    import json
    from backend.masker import mask_value_for_role, MaskedToken

    ticket_text = "Customer called from 9876543210 regarding issue."
    kyc_json = json.dumps({"src": "ONLINE", "father_name": "Relative", "name_match": 88})

    ticket_meta = {"name": "ticket_text", "tag": "PII_MEDIUM", "pii_type": "UNSTRUCTURED_TEXT"}
    kyc_meta = {"name": "kyc_meta", "tag": "PII_MEDIUM", "pii_type": "UNSTRUCTURED_TEXT"}

    # 1. Admin receives raw values
    assert mask_value_for_role("Admin", ticket_meta, ticket_text) == ticket_text
    assert mask_value_for_role("Admin", kyc_meta, kyc_json) == kyc_json

    # 2. Support receives context-aware sanitized values
    sup_ticket = mask_value_for_role("Support", ticket_meta, ticket_text)
    assert "[PHONE]" in sup_ticket
    assert "9876543210" not in sup_ticket
    assert "Customer called from [PHONE] regarding issue." == sup_ticket

    sup_kyc = mask_value_for_role("Support", kyc_meta, kyc_json)
    parsed_sup_kyc = json.loads(sup_kyc)
    assert parsed_sup_kyc["father_name"] == "[CONFIDENTIAL]"
    assert parsed_sup_kyc["src"] == "ONLINE"

    # 3. Analyst receives redaction or deterministic hash
    assert mask_value_for_role("Analyst", ticket_meta, ticket_text, mask_strategy="redact") == "[REDACTED]"
    assert mask_value_for_role("Analyst", kyc_meta, kyc_json, mask_strategy="redact") == "[REDACTED]"

    analyst_hash = mask_value_for_role("Analyst", ticket_meta, ticket_text, mask_strategy="hash")
    assert analyst_hash.startswith("sha256:")
    assert len(analyst_hash) == 39

    # 4. Idempotence: repeated masking does not corrupt already-masked output
    repeat_sup_ticket = mask_value_for_role("Support", ticket_meta, sup_ticket)
    assert repeat_sup_ticket == sup_ticket

    repeat_sup_kyc = mask_value_for_role("Support", kyc_meta, sup_kyc)
    assert repeat_sup_kyc == sup_kyc




