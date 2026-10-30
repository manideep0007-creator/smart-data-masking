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

