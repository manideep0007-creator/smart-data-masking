# Smart Data Masking System (Backend MVP)

A lightweight, role-based query gateway built with **FastAPI** and **SQLite**. It heuristically detects Personally Identifiable Information (PII) and sensitive financial data, enforcing dynamic, in-flight masking based on user roles without modifying stored database records.

---

## Architecture & Security Model

```
                    ┌─────────────────────────┐
                    │   Client / Frontend     │
                    └────────────┬────────────┘
                                 │
                     POST /query │ (role + SQL)
                                 ▼
         ┌───────────────────────────────────────────────┐
         │          Smart Data Masking Gateway           │
         │  1. SQL Read-Only Validation (Rejects writes) │
         │  2. Execute query on Read-Only Connection     │
         │  3. Heuristic PII Classification              │
         │  4. In-Memory Role Masking Engine             │
         │     (Admin, Support, Analyst)                 │
         └───────────────────────┬───────────────────────┘
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │   SQLite Database     │
                     │ (Raw records pristine)│
                     └───────────────────────┘
```

### Application-Layer Gateway vs. Direct Database Access
- **Trusted Query Gateway**: This API functions as the trusted query gateway for applications and end users. It validates SQL, blocks multi-statement / write injections, executes queries safely, and intercepts raw results to mask them before sending them over the network.
- **Important Security Consideration**: The masking logic resides at the **application layer**. Any user with direct access to the SQLite file or underlying database host can bypass application-layer masking unless database-level column encryption, row-level security (RLS), or dedicated database access controls are configured.

### Compliance Disclaimer
> [!NOTE]
> This system is a hackathon MVP demonstration prototype. Heuristic pattern matching and application-level role masking assist with privacy preservation, but **this prototype does NOT guarantee full compliance with GDPR, HIPAA, PCI-DSS, or other regulatory standards**. Production implementations require cryptographic field-level encryption, verified identity providers (OAuth2/OIDC), and hardware security modules (HSMs).

---

## Role-Based Access Control (RBAC) Matrix

| Role | Policy | Credit Cards | SSN | Email | Phone | Salary | Customer Name |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Admin** | Full access | `4111-2222-3333-1111` | `123-45-6789` | `asha@example.com` | `555-019-2834` | `85000` | `Asha` |
| **Support** | Partial masking | `4111-XXXX-XXXX-1111` | `XXX-XX-6789` | `a***@example.com` | `***-***-2834` | `[CONFIDENTIAL]` | `Asha` |
| **Analyst** | Redaction | `[REDACTED]` | `[REDACTED]` | `[REDACTED]` | `[REDACTED]` | `[REDACTED]` | `[REDACTED]` |

---

## API Endpoints & Stable JSON Schemas

### 1. `GET /health`
Verifies API status and database connectivity.

**Response `(200 OK)`:**
```json
{
  "status": "ok",
  "database": "connected",
  "version": "1.0.0"
}
```

---

### 2. `GET /scan`
Heuristically inspects database columns, categorizing them by PII sensitivity tags, confidence, and rule heuristics.

**Query Parameters:**
- `table` (optional, default: `"customers"`): Target table to scan.

**Response `(200 OK)`:**
```json
{
  "table": "customers",
  "total_columns": 8,
  "columns": [
    {
      "name": "id",
      "tag": "PUBLIC",
      "pii_type": "NONE",
      "confidence": "HIGH",
      "sensitivity": "NONE",
      "heuristic": "Column has no sensitive PII indicators"
    },
    {
      "name": "name",
      "tag": "PII_LOW",
      "pii_type": "NAME",
      "confidence": "HIGH",
      "sensitivity": "LOW",
      "heuristic": "Column name matches customer name pattern"
    },
    {
      "name": "email",
      "tag": "PII_MEDIUM",
      "pii_type": "EMAIL",
      "confidence": "HIGH",
      "sensitivity": "MEDIUM",
      "heuristic": "Column name matches email address pattern"
    },
    {
      "name": "phone",
      "tag": "PII_MEDIUM",
      "pii_type": "PHONE",
      "confidence": "HIGH",
      "sensitivity": "MEDIUM",
      "heuristic": "Column name matches telephone number pattern"
    },
    {
      "name": "ssn",
      "tag": "PII_HIGH",
      "pii_type": "SSN",
      "confidence": "HIGH",
      "sensitivity": "HIGH",
      "heuristic": "Column name matches government/national ID pattern"
    },
    {
      "name": "card_number",
      "tag": "FINANCIAL_CONFIDENTIAL",
      "pii_type": "CREDIT_CARD",
      "confidence": "HIGH",
      "sensitivity": "HIGH",
      "heuristic": "Column name matches payment card identifier"
    },
    {
      "name": "salary",
      "tag": "FINANCIAL_CONFIDENTIAL",
      "pii_type": "FINANCIAL",
      "confidence": "HIGH",
      "sensitivity": "HIGH",
      "heuristic": "Column name matches financial/salary data"
    },
    {
      "name": "address",
      "tag": "PII_MEDIUM",
      "pii_type": "ADDRESS",
      "confidence": "HIGH",
      "sensitivity": "MEDIUM",
      "heuristic": "Column name matches physical address pattern"
    }
  ]
}
```

---

### 3. `POST /query`
Executes a read-only SELECT query with role-based masking.

**Request Body:**
```json
{
  "role": "Support",
  "sql": "SELECT name, card_number FROM customers"
}
```

**Response `(200 OK)`:**
```json
{
  "columns": [
    "name",
    "card_number"
  ],
  "rows": [
    [
      "Asha",
      "4111-XXXX-XXXX-1111"
    ],
    [
      "John Doe",
      "4242-XXXX-XXXX-4242"
    ],
    [
      "Carlos Mendez",
      "5500-XXXX-XXXX-9999"
    ],
    [
      "Priya Patel",
      "4000-XXXX-XXXX-9010"
    ]
  ]
}
```

**Error Responses:**
- `400 Bad Request` if:
  - Role is invalid (must be `Admin`, `Support`, or `Analyst`).
  - SQL statement is a write/mutation command (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, etc.).
  - SQL contains multiple statements separated by semicolons.
  - SQL syntax is invalid.
- `404 Not Found` if table scanned does not exist.

---

## Setup & Running Instructions

### 1. Requirements
- Python 3.10+
- Dependencies listed in `backend/requirements.txt`:
  - `fastapi`
  - `uvicorn`
  - `pydantic`
  - `httpx`
  - `pytest`

### 2. Install Dependencies
```bash
pip install -r backend/requirements.txt
```

### 3. Run the API Server
Start the development server:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive Swagger documentation will be available at: `http://127.0.0.1:8000/docs`

### 4. Run the Test Suite
```bash
python -m pytest backend/test_main.py -v
```

---

## Quick Demo Commands (cURL)

**Health Check:**
```bash
curl -X GET http://127.0.0.1:8000/health
```

**Scan Schema for PII:**
```bash
curl -X GET http://127.0.0.1:8000/scan
```

**Query as Support (Partially Masked):**
```bash
curl -X POST http://127.0.0.1:8000/query \
  -H "Content-Type: application/json" \
  -d '{"role": "Support", "sql": "SELECT name, card_number FROM customers"}'
```

**Query as Analyst (Redacted):**
```bash
curl -X POST http://127.0.0.1:8000/query \
  -H "Content-Type: application/json" \
  -d '{"role": "Analyst", "sql": "SELECT name, card_number FROM customers"}'
```

**Query as Admin (Raw Data):**
```bash
curl -X POST http://127.0.0.1:8000/query \
  -H "Content-Type: application/json" \
  -d '{"role": "Admin", "sql": "SELECT name, card_number FROM customers"}'
```

**Test Write Query Rejection:**
```bash
curl -X POST http://127.0.0.1:8000/query \
  -H "Content-Type: application/json" \
  -d '{"role": "Admin", "sql": "DROP TABLE customers"}'
```
*(Returns HTTP 400 with rejection message)*

