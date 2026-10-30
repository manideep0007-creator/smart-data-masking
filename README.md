# PII Shield — Smart Data Masking System

> **Autonomous In-Flight PII Protection, Dynamic Masking & Read-Only Query Gateway**  
> Built for the AI Frontier Challenge 2026 (BFSI Track — Problem 11).

PII Shield is a lightweight, database-independent data protection engine that sits between analytical/support query clients and sensitive databases. It automatically scans table schemas, discovers Personally Identifiable Information (PII) using a two-stage heuristic engine, and dynamically masks query results in memory according to verified user roles without ever altering raw database records.

---

## 🌟 Key Features

- **Database Abstraction Layer**: Unified `DatabaseAdapter` interface supporting **SQLite** (native C-level `sqlite3.set_authorizer`) and **PostgreSQL** (`psycopg3` session-level read-only transactions & statement timeouts).
- **JWT Authentication & Server-Side RBAC**: Secure password hashing with Bcrypt, HMAC-SHA256 signed JWTs, and server-side role derivation (prevents frontend role tampering).
- **Two-Stage Automated PII Discovery**:
  - *Stage 1 (Column-Name Heuristics)*: Identifies credit cards, SSN, Aadhaar, PAN, emails, phones, salaries, addresses, names, and DOB.
  - *Stage 2 (Sample-Value Regex Patterns)*: Evaluates actual data formats (Luhn card ranges, 12-digit Aadhaar, 10-char PAN, RFC emails) and supports SQL column aliases.
- **Asynchronous Background Scanner**: Background worker thread (`POST /scan/start`, `GET /scan/status`, `GET /scan/history`) traverses tables and populates a central `MetadataRegistry` without blocking live user queries.
- **Role-Based Dynamic Masking & Pseudonymization**:
  - **Admin**: Raw unmasked access.
  - **Support**: Targeted partial masking (`4111-XXXX-XXXX-1111`, `XXXX-XXXX-1234` for Aadhaar, `XXXXX1234F` for PAN, `a***@example.com`), preserving customer names for service.
  - **Analyst**: Full redaction (`[REDACTED]`) or deterministic **HMAC-SHA256 pseudonymized hashing** (`sha256:...`) to support joins and groupings without exposing raw PII.
- **Multi-Layer Query Security Guard**: Enforces read-only SELECT/CTE queries, rejects write/DDL keywords (`DROP`, `DELETE`, `UPDATE`, `INSERT`, etc.), blocks comment obfuscation (`--`, `/* */`), and enforces row limits (`max_rows=1000`).
- **100% Offline-Capable Demonstration**: Zero internet access or cloud databases required. Uses local system fonts and bundled vanilla frontend.

---

## 🏗️ Architecture

```
[ Frontend Security Operations Console ]  <-- http://localhost:3000 or http://127.0.0.1:5500
             |  (JWT Bearer Token / Role)
             v
[ FastAPI Gateway & Query Validator ]      <-- http://127.0.0.1:8000
    ├── 1. Auth Module (Bcrypt / JWT decode)
    ├── 2. SQL Validator (Blocks DDL/DML, comments, multi-stmts)
    ├── 3. Database Adapter Layer (SQLite / PostgreSQL)
    │       ├── SQLite (set_authorizer C-callback)
    │       └── PostgreSQL (READ ONLY session & timeouts)
    ├── 4. Metadata Registry & Background Scanner
    └── 5. Dynamic Masking Engine (Support partial / Analyst hash)
             |
             v
[ Raw Database Storage: customers.db / PostgreSQL ] (Always Immutable)
```

---

## 🛠️ Technology Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn, Pydantic v2
- **Security & Cryptography**: PyJWT, Bcrypt, HMAC-SHA256, SQLite native C-authorizer
- **Database Adapters**: `sqlite3` (built-in standard library), `psycopg[binary]` (PostgreSQL)
- **Frontend**: Vanilla HTML5, CSS3, JavaScript (no external CDN or Node.js build required)
- **Testing**: Pytest, FastAPI TestClient, AnyIO

---

## 🚀 Quick Offline Startup (Windows PowerShell)

### 1. Install Dependencies
```powershell
pip install -r backend/requirements.txt
```

### 2. Run Test Suite
```powershell
python -m pytest backend/test_main.py -v
```

### 3. Launch Backend API Server
```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
*API is live at `http://127.0.0.1:8000`. Interactive docs at `http://127.0.0.1:8000/docs`.*

### 4. Launch Frontend Console
Open a new PowerShell terminal:
```powershell
python -m http.server 3000 --directory frontend
```
*Open `http://localhost:3000` in your web browser.*

---

## 🔑 Demonstration Personas

| Persona | Username | Password | Permitted Access |
| :--- | :--- | :--- | :--- |
| **👑 Admin (Anita)** | `admin_anita` | `password123` | Full raw, unmasked data |
| **🎧 Support (Ravi)** | `support_ravi` | `password123` | Partial card/SSN/Aadhaar/PAN mask, names preserved |
| **📊 Analyst (Kavya)** | `analyst_kavya` | `password123` | Full redaction `[REDACTED]` or `sha256:...` hash |
| **🔓 Anonymous Demo** | *None* | *None* | Unauthenticated local demonstration mode |

---

## 📡 API Endpoints Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Gateway and active database engine health status |
| `GET` | `/database/info` | Database connection latency, tables list, and read-only status |
| `POST` | `/auth/login` | Authenticate user credentials and issue signed JWT |
| `GET` | `/auth/me` | Inspect current user identity and role from verified JWT |
| `GET` | `/auth/users` | List demonstration personas (passwords omitted) |
| `GET` | `/scan` | Synchronously inspect schema and classify columns |
| `POST` | `/scan/start` | Trigger non-blocking asynchronous background scan (Admin) |
| `GET` | `/scan/status` | Current background scanner state and progress percentage |
| `GET` | `/scan/history` | Audit log of completed scans |
| `POST` | `/query` | Execute read-only query with role-based in-flight masking |

---

## 🛡️ Query Security Protections

1. **Read-Only Verification**: Rejects any statement not starting with `SELECT` or `WITH`.
2. **Comment Stripping / Denial**: Disallows `--` and `/* */` comments to avoid query splitting attacks.
3. **Multi-Statement Blocking**: Prohibits unquoted semicolons.
4. **Keyword Interception**: Strict detection of `DROP`, `DELETE`, `UPDATE`, `INSERT`, `ALTER`, `CREATE`, `TRUNCATE`, `ATTACH`, `PRAGMA`.
5. **Driver-Level Enforcement**: SQLite `set_authorizer` and PostgreSQL `default_transaction_read_only = ON` guarantee write commands fail even if parsing were bypassed.
6. **Bounded Resource Pagination**: Maximum row limiter (`max_rows=1000`) prevents runaway memory consumption.
