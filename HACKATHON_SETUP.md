# PII Shield — Hackathon Setup & Offline Demonstration Guide

This guide provides step-by-step instructions for running and evaluating the **PII Shield** data masking system completely offline on a Windows laptop.

---

## 💻 Prerequisites

- **OS**: Windows 10 or 11 (64-bit)
- **Python**: Version 3.10, 3.11, 3.12, or 3.14 (Python installed and on `PATH`)
- **Web Browser**: Chrome, Edge, Firefox, or Brave
- **Internet Connection**: **NOT REQUIRED**. The application runs 100% offline once Python packages are installed.

---

## 📦 Step 1: Install Dependencies

Open a PowerShell terminal in the project root directory:

```powershell
cd D:\Innovex\smart-data-masking
pip install -r backend/requirements.txt
```

*Required packages: `fastapi`, `uvicorn`, `pydantic`, `pytest`, `httpx`, `pyjwt`, `bcrypt`, `psycopg[binary]`.*

---

## 🧪 Step 2: Run Verification Test Suite

Run the full automated test suite to confirm zero regressions:

```powershell
python -m pytest backend/test_main.py -v
```

Expected result:
```
============================= 39 passed in ~8s =============================
```

---

## 🚀 Step 3: Launch the Servers

### Terminal 1: Backend Gateway API (Port 8000)
```powershell
cd D:\Innovex\smart-data-masking
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
- Status: `Uvicorn running on http://127.0.0.1:8000`
- API documentation is accessible at `http://127.0.0.1:8000/docs`.

### Terminal 2: Frontend Operations Console (Port 3000 or 5500)
Open a second PowerShell terminal:
```powershell
cd D:\Innovex\smart-data-masking
python -m http.server 3000 --directory frontend
```
- Status: `Serving HTTP on :: port 3000 ...`

---

## 🖥️ Step 4: Open the Dashboard

Open your browser and navigate to:
**`http://localhost:3000`** *(or `http://127.0.0.1:5500` if using Live Server)*

---

## 🎯 Step 5: Hackathon Demonstration Walkthrough

Follow this 5-minute evaluation script to demonstrate all system capabilities to hackathon judges:

### 1. Show Heuristic PII Radar
- Look at the left panel **PII Schema Radar**.
- Click **Scan Schema**: Observe automatic detection and categorization of columns:
  - `card_number` → `FINANCIAL_CONFIDENTIAL` (HIGH)
  - `ssn` → `PII_HIGH` (HIGH)
  - `email`, `phone`, `address` → `PII_MEDIUM` (MEDIUM)
  - `id` → `PUBLIC` (NONE)
- Click **Async Scan**: Watch the progress bar advance asynchronously via background worker without blocking any queries.

### 2. Demonstrate Role-Based In-Flight Masking
- In the top **Verified JWT Persona** ribbon, click **`🎧 Support (Ravi)`**.
- Click **▶ Run Query via Gateway** (query: `SELECT name, card_number FROM customers`).
  - **Notice**: Credit card numbers are partially masked (`4111-XXXX-XXXX-1111`), while customer names remain unmasked so support agents can assist clients.
- Click template chip **`Full PII Profile`** and run again:
  - **Notice**: Salary shows `[CONFIDENTIAL]`, phone shows `***-***-2834`, and SSN shows `XXX-XX-6789`.

### 3. Demonstrate Analyst Pseudonymization vs. Redaction
- In the ribbon, click **`📊 Analyst (Kavya)`**.
- Keep strategy as **Full Redaction [REDACTED]** and run query:
  - All sensitive fields display `[REDACTED]`.
- Change the **Analyst Masking Strategy** dropdown to **Deterministic Hash (sha256:12char)** and run query:
  - Notice `sha256:37b954877721` tokens.
  - Explain to judges: *"This deterministic pseudonymization allows risk analysts and data science teams to perform joins, count cardinalities, and build ML models without ever seeing plaintext PII."*

### 4. Demonstrate Admin Full Access
- Click **`👑 Admin (Anita)`** in the ribbon.
- Run the query: raw, unmasked database records are displayed.

### 5. Demonstrate Database Immutability & Write Rejection
- Click template chip **`Test Write Rejection`** (`DROP TABLE customers`).
- Hit **Run Query**: The gateway instantly rejects the query with:
  `Query rejected: Write or administrative command 'DROP' is forbidden. Only read-only SELECT queries are allowed.`
- Click template chip **`Test Injection`** (`SELECT name FROM customers; DROP TABLE customers`):
  `Query rejected: Multiple SQL statements are not permitted.`
- Explain: *"Even if an attacker bypassed Python-level validation, SQLite's native C-level `sqlite3.set_authorizer` and PostgreSQL's session-level read-only guards enforce driver-level immutability."*

---

## 🔧 Troubleshooting Guide

| Issue | Cause | Fix |
| :--- | :--- | :--- |
| Gateway shows "Offline" badge | Backend is not running on port 8000 | Ensure Terminal 1 is running `python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000` |
| `psycopg driver is not installed` | Missing PostgreSQL client driver | Run `pip install psycopg[binary]` |
| `fatal: not a git repository` | Command executed in parent folder | Ensure terminal is in `D:\Innovex\smart-data-masking` |
| Port 8000 already in use | Stale process holding port | In PowerShell: `Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess \| Stop-Process -Force` |
