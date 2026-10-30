# PII Shield – Live Hackathon Laptop Demonstration Guide
**Project: Smart Data Masking System for PII Protection**  
*BFSI Track – Hackathon Problem 11 | AI Frontier Challenge 2026*  
*Offline-Ready Live Demonstration Architecture*

---

## 🚀 1. One-Click Demonstration Launchers

For the live laptop presentation, two automated scripts are provided in the project root:

### ▶️ `START_DEMO.bat`
Double-click this batch file before the judges arrive. It will:
1. Verify Python availability.
2. Check if the FastAPI backend (Port 8000) is already running (avoids duplicate processes).
3. Start the backend in a dedicated console window if needed.
4. Poll `http://127.0.0.1:8000/health` until HTTP 200 OK is returned.
5. Check if the frontend server (Port 3000) is running and start it if needed.
6. Automatically open your default web browser to:
   **`http://localhost:3000`**

### ⏹️ `STOP_DEMO.bat`
Double-click this script after your demonstration is complete. It safely terminates only the demo servers listening on ports 8000 and 3000 without touching any unrelated applications.

---

## 🌐 2. Services & URLs

| Component | URL | Description |
| :--- | :--- | :--- |
| **Web Console** | `http://localhost:3000` | Full Security Operations Dashboard with 1-click Judge Demo |
| **API Gateway** | `http://127.0.0.1:8000` | FastAPI in-flight masking gateway |
| **Interactive Docs** | `http://127.0.0.1:8000/docs` | OpenAPI / Swagger interactive documentation |
| **Health Check** | `http://127.0.0.1:8000/health` | Gateway & SQLite database health endpoint |

> **100% Offline Reliable:** PII Shield uses local SQLite storage, system font fallbacks, and zero external CDNs. It operates seamlessly with Wi-Fi completely turned off.

---

## 👥 3. Pre-Configured Demo Personas

All personas authenticate using **real Bcrypt passwords and cryptographically signed JWT tokens** (HMAC-SHA256).

| Persona | Role | Default Password | Permissions & Masking Behavior |
| :--- | :--- | :--- | :--- |
| **`admin_anita`** | **Admin** | `password123` | Full unmasked raw database values (Superuser/DBA). |
| **`support_ravi`** | **Support** | `password123` | Partial masking (`4532-XXXX-XXXX-9010`, `XXX-XX-4321`, `[CONFIDENTIAL]` salary, names preserved). |
| **`analyst_kavya`** | **Analyst** | `password123` | Full redaction (`[REDACTED]`) OR Deterministic HMAC-SHA256 hashing (`sha256:7f83b...`) for safe analytics. |

---

## 🎯 4. Step-by-Step Judge Demonstration Script (5 Minutes)

When the judges arrive at your laptop, follow this exact sequence using the **"⭐ START JUDGE DEMO"** mode on the dashboard:

### 🟢 Stage 1 – System Overview (30 Seconds)
- **What to show:** Click **"⭐ START JUDGE DEMO"** at the top right of the dashboard.
- **Judge Talking Point:**
  > *"Judges, PII Shield is an in-flight security gateway. Raw data stays encrypted and untouched in our database. Queries are dynamically intercepted, validated, and masked strictly in memory based on the user's verified cryptographic identity."*
- **Key Metrics Shown:** SQLite Read-Only Guard Active, FastAPI Gateway Online, JWT Token Authority active.

---

### 🔍 Stage 2 – Automated PII Discovery (45 Seconds)
- **What to show:** Click **"Scan Database"**.
- **Judge Talking Point:**
  > *"Rather than relying on manual classification, our 2-stage discovery engine combines structural heuristic detection with live data sampling. It classifies columns by sensitivity (High, Medium, Confidential) and detects Aadhaar numbers (Verhoeff checksum), PAN cards, credit cards (Luhn algorithm), SSNs, emails, and salaries with zero external cloud dependencies."*
- **Key Visual:** Discovered tables (`customers`), total columns classified (8), PII sensitivity tags.

---

### 🔐 Stage 3 – Cryptographic RBAC & Anti-Spoofing (45 Seconds)
- **What to show:** Click between the persona cards (**Admin**, **Support**, **Analyst**).
- **Judge Talking Point:**
  > *"Security is enforced at the server level. Notice that selecting a persona executes a real POST to `/auth/login`, issuing a signed JWT access token. If an attacker modifies their client-side request body to claim they are an 'Admin', our backend server extracts the role from the cryptographically verified JWT claims, completely shutting down privilege escalation."*

---

### 🛡️ Stage 4 – Live Dynamic Masking Comparison (90 Seconds)
- **What to show:** Click **"Execute 4-Way Comparison Query"** using the standard query:
  ```sql
  SELECT id, name, card_number, ssn, email, salary FROM customers WHERE id = 1;
  ```
- **Judge Talking Point:**
  > *"Here is the core capability in action: the exact same SQL query produces four distinct, role-tailored views in real time:*
  > 1. *Admin Anita sees raw, unmasked data for platform administration.*
  > 2. *Support Ravi sees partial masking (`4532-XXXX-XXXX-9010`, email domain preserved for customer communication, salary confidential).*
  > 3. *Analyst Kavya (Redact) sees `[REDACTED]` across all sensitive identifiers.*
  > 4. *Analyst Kavya (Hash) receives deterministic HMAC-SHA256 pseudonyms (`sha256:7f83b...`), allowing risk analysts to join datasets and count unique users without ever exposing customer PII."*

---

### 🧱 Stage 5 – Database Protection & SQL Injection Defense (45 Seconds)
- **What to show:** Click **"Test Database Protection"**.
- **Judge Talking Point:**
  > *"PII Shield features dual-layer defense. First, our AST-based SQL Validator blocks DDL and DML keywords (`DROP`, `DELETE`, `UPDATE`, `INSERT`, comments `--`, `/* */`, and multiple statements). Second, even if a query bypassed validation, SQLite's native C-level authorizer (`sqlite3_set_authorizer`) enforces read-only access at the driver kernel level."*
- **Key Visual:** Live rejection table showing 5 attack queries blocked with `HTTP 400 Bad Request`.

---

### 💾 Stage 6 – Zero Mutation: Original Data Preservation (30 Seconds)
- **What to show:** Click **"Verify Underlying Database"**.
- **Judge Talking Point:**
  > *"Traditional masking often permanently overwrites database records. PII Shield guarantees zero mutation. The original database record remains 100% intact, proving all masking occurs strictly in transient memory."*

---

### 🏛️ Stage 7 – Architecture & Extensibility (15 Seconds)
- **What to show:** Review the interactive Architecture Flow diagram.
- **Judge Talking Point:**
  > *"Our clean Database Abstraction Layer decouples query parsing from the physical storage engine. Today we demonstrate SQLite for offline hackathon portability, with our PostgreSQL adapter ready for enterprise migration."*

---

## 🛠️ 5. Troubleshooting & Verification

- **Ports already in use:** Run `STOP_DEMO.bat` and relaunch `START_DEMO.bat`.
- **Manual Start (if needed):**
  - Backend: `python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000`
  - Frontend: `python -m http.server 3000 --directory frontend`
- **Verify Test Suite (Evidence for Judges):**
  - Run `python -m pytest backend/test_main.py -v` (39/39 passing unit tests).
  - Run `python e2e_test_suite.py` (34/34 passing live E2E integration tests).
