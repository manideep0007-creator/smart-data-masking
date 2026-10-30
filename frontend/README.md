# Smart Data Masking frontend

A Streamlit dashboard for backend health, PII scans, and role-based query results.

## Setup

From the repository root, create and activate a virtual environment if desired, then install the minimal frontend dependencies:

```powershell
python -m pip install streamlit requests pandas
```

## Run

From the repository root:

```powershell
python -m streamlit run frontend/app.py
```

The frontend expects the backend at `http://localhost:8000`. To use another base URL, set `MASKING_API_URL` before starting Streamlit, for example:

```powershell
$env:MASKING_API_URL = "http://localhost:8000"
python -m streamlit run frontend/app.py
```

The app calls `GET /health`, `GET /scan`, and `POST /query` (with `role` and `sql` JSON fields). Since the `/scan` response schema is not specified yet, the Scan action displays the backend response as-is rather than assuming a shape.
