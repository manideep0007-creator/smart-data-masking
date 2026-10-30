# Smart Data Masking — Security Operations Console

A lightweight, distinctive web-based Security Operations Console built with vanilla **HTML, CSS, and JavaScript** for the Smart Data Masking hackathon demo.

---

## Architecture & Features

- **Live Gateway Health**: Polls `GET /health` to ensure the FastAPI query gateway and SQLite database are operational.
- **PII Schema Radar**: Calls `GET /scan` to detect sensitive fields (`card_number`, `ssn`, `email`, `phone`, `salary`, `address`) and displays them as colored sensitivity tags.
- **Role-Based Querying**: Calls `POST /query` with selectable roles (**Support**, **Analyst**, **Admin**) and displays masked results in a formatted data table.
- **SQL Injection & Mutation Guard**: Attempts to run write operations (`DROP TABLE`, etc.) or chained queries are safely blocked and displayed with clear error banners.
- **Quick Template Chips**: Instant test queries for cards, full PII profiles, and safe attack rejections.

---

## How to Run

### 1. Ensure the Backend is Running
From the project root:
```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Serve the Frontend
From the project root:
```powershell
python -m http.server 3000 --directory frontend
```

👉 Open in your browser: **[http://localhost:3000](http://localhost:3000)**
