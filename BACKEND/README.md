# APK Security Analyzer — Backend

Flask + SQLite backend for the APK Security Analyzer frontend.

---

## Setup

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the server

```bash
python app.py
```

Server starts at: `http://127.0.0.1:5000`

---

## Project Structure

```
apk_backend/
├── app.py           # Main Flask application & analysis engine
├── database.py      # SQLite DB helpers
├── requirements.txt
├── apk_scanner.db   # Auto-created on first run
└── uploads/         # Temp folder — files deleted after scan
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/analyze` | Upload & analyze an APK file |
| GET | `/history` | List all previously scanned APKs |
| GET | `/history/<sha256>` | Get cached result by file hash |
| GET | `/stats` | Count of HIGH / MEDIUM / LOW scans |
| GET | `/health` | Health check |

---

## How `/analyze` works

1. Receives the `.apk` file via multipart form (`apk` field)
2. Computes **SHA-256** hash → checks SQLite cache
3. If cached → returns stored result instantly (no re-scan)
4. If new → extracts `AndroidManifest.xml` from the APK zip
5. Parses permissions, matches against 30+ known risk signatures
6. Detects malicious patterns (SMS trojans, droppers, spyware combos)
7. Calculates risk score (0–100) → LOW / MEDIUM / HIGH
8. Stores result in `apk_scanner.db`
9. Returns full JSON result to frontend

---

## Database Schema

```sql
CREATE TABLE scanned_apks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    file_hash    TEXT UNIQUE NOT NULL,   -- SHA-256
    file_name    TEXT NOT NULL,
    package_name TEXT,
    risk_score   INTEGER NOT NULL,       -- 0-100
    risk_level   TEXT NOT NULL,          -- LOW/MEDIUM/HIGH
    result_json  TEXT NOT NULL,          -- Full analysis JSON
    scanned_at   REAL NOT NULL           -- Unix timestamp
);
```

---

## Frontend Integration

Your existing `upload.js` already points to `http://127.0.0.1:5000/analyze` — no changes needed.

The backend returns the same JSON shape that `results.js` expects:

```json
{
  "fileName": "...",
  "packageName": "...",
  "version": "...",
  "permissions": [...],
  "threats": [...],
  "riskScore": 72,
  "riskLevel": "HIGH",
  "summary": { "criticalIssues": 2, "highRiskPermissions": 5, ... },
  "recommendations": [...],
  "scanInfo": { "duration": "1.3 seconds", ... },
  "cached": false
}
```

---

## Optional: History Page

Add a call to `GET /history` in a new `history.html` page to show all previously scanned APKs with their risk levels — the database stores everything automatically.
