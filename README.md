# Automated USB Forensics & Artifact Parser

A full-stack cybersecurity application designed to inspect, catalog, and analyze USB storage devices, hardware connection logs (Windows `setupapi.dev.log`, Linux `dmesg`/`syslog`), and storage file artifacts with signature and heuristic threat detection.

---

## Project Structure

```text
IS Project/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── database.py         # SQLite connection & session management
│   │   ├── models.py           # SQLAlchemy Device & FileArtifact schemas
│   │   ├── schemas.py          # Pydantic validation schemas
│   │   └── main.py             # FastAPI server with CORS & endpoints
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── test_db.py          # Pytest suite for models and API routes
│   │   ├── generate_mock_logs.py # Generates mock logs & forensic files
│   │   ├── sample_data/        # setupapi.dev.log, dmesg_usb.log, syslog_usb.log
│   │   └── mock_files/         # Harmless test files (.pdf, .bat, .vbs, .exe, .inf)
│   ├── requirements.txt
│   ├── usb_forensics.db        # SQLite database
│   └── venv/                   # Python 3.13 virtual environment
├── frontend/
│   ├── src/
│   │   ├── App.tsx             # Interactive forensics dashboard & log studio
│   │   ├── main.tsx
│   │   ├── index.css           # Tailwind CSS styles & forensic theme
│   │   └── vite-env.d.ts
│   ├── index.html
│   ├── package.json
│   ├── vite.config.ts
│   └── tsconfig.json
├── .gitignore
└── README.md
```

---

## Database Schema (SQLite)

### 1. `devices` Table
| Column | Type | Constraints / Description |
|---|---|---|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT |
| `vendor_id` | VARCHAR(32) | NOT NULL, INDEX (e.g. `0781`) |
| `product_id` | VARCHAR(32) | NOT NULL, INDEX (e.g. `5581`) |
| `serial_number` | VARCHAR(128) | NOT NULL, UNIQUE, INDEX |
| `volume_label` | VARCHAR(128) | NULLABLE (e.g. `SANDISK_ULTRA`) |
| `first_connected` | DATETIME | UTC timestamp |
| `last_connected` | DATETIME | UTC timestamp |

### 2. `file_artifacts` Table
| Column | Type | Constraints / Description |
|---|---|---|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT |
| `device_id` | INTEGER | FOREIGN KEY -> `devices.id` (ON DELETE CASCADE) |
| `file_path` | VARCHAR(1024) | NOT NULL |
| `file_size` | INTEGER | NOT NULL (Bytes) |
| `creation_time` | DATETIME | NULLABLE |
| `modification_time` | DATETIME | NULLABLE |
| `md5_hash` | VARCHAR(32) | NULLABLE |
| `sha256_hash` | VARCHAR(64) | NULLABLE |
| `flag_suspicious` | BOOLEAN | NOT NULL, DEFAULT FALSE |
| `flag_reason` | TEXT | NULLABLE (Detection rationale) |

---

## Running the Application

### 1. Backend Server (FastAPI)
```powershell
cd backend
.\venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --port 8000
```
- API Documentation (Swagger): `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/api/health`

### 2. Frontend Dashboard (React + Vite + Tailwind CSS)
```powershell
cd frontend
npm run dev
```
- Access Dashboard: `http://localhost:5173`

### 3. Generate Mock Forensic Datasets
```powershell
cd backend
.\venv\Scripts\python tests\generate_mock_logs.py
```

### 4. Run Pytest Suite
```powershell
cd backend
.\venv\Scripts\pytest -v
```
