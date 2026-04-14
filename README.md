# 🛡️ Phishing Guard V2

> **AI-powered email phishing detection system** — analyzes email text, URLs, and attachments using three independent engines and produces a risk verdict stored in PostgreSQL.

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com)
[![PostgreSQL 16](https://img.shields.io/badge/PostgreSQL-16-blue.svg)](https://postgresql.org)

---

## Features

| Engine | Technology | What It Detects |
|---|---|---|
| 🤖 AI Engine | scikit-learn (TF-IDF + Logistic Regression) | Phishing language patterns in email body |
| 🔗 URL Engine | Heuristics + VirusTotal API | Malicious/suspicious URLs in email |
| 📎 File Engine | pefile, PyPDF2, olefile, YARA rules | Malware in email attachments |

- **REST API** with Swagger UI at `/docs`
- **Incremental IMAP fetch** — only downloads new emails each time
- **Probabilistic scoring** — combines all three engines into one final risk score
- **PostgreSQL storage** — full history of emails, scans, verdicts, and per-URL results
- **Alembic migrations** — schema versioned, safe to re-run

---

## Quick Start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Docker + Docker Compose)
- Git

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd Intership-project-V2
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Open `.env` and fill in your values (see [Environment Variables](#environment-variables) below).

### 3. Add the ML Model

The trained model file is not committed to Git. You have two options:

**Option A — Use pre-built model** (if you have it):
```bash
# Place the file here:
data/phishing_model.joblib
```

**Option B — Train a new model**:
```bash
# First run the training script (requires pandas, matplotlib)
pip install pandas matplotlib seaborn scikit-learn joblib
python train_model.py
# Output: data/phishing_model.joblib
```
> If the model file is missing, the AI engine will return a score of 0 for all emails. URL and File engines still work normally.

### 4. Run with Docker

```bash
docker compose up --build
```

That's it. Docker will:
1. Build the Python app image
2. Start PostgreSQL
3. Run `alembic upgrade head` (create/migrate DB schema)
4. Start the FastAPI server on port 8000

**API**: http://localhost:8000  
**Swagger UI**: http://localhost:8000/docs  
**PostgreSQL**: `localhost:5433` (host port, use `5433` to avoid conflict with local PG)

### 5. First API Call

```bash
# Fetch emails from your IMAP inbox
curl -X POST "http://localhost:8000/emails/fetch?limit=10"

# Trigger a scan on email #1
curl -X POST "http://localhost:8000/scans/1"

# Get scan result (returns scan + verdict)
curl "http://localhost:8000/scans/1"
```

---

## Local Development (Without Docker)

### Prerequisites

- Python 3.12
- PostgreSQL 16 running locally

### 1. Create Virtual Environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -e .
```

**Windows only** — install the Windows-compatible magic library:
```bash
pip install python-magic-bin
```

**Linux/macOS** — install system dependency:
```bash
# Ubuntu/Debian
sudo apt-get install libmagic1

# macOS
brew install libmagic
```

### 3. Set Up PostgreSQL

```bash
# Create database and user
psql -U postgres -c "CREATE USER phishing_user WITH PASSWORD 'phishing_pass';"
psql -U postgres -c "CREATE DATABASE phishing_guard OWNER phishing_user;"
```

### 4. Configure `.env` for Local

```bash
cp .env.example .env
```

Edit `DATABASE_URL` to point to your local PostgreSQL:
```env
DATABASE_URL=postgresql://phishing_user:phishing_pass@localhost:5432/phishing_guard
```

### 5. Run Migrations

```bash
alembic upgrade head
```

### 6. Start the Server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open http://localhost:8000/docs

---

## Environment Variables

Copy `.env.example` to `.env` and fill in your values.

```env
# ── Database ──────────────────────────────────────────────────────────
# Docker: use "postgres" as host (service name in docker-compose)
# Local:  use "localhost"
DATABASE_URL=postgresql://phishing_user:phishing_pass@postgres:5432/phishing_guard

# ── App Settings ──────────────────────────────────────────────────────
DEBUG=false

# ── VirusTotal API (Optional) ─────────────────────────────────────────
# Get a free key at https://www.virustotal.com/gui/my-apikey
# Multiple keys (comma-separated) enable round-robin rotation
# Leave empty to run in heuristic-only mode (no VT lookups)
VIRUSTOTAL_API_KEYS=

# ── Email IMAP ────────────────────────────────────────────────────────
EMAIL_HOST=imap.gmail.com
EMAIL_PORT=993
EMAIL_ADDRESS=your-email@gmail.com
# Gmail: create an App Password at:
# Google Account → Security → 2-Step Verification → App Passwords
EMAIL_PASSWORD=your-app-password

# ── File Paths ────────────────────────────────────────────────────────
ATTACHMENT_DIR=/app/uploads
MODEL_PATH=/app/data/phishing_model.joblib

# ── Limits ────────────────────────────────────────────────────────────
MAX_ATTACHMENT_BYTES=52428800
```

---

## Project Structure

```
app/
├── main.py              # FastAPI app factory
├── config.py            # All settings (pydantic-settings)
├── dependencies.py       # Database session injection
│
├── api/                 # HTTP route handlers
│   ├── email.py         # /emails endpoints
│   ├── scan.py          # /scans endpoints
│   └── health.py        # /health
│
├── models/              # SQLAlchemy ORM table definitions
│   ├── email.py         # Email, Attachment
│   ├── scan.py          # Scan, Verdict
│   ├── url_result.py    # UrlResult (per-URL rows)
│   └── fetch_state.py   # IMAP UID cursor
│
├── services/            # Business logic
│   ├── email_service.py # IMAP fetch + parse + store
│   └── scan_service.py  # Scan pipeline orchestration
│
└── engines/             # Analysis engines
    ├── text_analyzer.py      # AI engine (sklearn)
    ├── url_analyzer.py       # URL engine (heuristics + VT)
    ├── attachment_analyzer.py# File engine orchestrator
    ├── analyzers/            # Format-specific file scanners
    └── rules/                # YARA rule files (.yar)
```

---

## API Reference

All endpoints available at `http://localhost:8000/docs` (Swagger UI).

### Email Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/emails/fetch?limit=20` | Fetch N new emails from IMAP |
| `GET` | `/emails` | List emails (with filters) |
| `GET` | `/emails/{id}` | Get full email details |

### Scan Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/scans/{email_id}` | Trigger analysis (returns 202) |
| `GET` | `/scans` | List scans + verdicts |
| `GET` | `/scans/{id}` | Get scan details + verdict |

### Health

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Returns `{"status": "ok"}` |

---

## Database Migrations

Migrations run automatically inside Docker on startup. For manual control:

```bash
# Apply all pending migrations
alembic upgrade head

# Check current version
alembic current

# Show migration history
alembic history

# Rollback one step
alembic downgrade -1

# If running Alembic on an existing DB for the first time:
alembic stamp 0001    # Mark 0001 as done without re-running it
alembic upgrade head  # Now run only 0002 onwards
```

---

## Running Tests

```bash
# Run all tests
pytest

# With coverage report
pytest --cov=app --cov-report=term-missing

# Run a specific test file
pytest tests/test_url_analyzer.py -v
```

---

## Troubleshooting

### `relation "url_results" already exists`

Your database has the table but Alembic thinks it needs to create it. Fix:
```bash
# Inside the app container
docker exec -it phishing-guard bash
alembic stamp 0002     # Mark 0002 as already applied
exit
docker restart phishing-guard
```

### IMAP connection fails

- Make sure `EMAIL_ADDRESS` and `EMAIL_PASSWORD` are set in `.env`
- For Gmail: use an **App Password**, not your real password
- Enable IMAP in Gmail Settings → See all settings → Forwarding and POP/IMAP

### Model not found

```
WARNING: Model not found at /app/data/phishing_model.joblib. AI scores will be 0.
```
Run `python train_model.py` to generate the model, then rebuild Docker.

### Port conflict on 5433

Change the host port in `docker-compose.yml`:
```yaml
ports:
  - "5434:5432"   # Use 5434 instead
```

---

## Architecture

For detailed technical documentation including schema diagrams, engine internals, and scoring formulas, see [`docs/PROJECT_DETAIL.md`](docs/PROJECT_DETAIL.md).

For architecture diagrams, see the [`architecture/`](architecture/) folder — open `.excalidraw` files at [excalidraw.com](https://excalidraw.com).
