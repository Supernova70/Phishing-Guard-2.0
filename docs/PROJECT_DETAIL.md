# Phishing Guard V2 — Complete Technical Documentation

> **Purpose**: This document is the single source of truth for the project. It covers architecture, technology decisions, data flow, database schema, API contracts, and engine internals. Use this as the starting point for any future edits.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Technology Stack](#2-technology-stack)
3. [Architecture Overview](#3-architecture-overview)
4. [Directory Structure](#4-directory-structure)
5. [Configuration System](#5-configuration-system)
6. [Database Schema (ORM Models)](#6-database-schema-orm-models)
7. [Alembic Migration System](#7-alembic-migration-system)
8. [Analysis Engines](#8-analysis-engines)
   - 8.1 [AI Engine — Text Analyzer](#81-ai-engine--text-analyzer)
   - 8.2 [URL Engine — URL Analyzer](#82-url-engine--url-analyzer)
   - 8.3 [File Engine — Attachment Analyzer](#83-file-engine--attachment-analyzer)
9. [Scan Pipeline (Scan Service)](#9-scan-pipeline-scan-service)
10. [API Layer](#10-api-layer)
11. [Email Fetching Service](#11-email-fetching-service)
12. [Scoring & Classification Logic](#12-scoring--classification-logic)
13. [Docker & Infrastructure](#13-docker--infrastructure)
14. [Environment Variables Reference](#14-environment-variables-reference)
15. [Known Limitations & Future Work](#15-known-limitations--future-work)

---

## 1. Project Overview

**Phishing Guard V2** is a REST API service that automatically fetches emails via IMAP, analyzes them for phishing signals across three independent engines, and produces a risk score + verdict stored in PostgreSQL.

### Core Capabilities

| Capability | Description |
|---|---|
| Email ingestion | Connects to any IMAP mailbox; fetches messages incrementally via UID tracking |
| AI Text Analysis | Pre-trained scikit-learn `TfidfVectorizer + LogisticRegression` pipeline classifies email body text as phishing or legitimate |
| URL Analysis | Extracts all URLs from email body/HTML, runs 10 heuristic checks + optional VirusTotal API lookup |
| File Analysis | Static analysis of email attachments (PE/EXE, PDF, OLE Office, OOXML Office) + YARA rule scanning |
| Verdict Storage | All results stored in PostgreSQL with full JSON breakdown per scan |
| REST API | FastAPI-powered API with Swagger UI at `/docs` |

---

## 2. Technology Stack

### Runtime

| Layer | Technology | Version | Role |
|---|---|---|---|
| Language | Python | 3.12 | Application runtime |
| Web Framework | FastAPI | ≥0.110 | REST API + async request handling |
| ASGI Server | Uvicorn | ≥0.27 | Production ASGI server |
| ORM | SQLAlchemy | ≥2.0 | Database abstraction (sync sessions) |
| Migrations | Alembic | ≥1.13 | Schema versioning and incremental migrations |
| Database | PostgreSQL | 16 | Primary persistence store |
| Settings | pydantic-settings | ≥2.0 | Type-safe env-var config with `.env` file support |

### Analysis Libraries

| Library | Purpose |
|---|---|
| scikit-learn | ML model training + inference (TF-IDF + Logistic Regression) |
| joblib | Model serialization/deserialization |
| httpx | Synchronous HTTP client for VirusTotal API calls |
| beautifulsoup4 | HTML parsing for URL extraction from email bodies |
| imapclient | IMAP protocol client for email fetching |
| pefile | Windows PE/EXE binary static analysis |
| olefile | Legacy OLE2 binary Office format analysis (.doc, .xls) |
| PyPDF2 | PDF internal object tree inspection |
| python-magic | File-type detection from magic bytes (requires `libmagic1` system lib) |
| yara-python | YARA pattern-matching engine for malware signatures |

### Infrastructure

| Component | Image | Port |
|---|---|---|
| App (FastAPI) | `python:3.12-bookworm` (custom build) | 8000 |
| Database | `postgres:16-alpine` | 5432 (container), 5433 (host) |

> **Note**: Redis has been intentionally removed for simplicity. VirusTotal results are not cached between requests.

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Phishing Guard V2                            │
│                                                                     │
│  ┌──────────┐    ┌──────────────────────────────────────────────┐  │
│  │  FastAPI │    │              Scan Pipeline                    │  │
│  │  /docs   │───▶│  ScanService._execute_pipeline()             │  │
│  │  REST API│    │                                              │  │
│  └──────────┘    │  ┌────────────┐ ┌────────────┐ ┌─────────┐ │  │
│       │          │  │ AI Engine  │ │ URL Engine │ │File Eng.│ │  │
│  ┌────▼─────┐    │  │text_analyz.│ │url_analyz. │ │attach_  │ │  │
│  │ Email    │    │  │(scikit-    │ │(heuristics │ │analyz.  │ │  │
│  │ Service  │    │  │ learn)     │ │+ VT API)   │ │(YARA +  │ │  │
│  │(IMAP)    │    │  └────────────┘ └────────────┘ │pefile / │ │  │
│  └──────────┘    │                                │pdf/ole) │ │  │
│                  │  └──────────────────────────────┘─────────┘ │  │
│                  │           ↓ scores + breakdown               │  │
│                  │  Final Score = 1−(1−p_ai)(1−p_url)(1−p_att) │  │
│                  └──────────────────────────────────────────────┘  │
│                                    │                               │
│                          ┌─────────▼──────────┐                   │
│                          │    PostgreSQL DB    │                   │
│                          │  emails / scans /  │                   │
│                          │  verdicts /        │                   │
│                          │  url_results /     │                   │
│                          │  attachments /     │                   │
│                          │  fetch_state       │                   │
│                          └────────────────────┘                   │
└─────────────────────────────────────────────────────────────────────┘
```

### Request Flow (Scan)

```
POST /scans/{email_id}
        │
        ▼
   Load Email from DB
        │
        ▼
   Create Scan (PENDING) → Save to DB
        │
        ▼
   BackgroundTask: _run_scan_background(scan_id)
        │
        ├──▶ AI Engine   → ai_score (0–100)
        ├──▶ URL Engine  → url_score (0–100)  + per-url rows → url_results table
        └──▶ File Engine → attachment_score (0–100)
                │
                ▼
        Probabilistic final_score = 1-(1-p_ai)(1-p_url)(1-p_att) × 100
                │
                ▼
        Classify: SAFE | SUSPICIOUS | DANGEROUS
                │
                ▼
        Verdict + breakdown JSON → DB
```

---

## 4. Directory Structure

```
Intership-project-V2/
├── app/                          # Main Python package
│   ├── main.py                   # FastAPI app factory (lifespan, router mount)
│   ├── config.py                 # Pydantic Settings — all env vars loaded here
│   ├── dependencies.py           # SQLAlchemy engine + get_db() DI function
│   ├── cache.py                  # Stub (no Redis) — returns None
│   │
│   ├── api/                      # HTTP route handlers (thin controllers)
│   │   ├── router.py             # Aggregates all sub-routers
│   │   ├── email.py              # GET /emails, POST /emails/fetch
│   │   ├── scan.py               # POST /scans/{id}, GET /scans
│   │   └── health.py             # GET /health
│   │
│   ├── models/                   # SQLAlchemy ORM models (table definitions)
│   │   ├── __init__.py           # Exports Base + all models (for Alembic)
│   │   ├── email.py              # Email, Attachment
│   │   ├── scan.py               # Scan, Verdict, ScanStatus, Classification
│   │   ├── url_result.py         # UrlResult (one row per URL per scan)
│   │   └── fetch_state.py        # FetchState (IMAP UID cursor)
│   │
│   ├── schemas/                  # Pydantic schemas (request/response validation)
│   │   ├── email.py
│   │   └── scan.py
│   │
│   ├── services/                 # Business logic layer
│   │   ├── email_service.py      # IMAP fetch, parse, dedup, store
│   │   └── scan_service.py       # Orchestrates the 3 analysis engines
│   │
│   ├── engines/                  # Analysis engine implementations
│   │   ├── text_analyzer.py      # AI engine (sklearn model)
│   │   ├── url_analyzer.py       # URL heuristics + VirusTotal
│   │   ├── attachment_analyzer.py# File engine orchestrator
│   │   ├── analyzers/            # Format-specific file analyzers
│   │   │   ├── base.py           # FileAnalysisResult dataclass
│   │   │   ├── pe_analyzer.py    # Windows PE/EXE (pefile)
│   │   │   ├── pdf_analyzer.py   # PDF (PyPDF2)
│   │   │   ├── office_analyzer.py# OLE + OOXML (olefile, zipfile)
│   │   │   ├── generic_analyzer.py # Catch-all heuristic scanner
│   │   │   └── yara_scanner.py   # YARA rule loader + scanner
│   │   └── rules/                # YARA rule files (.yar)
│   │
│   └── middleware/               # (Kept for future use, not active)
│       └── auth.py               # ApiKeyMiddleware (disabled)
│
├── alembic/                      # Database migration system
│   ├── env.py                    # Alembic runtime config (connects to DB)
│   ├── script.py.mako            # Migration file template
│   └── versions/
│       ├── 0001_initial_schema.py# Creates: emails, attachments, scans, verdicts, fetch_state
│       └── 0002_add_url_results.py# Creates: url_results (idempotent)
│
├── data/                         # ML model storage
│   └── phishing_model.joblib     # Trained sklearn pipeline (git-ignored)
│
├── uploads/                      # Attachment file storage (git-ignored)
│
├── architecture/                 # Architecture diagrams
│   ├── current_architecture.excalidraw
│   ├── overall_target_architecture.excalidraw
│   └── phishing_guard_v2_architecture.excalidraw
│
├── scripts/                      # Utility scripts
├── tests/                        # pytest test suite
├── train_model.py                # Model training script
├── Dockerfile                    # App container image
├── docker-compose.yml            # Runs: app + postgres
├── pyproject.toml                # Python project deps + build config
├── alembic.ini                   # Alembic DB URL config
└── .env                          # Local environment variables (git-ignored)
```

---

## 5. Configuration System

**File**: `app/config.py`

Uses `pydantic-settings` `BaseSettings`. All values are loaded from environment variables or the `.env` file. Accessed everywhere via `get_settings()` (LRU-cached singleton).

```python
from app.config import get_settings
settings = get_settings()
```

### Settings Reference

| Variable | Type | Default | Description |
|---|---|---|---|
| `APP_NAME` | str | `"Phishing Guard"` | Application name shown in API docs |
| `APP_VERSION` | str | `"2.0.0"` | API version string |
| `DEBUG` | bool | `False` | Enables SQLAlchemy query logging |
| `DATABASE_URL` | str | `postgresql://...` | Full PostgreSQL connection DSN |
| `VIRUSTOTAL_API_KEYS` | str | `""` | Comma-separated VT API keys. Empty = VT disabled |
| `EMAIL_HOST` | str | `imap.gmail.com` | IMAP server hostname |
| `EMAIL_PORT` | int | `993` | IMAP SSL port |
| `EMAIL_ADDRESS` | str | `""` | Mailbox address |
| `EMAIL_PASSWORD` | str | `""` | App password (not your real Gmail password) |
| `ATTACHMENT_DIR` | str | `/app/uploads` | Disk path where attachments are saved |
| `MODEL_PATH` | str | `/app/data/phishing_model.joblib` | Path to the trained ML model file |
| `MAX_ATTACHMENT_BYTES` | int | `52428800` (50 MB) | Files larger than this are skipped |
| `ENABLE_VT_HASH_LOOKUP` | bool | `False` | Reserved for future VT hash lookup on attachments |

### Computed Property

```python
@property
def vt_api_keys(self) -> List[str]:
    return [k.strip() for k in self.VIRUSTOTAL_API_KEYS.split(",") if k.strip()]
```
Returns a Python list. If `VIRUSTOTAL_API_KEYS` is empty, returns `[]` and the URL analyzer skips the VT API.

---

## 6. Database Schema (ORM Models)

**Base**: `app/models/__init__.py` exports `Base = declarative_base()`

### Table: `emails`

Stores one row per unique email message.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | SERIAL | PK, indexed | Auto-increment primary key |
| `message_id` | VARCHAR(512) | UNIQUE, indexed | RFC 2822 Message-ID header; prevents duplicates |
| `sender` | VARCHAR(512) | NOT NULL, indexed | From: header |
| `subject` | VARCHAR(1024) | NOT NULL, indexed | Subject line |
| `date` | VARCHAR(256) | nullable | Raw Date: header string |
| `to_address` | VARCHAR(512) | nullable | To: header |
| `body_html` | TEXT | nullable | Full HTML body |
| `body_text` | TEXT | nullable | Plain-text body |
| `has_html` | BOOLEAN | NOT NULL | True if email has HTML part |
| `has_attachments` | BOOLEAN | NOT NULL | True if email has ≥1 attachment |
| `fetched_at` | TIMESTAMP | NOT NULL, indexed | When the row was inserted |

### Table: `attachments`

One row per file attached to an email.

| Column | Type | Description |
|---|---|---|
| `id` | SERIAL PK | |
| `email_id` | INTEGER FK→emails.id | Parent email |
| `filename` | VARCHAR(512) | Sanitized filename |
| `content_type` | VARCHAR(256) | MIME type declared in email |
| `size_bytes` | INTEGER | File size |
| `sha256_hash` | VARCHAR(64) | SHA-256 hex digest of raw bytes |
| `storage_path` | VARCHAR(1024) | Absolute disk path where file was saved |

### Table: `scans`

One row per analysis run. An email can have multiple scans.

| Column | Type | Description |
|---|---|---|
| `id` | SERIAL PK | |
| `email_id` | INTEGER FK→emails.id | Email being analyzed |
| `status` | VARCHAR(32) | `pending` \| `running` \| `complete` \| `error` |
| `started_at` | TIMESTAMP | When pipeline started |
| `completed_at` | TIMESTAMP | When pipeline finished |

### Table: `verdicts`

One row per scan (1:1 relationship). Stores the final analysis result.

| Column | Type | Description |
|---|---|---|
| `id` | SERIAL PK | |
| `scan_id` | INTEGER FK→scans.id | Parent scan (UNIQUE) |
| `final_score` | FLOAT | 0–100 probabilistic risk score |
| `classification` | VARCHAR(32) | `safe` \| `suspicious` \| `dangerous` |
| `ai_score` | FLOAT | ML engine score (0–100) |
| `ai_label` | VARCHAR(64) | `"Phishing"` or `"Legitimate"` |
| `url_score` | FLOAT | URL engine score (0–100) |
| `attachment_score` | FLOAT | File engine score (0–100) |
| `breakdown` | JSON | Full per-engine detail for debugging |
| `created_at` | TIMESTAMP | |

### Table: `url_results`

One row per unique URL found per scan (1 scan : N url_results).

| Column | Type | Description |
|---|---|---|
| `id` | SERIAL PK | |
| `scan_id` | INTEGER FK→scans.id | Parent scan |
| `original_url` | VARCHAR(2048) | URL as extracted from email |
| `normalized_url` | VARCHAR(2048) | URL after normalization (tracking params stripped) |
| `is_shortener` | BOOLEAN | True if domain is a known URL shortener |
| `heuristic_score` | FLOAT | Score from 10 static heuristic checks |
| `vt_score` | FLOAT | Score from VirusTotal (0 if not checked) |
| `final_score` | FLOAT | `max(heuristic_score, vt_score)` |
| `vt_malicious` | INTEGER | # VT engines flagging URL as malicious |
| `vt_suspicious` | INTEGER | # VT engines flagging URL as suspicious |
| `vt_harmless` | INTEGER | # VT engines flagging URL as harmless |
| `vt_total` | INTEGER | # VT engines that checked the URL |
| `vt_error` | VARCHAR(256) | VT error message if lookup failed |
| `heuristic_flags` | JSON | List of string descriptions for triggered checks |
| `created_at` | TIMESTAMP | |
| `dynamic_score` | FLOAT | Reserved for future Playwright dynamic analysis |
| `redirect_chain` | JSON | Reserved for future redirect tracking |
| `dom_has_login_form` | BOOLEAN | Reserved for future DOM analysis |
| `ssl_valid` | BOOLEAN | Reserved for future SSL check |
| `playwright_screenshot_path` | VARCHAR | Reserved for future screenshot |

### Table: `fetch_state`

Tracks the IMAP UID cursor per mailbox to enable incremental fetching.

| Column | Type | Description |
|---|---|---|
| `id` | SERIAL PK | |
| `mailbox` | VARCHAR(256) | UNIQUE — mailbox name (e.g. `"INBOX"`) |
| `last_uid` | INTEGER | Highest UID successfully processed |
| `last_fetched_at` | TIMESTAMP | Timestamp of last successful fetch |

---

## 7. Alembic Migration System

Alembic manages all schema changes. The app **does not** call `Base.metadata.create_all()` at startup — migrations are the only schema authority.

### Migration Files

| Revision | File | What It Creates |
|---|---|---|
| `0001` | `0001_initial_schema.py` | `emails`, `attachments`, `scans`, `verdicts`, `fetch_state` |
| `0002` | `0002_add_url_results.py` | `url_results` (idempotent — guarded with `inspector.get_table_names()`) |

### Running Migrations

```bash
# Apply all pending migrations (done automatically by Docker entrypoint)
alembic upgrade head

# Check current revision
alembic current

# Roll back one step
alembic downgrade -1

# If you have an existing DB and want to skip re-running 0001:
alembic stamp 0001
```

### Why Migrations Are Idempotent

Both `0001` and `0002` use `inspector.get_table_names()` to check if a table already exists before calling `op.create_table()`. This means they are safe to run on:
- A fresh empty database (creates everything)
- An existing database (skips existing tables/indexes)

---

## 8. Analysis Engines

### 8.1 AI Engine — Text Analyzer

**File**: `app/engines/text_analyzer.py`

**What it does**: Loads a pre-trained scikit-learn pipeline from disk and classifies email body text as phishing or legitimate.

**Model**: `TfidfVectorizer` → `LogisticRegression` pipeline.
- Trained on the `spam.csv` dataset (Kaggle) via `train_model.py`
- Serialized to `data/phishing_model.joblib` with joblib
- Loaded once at startup via `@lru_cache` singleton

**Input**: Plain-text email body (falls back to HTML body if no text part)

**Output**: `TextAnalysisResult`
```python
@dataclass
class TextAnalysisResult:
    is_phishing: bool      # True if confidence > 50%
    confidence: float      # 0–100 probability score
    label: str             # "Phishing" or "Legitimate"
```

**Score → ai_score**: `confidence` (0–100)

---

### 8.2 URL Engine — URL Analyzer

**File**: `app/engines/url_analyzer.py`

**What it does**: Extracts all URLs from email text + HTML body, runs static heuristic checks on each URL, and optionally queries the VirusTotal API.

#### Stage 1: URL Extraction

- Regex scan of plain-text body: `https?://[^\s"'<>]+`
- BeautifulSoup scan of HTML: `href`, `src`, `action` attributes
- Deduplication by normalized URL
- Filters: local IPs (127.x, 192.168.x, 10.x, 172.16–31.x) are excluded

#### Stage 2: URL Normalization

Strips tracking query parameters with prefixes: `utm_`, `fbclid`, `gclid`, `ref`, `mc_`

#### Stage 3: Heuristic Scoring (10 Checks)

| Check | Points | Trigger |
|---|---|---|
| HTTP scheme | +15 | URL uses `http://` (not `https://`) |
| IP hostname | +35 | Hostname is a bare IP address |
| Suspicious TLD | +20 | TLD is in a blocklist (`.tk`, `.ml`, `.xyz`, etc.) |
| URL shortener | +20 | Domain is a known shortener (bit.ly, tinyurl, etc.) |
| Brand impersonation | +40 | Hostname matches brand pattern but isn't the real domain |
| Excessive subdomains | +15 | ≥4 domain components (e.g. `a.b.c.example.com`) |
| Long URL | +10 | URL length > 200 characters |
| High path entropy | +15 | Shannon entropy > 4.5 (obfuscated random path) |
| @ symbol in host | +25 | Credential obfuscation pattern |
| Embedded redirect | +20 | URL contains `http` more than once |

Max score capped at 100.

#### Stage 4: VirusTotal Lookup (Optional)

- Only runs if `VIRUSTOTAL_API_KEYS` is set
- URL is Base64-encoded and sent to `GET /api/v3/urls/{url_id}`
- Uses round-robin key rotation across multiple API keys
- If URL is unknown to VT (404), submits it for analysis
- `vt_score = (malicious + suspicious×0.5) / total × 100`

**Final URL Score**: `max(heuristic_score, vt_score)` per URL, then `max()` across all URLs

---

### 8.3 File Engine — Attachment Analyzer

**File**: `app/engines/attachment_analyzer.py`

**What it does**: Analyzes each email attachment using format-specific static analysis + YARA pattern matching.

#### File Type Routing

```
File bytes
    │
    ├── MIME = PE / ext = .exe/.dll → pe_analyzer (pefile)
    ├── MIME = PDF / ext = .pdf     → pdf_analyzer (PyPDF2)
    ├── ext = .docx/.xlsx/.pptx     → office_analyzer (OOXML/zipfile)
    ├── ext = .doc/.xls/.ppt        → office_analyzer (OLE binary)
    └── everything else             → generic_analyzer (heuristics)
                  │
                  └── ALL files also run YARA scanner
```

#### Sub-Analyzers

| Analyzer | File | What It Checks |
|---|---|---|
| `pe_analyzer` | `analyzers/pe_analyzer.py` | Suspicious imports, PE sections, entropy, packer signatures |
| `pdf_analyzer` | `analyzers/pdf_analyzer.py` | JavaScript objects, embedded files, auto-launch actions |
| `office_analyzer` | `analyzers/office_analyzer.py` | OLE macro streams (VBA), OOXML macro-enabled files, suspicious streams |
| `generic_analyzer` | `analyzers/generic_analyzer.py` | High entropy, suspicious strings, script extension check |
| `yara_scanner` | `analyzers/yara_scanner.py` | YARA rules from `engines/rules/*.yar` |

#### MIME Mismatch Detection

Uses `python-magic` (libmagic) to detect the real MIME type from magic bytes. If declared content-type ≠ detected type, +20 points and a finding is added.

#### Score Aggregation

- Each file gets a `risk_score` 0–100
- YARA score is `max()`-merged with the heuristic score
- `attachment_score = max(all per-file scores)` — one bad file flags the entire email

#### YARA Rules

Rules live in `app/engines/rules/*.yar`. Add or edit `.yar` files to customize detection without touching Python code. Rules are compiled and cached on the first scan.

---

## 9. Scan Pipeline (Scan Service)

**File**: `app/services/scan_service.py`

### Entry Points

```python
class ScanService:
    def run_scan(self, email: Email) -> Scan          # Create + run immediately
    def run_scan_by_id(self, scan_id: int) -> Scan    # Load existing scan + run
```

### Pipeline Steps

```python
def _execute_pipeline(self, scan, email) -> Scan:
    # 1. AI Text Analysis
    text = email.body_text or email.body_html or ""
    ai_result = get_text_analyzer().analyze(text)

    # 2. URL Analysis
    url_result = UrlAnalyzer().analyze(body_text, body_html)
    # → Saves each URL as a UrlResult row to DB

    # 3. Attachment Analysis
    att_result = AttachmentAnalyzer().analyze(email.attachments)

    # 4. Compute final score
    final_score = _compute_final_score(ai_score, url_score, attachment_score)

    # 5. Store Verdict + breakdown JSON
```

### Background Task Pattern

The `/scans/{email_id}` endpoint returns HTTP 202 immediately with `scan_id`, then dispatches the pipeline to a FastAPI `BackgroundTask`. The background task opens its **own** database session to avoid session lifecycle conflicts.

```python
background_tasks.add_task(_run_scan_background, scan.id)
```

---

## 10. API Layer

**Base prefix**: None (flat router)

### Endpoints

#### Health

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Returns `{"status": "ok"}` |

#### Emails

| Method | Path | Description |
|---|---|---|
| POST | `/emails/fetch` | Fetch N emails from IMAP inbox |
| GET | `/emails` | List emails with filters |
| GET | `/emails/{email_id}` | Get full email detail |

**Fetch query params**: `limit` (1–100, default 20)

**List query params**: `sender`, `has_attachments`, `date_from`, `date_to`, `scanned`, `skip`, `limit`

#### Scans

| Method | Path | Description |
|---|---|---|
| POST | `/scans/{email_id}` | Trigger analysis scan (returns 202) |
| GET | `/scans` | List scans with filters |
| GET | `/scans/{scan_id}` | Get scan + verdict details |

**List query params**: `classification` (safe/suspicious/dangerous), `score_min`, `score_max`, `email_id`, `skip`, `limit`

#### Swagger UI

Available at `http://localhost:8000/docs` — fully interactive, no auth required (auth middleware disabled).

---

## 11. Email Fetching Service

**File**: `app/services/email_service.py`

### Flow

```
EmailService.fetch_and_store(limit)
    │
    ├── Connect to IMAP via IMAPClient (SSL)
    ├── Load FetchState from DB → get last_uid for this mailbox
    ├── Search for UIDs > last_uid (incremental fetch)
    ├── For each new UID:
    │     ├── Fetch raw RFC 2822 message bytes
    │     ├── Parse with email.message_from_bytes()
    │     ├── Extract: Message-ID, sender, subject, date, to, body, attachments
    │     ├── DEDUP check: skip if message_id already in DB
    │     ├── Save attachments to disk (ATTACHMENT_DIR/{email_id}/{safe_filename})
    │     └── Save Email + Attachment rows to DB
    └── Update FetchState.last_uid = max(processed UIDs)
```

### Deduplication

Uses the RFC 2822 `Message-ID` header as the unique key. If a message with the same `message_id` already exists in the `emails` table, it is skipped.

### Attachment Sanitization

Filenames are sanitized before saving to disk: path traversal characters (`..`, `/`, `\`) are stripped. SHA-256 hash is computed for each attachment.

---

## 12. Scoring & Classification Logic

### Per-Engine Scores

All three engines produce a score in the range **0–100** where 0 = definitely safe and 100 = definitely malicious.

### Final Score Formula

Uses probabilistic risk accumulation — equivalent to asking "what is the probability that at least one engine thinks this is dangerous?":

```
P_final = 1 − (1 − P_ai) × (1 − P_url) × (1 − P_att)
```

Where `P_x = score_x / 100`. Result is multiplied back to 0–100.

**Why this formula?**
- If any single engine is highly confident (e.g., `P_ai = 0.95`), the final score is also high
- Multiple moderate signals accumulate (e.g., three 0.5 signals → 0.875)
- No engine can dominate unfairly — all contribute

### Classification Thresholds

| Score Range | Classification | Meaning |
|---|---|---|
| 0 – 29.9 | `safe` | Low risk |
| 30 – 69.9 | `suspicious` | Investigate |
| 70 – 100 | `dangerous` | High confidence phishing |

---

## 13. Docker & Infrastructure

### Dockerfile

```dockerfile
FROM python:3.12-bookworm
WORKDIR /app
RUN apt-get install -y libmagic1 file   # Required for python-magic
COPY pyproject.toml .
RUN pip install .
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", ...]
```

### docker-compose.yml Services

| Service | Role | Ports |
|---|---|---|
| `app` (phishing-guard) | FastAPI app + Alembic migrations | 8000:8000 |
| `postgres` (phishing-guard-db) | PostgreSQL 16 primary DB | 5433:5432 |

### Startup Sequence (Docker)

```sh
alembic upgrade head    # Run pending migrations
uvicorn app.main:app    # Start the API server
```

The `app` service waits for `postgres` to pass its healthcheck before starting.

### Volumes

| Volume | Mount Point | Purpose |
|---|---|---|
| `pg_data` | `/var/lib/postgresql/data` | Persist database across container restarts |
| `uploads_data` | `/app/uploads` | Persist saved attachment files |
| `.:/app` (bind mount) | `/app` | Hot-reload during development |

---

## 14. Environment Variables Reference

See `.env.example` for a copyable template.

```bash
# ── Core ──────────────────────────────────────────────
DATABASE_URL=postgresql://phishing_user:phishing_pass@postgres:5432/phishing_guard
DEBUG=false

# ── VirusTotal (optional) ─────────────────────────────
# Leave empty to skip VT lookups — heuristic-only mode
VIRUSTOTAL_API_KEYS=

# ── Email IMAP ────────────────────────────────────────
EMAIL_HOST=imap.gmail.com
EMAIL_PORT=993
EMAIL_ADDRESS=you@gmail.com
EMAIL_PASSWORD=your-gmail-app-password

# ── Paths ─────────────────────────────────────────────
ATTACHMENT_DIR=/app/uploads
MODEL_PATH=/app/data/phishing_model.joblib
```

> **Gmail App Password**: Go to Google Account → Security → 2-Step Verification → App Passwords. Generate one for "Mail". Do NOT use your real Gmail password.

---

## 15. Known Limitations & Future Work

### Current Limitations

| Item | Detail |
|---|---|
| No Redis / caching | VirusTotal API is called fresh every scan. Rate limits apply (4 req/min on free tier). |
| No auth | API key middleware exists (`app/middleware/auth.py`) but is disabled. All endpoints are open. |
| Synchronous pipeline | The scan pipeline runs synchronously inside a BackgroundTask. Long scans may block. |
| No dynamic URL analysis | `dynamic_score`, `redirect_chain`, `dom_has_login_form` columns exist but Playwright integration is not yet implemented. |
| No VT hash lookup | `ENABLE_VT_HASH_LOOKUP=False` — attachment VT lookups are stubbed. |

### Future Improvements

- [ ] Re-enable `ApiKeyMiddleware` for production
- [ ] Add Redis back for VT result caching
- [ ] Implement Playwright dynamic URL crawling (redirect chain, login form detection)
- [ ] Add Celery + Redis worker for async scan queue
- [ ] Add attachment VirusTotal hash lookup (`/api/v3/files/{sha256}`)
- [ ] Add webhook/notification for high-risk verdicts
- [ ] Build a simple web dashboard (React or plain HTML)
