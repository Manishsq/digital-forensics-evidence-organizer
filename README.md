# Digital Forensics Evidence Organizer (DFEO)

> A production-quality, academic digital forensics evidence management system built with Python 3.11+, FastAPI, SQLAlchemy, and SQLite.

---

## Features

| Feature | Description |
|---|---|
| **Case Management** | Create, update, view, and track forensic investigation cases with full status lifecycle |
| **Evidence Import** | Secure file upload with automatic SHA-256/SHA-512/MD5 hash calculation |
| **Integrity Verification** | Re-calculate and compare hashes at any time; tamper is instantly detected |
| **Chain of Custody** | Append-only, hash-chained custody log for every evidence action |
| **Audit Log** | Application-wide audit trail of all user actions |
| **Forensic Tool Output Import** | Parse JSON/CSV/TXT output from forensic tools (metadata only, never executed) |
| **Search** | Full-text search across filenames, hashes, IDs, descriptions |
| **Report Generation** | Printable HTML forensic evidence reports (clearly labelled as derived documents) |
| **Role-Based Access** | ADMIN / INVESTIGATOR / REVIEWER roles with enforced permissions |
| **Dark Theme UI** | Professional navy/blue forensics UI with Bootstrap 5 |
| **Test Suite** | Comprehensive pytest tests for hashing, custody, evidence, auth, and API |

---

## Technology Stack

- **Python 3.11+**
- **FastAPI** — async web framework
- **SQLAlchemy 2.x** — ORM (sync, SQLite)
- **SQLite** — embedded database
- **Jinja2** — HTML templating
- **Bootstrap 5** — responsive dark UI
- **passlib + bcrypt** — secure password hashing
- **python-jose** — JWT session tokens
- **hashlib** — SHA-256 / SHA-512 / MD5 (streaming, chunked)
- **pytest** — test suite

---

## Project Structure

```
digital-forensics-evidence-organizer/
├── app/
│   ├── main.py              # FastAPI app, router registration
│   ├── config.py            # Settings (env vars / .env)
│   ├── auth.py              # Password hashing, JWT, session
│   ├── database/
│   │   ├── database.py      # SQLAlchemy engine & session
│   │   └── models.py        # ORM models (all tables)
│   ├── routers/
│   │   ├── auth.py          # Login / logout / user management
│   │   ├── dashboard.py     # Dashboard statistics
│   │   ├── cases.py         # Case CRUD
│   │   ├── evidence.py      # Evidence import, detail, verify, download
│   │   ├── custody.py       # Chain-of-custody viewer & verifier
│   │   ├── audit.py         # Audit log viewer
│   │   └── reports.py       # Report generation & viewer
│   ├── services/
│   │   ├── hashing.py           # Chunked SHA-256/SHA-512/MD5
│   │   ├── evidence_service.py  # Evidence import & storage
│   │   ├── custody_service.py   # Custody chain management
│   │   ├── audit_service.py     # Audit logging
│   │   ├── verification_service.py  # Hash re-verification
│   │   └── report_service.py    # HTML report generation
│   ├── importers/
│   │   ├── base.py          # Abstract BaseImporter
│   │   ├── json_importer.py # JSON forensic output parser
│   │   ├── csv_importer.py  # CSV forensic output parser
│   │   └── text_importer.py # Plain-text/log parser
│   ├── templates/           # Jinja2 HTML templates
│   └── static/              # CSS + JS
├── tests/                   # pytest test suite
├── storage/
│   ├── evidence/            # Evidence file repository
│   └── reports/             # Generated HTML reports
├── sample_data/             # Sample JSON, CSV, TXT for demos
├── seed_db.py               # Database seeding script
├── run.py                   # Application launcher
├── requirements.txt
├── .env.example
└── README.md
```

---

## Installation

### 1. Clone / extract

```bash
cd digital-forensics-evidence-organizer
```

### 2. Create a virtual environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
cp .env.example .env
# Edit .env and set a strong SECRET_KEY
```

### 5. Initialize the database and seed sample data

```bash
python seed_db.py
```

This creates:
- SQLite database at `./storage/forensics.db`
- 3 users (admin, investigator, reviewer)
- 2 sample cases
- 5 sample evidence items with hashes

### 6. Run the application

```bash
python run.py
# or with auto-reload for development:
python run.py --reload
```

Open your browser at: **http://127.0.0.1:8000**

---

## Default Login Credentials (development only)

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `Admin@123!` |
| Investigator | `investigator` | `Investigator@123!` |
| Reviewer | `reviewer` | `Reviewer@123!` |

> **⚠ Change these passwords before any real use.**

---

## How to Create an Admin User Manually

```bash
python -c "
from app.database.database import init_db, SessionLocal
from app.database.models import User, UserRole, gen_uuid
from app.auth import hash_password
init_db()
db = SessionLocal()
u = User(id=gen_uuid(), username='myadmin', email='me@lab.local',
         full_name='My Admin', hashed_password=hash_password('SecurePass!'),
         role=UserRole.ADMIN, organization='My Lab')
db.add(u); db.commit(); print('Created:', u.username)
"
```

---

## How to Import Evidence

1. Login as **investigator** or **admin**.
2. Click **Cases** → select or create a case.
3. Click **Import Evidence** → select one or more files.
4. Fill in metadata (category, source, description, tags).
5. Submit — the system will:
   - Copy the file to `./storage/evidence/` under a generated filename
   - Calculate SHA-256, SHA-512 and MD5 immediately
   - Record a chain-of-custody event
   - Display the evidence detail page with all hashes

---

## How Hash Verification Works

When you click **Verify Integrity** on an evidence detail page:

1. The system locates the stored evidence file (never the original upload path).
2. It re-reads the file in **1 MB chunks** (never loads entire file into RAM).
3. It re-calculates SHA-256, SHA-512 and MD5.
4. It compares calculated hashes with the **original stored hashes** (which are never overwritten).
5. Result displayed: **INTEGRITY VERIFIED** ✅ or **INTEGRITY FAILURE** ❌.
6. A chain-of-custody event is created recording the result.
7. An audit log entry is recorded.

If the file has been tampered with, the SHA-256 mismatch is immediately detected.

---

## How Chain of Custody Works

Each custody event is chained:

```
event_hash = SHA-256(
    previous_event_hash  +
    event_id             +
    evidence_id          +
    action               +
    description          +
    timestamp_iso
)
```

- The first event uses `"GENESIS"` as `previous_hash`.
- Each subsequent event's `previous_hash` = the previous event's `event_hash`.
- To verify: click **Verify Chain** on the custody page.
- The verifier walks all events chronologically and recomputes each hash.
- If **any** event's data has been modified, the chain breaks and `CHAIN INTEGRITY FAILURE` is displayed.

---

## Running Tests

```bash
pytest
# With coverage:
pytest --cov=app --cov-report=term-missing
# Verbose:
pytest -v
```

Tests cover:
- SHA-256 / SHA-512 / MD5 against known values
- Multi-chunk hashing of large files
- Evidence import, metadata, and case relationship
- Custody chain creation, linkage, and tamper detection
- Evidence integrity verification (pass and fail cases)
- Authentication (login, wrong password, token decode/tamper)
- Role permissions (reviewer cannot import)
- API endpoint tests (dashboard, cases, evidence, reports)
- Forensic tool output parsers (JSON, CSV, TXT)

---

## Security Considerations

- Passwords are hashed with **bcrypt** via passlib (never stored plaintext).
- Session tokens are JWTs signed with `SECRET_KEY`.
- Uploaded filenames are **never used** for storage — a generated UUID-based name is used instead.
- Path traversal is prevented: storage path is always under the controlled `evidence/` directory.
- Evidence files are **never executed** — only read for hashing and download.
- SQLAlchemy ORM prevents SQL injection.
- Role-based access control is enforced on every sensitive route.
- All file uploads have a configurable size limit (default 2 GB).
- All actions are audit-logged with UTC timestamps and source IP.
- The original stored hash is **never overwritten** — not even after a failed verification.

---

## Forensic Principles

This application follows core digital forensics principles:
- **Preservation**: Original evidence is never modified.
- **Integrity**: Hashes are computed at acquisition and verifiable at any time.
- **Chain of Custody**: Every action on evidence is logged in an append-only, hash-chained log.
- **Non-repudiation**: Audit log records who did what and when.
- **Non-execution**: Uploaded files are never executed under any circumstances.

---

## Limitations

- Single-server local deployment (no horizontal scaling).
- SQLite is suitable for lab/study use; production would use PostgreSQL.
- No real-time notifications.
- No two-factor authentication (suitable enhancement for future work).
- PDF report generation uses HTML (print to PDF via browser).

---

## Future Enhancements

- PostgreSQL support for production deployments
- Two-factor authentication (TOTP)
- RESTful JSON API with OpenAPI documentation
- Evidence timeline visualization
- Integration with Autopsy, Volatility, Sleuth Kit
- E-mail notifications for case updates
- Digital signatures for reports
- Evidence expiry / retention policies

---

## Academic Context

This project is a final-year academic project demonstrating:
- Secure web application development in Python
- Digital forensics concepts (hashing, chain of custody, evidence integrity)
- Database design and ORM usage
- RESTful routing and session management
- Role-based access control
- Cryptographic integrity verification
- Append-only audit systems
