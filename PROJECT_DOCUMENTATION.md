# PROJECT_DOCUMENTATION.md
# Digital Forensics Evidence Organizer
## Academic Project Documentation

---

## 1. Abstract

The Digital Forensics Evidence Organizer (DFEO) is a web-based evidence management system designed for digital forensic investigations. The system enables forensic investigators to securely import, store, organize, and verify digital evidence while maintaining a tamper-evident chain of custody. Built with Python, FastAPI, and SQLite, the application demonstrates the application of cryptographic hashing, database design, secure web development, and digital forensics principles in a practical academic context.

---

## 2. Introduction

Digital forensics is the science of recovering and investigating digital evidence from electronic devices. One of the most critical aspects of a forensic investigation is the management and preservation of digital evidence. Poorly managed evidence can compromise the outcome of legal proceedings.

Traditional manual methods of evidence tracking are error-prone and difficult to audit. This project proposes and implements a software solution that automates evidence management, ensures cryptographic integrity, and maintains a complete, tamper-evident audit history of all actions performed on digital evidence.

---

## 3. Problem Statement

Digital forensic investigations frequently suffer from:
- Inadequate evidence tracking leading to chain-of-custody disputes
- Manual hash verification processes that are slow and error-prone
- Lack of structured audit trails for evidence access and handling
- No centralized repository for multi-examiner investigations
- Risk of accidental evidence modification or execution of malicious files

This system addresses all these problems through a structured, automated approach.

---

## 4. Objectives

1. Provide a secure, web-based interface for managing forensic evidence.
2. Automatically calculate SHA-256, SHA-512, and MD5 hashes on import.
3. Implement a tamper-evident, hash-chained chain of custody.
4. Never modify or execute uploaded evidence files.
5. Support role-based access control (Admin, Investigator, Reviewer).
6. Generate professional forensic evidence reports.
7. Provide comprehensive audit logging.
8. Support import of forensic tool output files (JSON, CSV, TXT).

---

## 5. Existing Systems

| System | Strengths | Weaknesses |
|--------|-----------|------------|
| Autopsy | Powerful analysis | Complex, no web UI |
| FTK (Forensic Toolkit) | Commercial standard | Expensive, proprietary |
| OpenEvidenceBox | Open source | Limited features |
| Manual spreadsheets | Simple | No integrity verification, no chain |

DFEO fills the gap by providing a lightweight, local, web-accessible evidence management system with automatic hash verification and chain-of-custody enforcement.

---

## 6. Proposed System

A web application that:
- Runs locally without cloud dependencies
- Automatically hashes evidence at import using streaming reads
- Maintains an append-only, hash-chained custody log
- Supports multiple investigators with role-based permissions
- Generates printable forensic reports
- Logs all actions in an immutable audit trail

---

## 7. Scope

**In Scope:**
- Evidence file import and storage
- Cryptographic hash calculation (SHA-256, SHA-512, MD5)
- Chain-of-custody management
- Case management
- User authentication and authorization
- Audit logging
- Report generation
- Search and filtering
- Forensic tool output import (JSON, CSV, TXT)

**Out of Scope:**
- Forensic analysis (file carving, memory analysis, etc.)
- Live acquisition from devices
- Cloud storage integration
- Mobile client

---

## 8. Functional Requirements

| ID | Requirement |
|----|-------------|
| FR-01 | System shall accept evidence file uploads |
| FR-02 | System shall calculate SHA-256, SHA-512 and MD5 immediately on import |
| FR-03 | System shall store evidence metadata in a database |
| FR-04 | System shall never modify or execute uploaded files |
| FR-05 | System shall support re-verification of stored hashes |
| FR-06 | System shall maintain an append-only chain-of-custody log |
| FR-07 | System shall detect tampering in the custody chain |
| FR-08 | System shall provide role-based access control |
| FR-09 | System shall generate forensic evidence reports |
| FR-10 | System shall log all user actions |
| FR-11 | System shall support case creation and management |
| FR-12 | System shall support search by filename, hash, ID, and metadata |
| FR-13 | System shall import structured output from forensic tools |

---

## 9. Non-Functional Requirements

| ID | Requirement |
|----|-------------|
| NFR-01 | Passwords shall be stored using bcrypt hashing |
| NFR-02 | Evidence hashing shall use streaming reads (max 1 MB chunk) |
| NFR-03 | All timestamps shall be stored in UTC |
| NFR-04 | Stored filenames shall be system-generated, not user-supplied |
| NFR-05 | The application shall run on a standard laptop without cloud services |
| NFR-06 | The system shall not trust uploaded file content |
| NFR-07 | Audit records shall not be deletable through the UI |
| NFR-08 | Custody records shall be append-only |
| NFR-09 | Reports shall be clearly labelled as derived documents, not evidence |

---

## 10. System Architecture

```
Browser (Bootstrap 5 UI)
         │
         ▼ HTTP
FastAPI Application (Python 3.11)
    ├── Routers (auth, cases, evidence, custody, audit, reports)
    ├── Services (hashing, evidence, custody, verification, audit, report)
    ├── Importers (JSON, CSV, Text)
    └── Database Layer (SQLAlchemy → SQLite)
         │
         ├── storage/evidence/   (binary evidence files)
         └── storage/reports/    (generated HTML reports)
```

---

## 11. Module Description

### 11.1 Authentication Module
Handles login, logout, session management using JWT cookies. Passwords are hashed with bcrypt. Three roles: ADMIN, INVESTIGATOR, REVIEWER.

### 11.2 Case Management Module
Create, view, update forensic cases. Each case has a unique Case ID, status (OPEN/IN_REVIEW/CLOSED/ARCHIVED), and is associated with an investigator.

### 11.3 Evidence Import Module
Accepts one or more files via HTTP multipart upload. For each file: generates a unique Evidence ID, copies to the evidence repository under a generated filename, calculates all three hashes via streaming reads, stores metadata in the database, creates an initial custody event.

### 11.4 Hashing Service
Uses Python's `hashlib` with `hashlib.sha256()`, `hashlib.sha512()` and `hashlib.md5()`. Files are read in 1 MB chunks. This ensures correct operation on files of any size without memory exhaustion.

### 11.5 Verification Service
Re-reads the stored evidence file using the same streaming hash approach. Compares against stored hashes. Never overwrites the stored original hashes regardless of the result. Records the verification result in the custody chain and audit log.

### 11.6 Chain-of-Custody Service
Implements an append-only, hash-chained event log. Each event's hash is computed over: `SHA-256(previous_hash + event_id + evidence_id + action + description + timestamp)`. The first event's `previous_hash` is the literal string `"GENESIS"`. Chain verification walks all events chronologically and recomputes each hash.

### 11.7 Forensic Tool Output Import
A pluggable importer architecture (BaseImporter abstract class) with implementations for JSON, CSV, and plain-text formats. Importers parse metadata from tool output files without executing them.

### 11.8 Report Generation
Generates self-contained HTML forensic reports. Reports are clearly labelled as derived documents. They include case information, evidence details, hashes, verification status, and the full chain of custody.

### 11.9 Audit Log
Application-wide, append-only log of all significant actions. Stored in the `audit_logs` table with user, action type, entity reference, description, timestamp, and source IP.

---

## 12. Database Design

### Tables

| Table | Purpose |
|-------|---------|
| `users` | User accounts and roles |
| `cases` | Forensic investigation cases |
| `evidence` | Evidence items with hashes and metadata |
| `evidence_metadata` | Extended key-value metadata per evidence item |
| `tags` | Tag catalogue |
| `evidence_tags` | Many-to-many evidence ↔ tags |
| `chain_of_custody` | Append-only hash-chained custody log |
| `audit_logs` | Application-wide audit trail |
| `reports` | Generated report metadata |

### Key Fields — Evidence Table

| Column | Type | Description |
|--------|------|-------------|
| `evidence_id` | VARCHAR | Human-readable unique ID (EVD-YYYYMMDDHHMMSS-XXXXXXXX) |
| `original_filename` | VARCHAR | Preserved original filename (never used for storage) |
| `stored_filename` | VARCHAR | System-generated safe storage filename |
| `sha256` | VARCHAR(64) | SHA-256 hash at time of import — never overwritten |
| `sha512` | VARCHAR(128) | SHA-512 hash at time of import |
| `md5` | VARCHAR(32) | MD5 hash (legacy) |
| `verification_status` | ENUM | UNVERIFIED / VERIFIED / FAILED |

### Key Fields — Chain of Custody Table

| Column | Type | Description |
|--------|------|-------------|
| `event_id` | VARCHAR | Unique event UUID |
| `previous_hash` | VARCHAR(64) | Hash of previous event (or "GENESIS") |
| `event_hash` | VARCHAR(64) | SHA-256(prev_hash + event fields + timestamp) |
| `action` | ENUM | EVIDENCE_IMPORTED / VERIFIED / etc. |

---

## 13. Entity-Relationship Diagram

```mermaid
erDiagram
    USERS {
        string id PK
        string username
        string email
        string full_name
        string hashed_password
        enum role
        string organization
        bool is_active
        datetime created_at
    }

    CASES {
        string id PK
        string case_id
        string name
        string description
        string investigator_id FK
        enum status
        datetime created_at
        datetime updated_at
    }

    EVIDENCE {
        string id PK
        string evidence_id
        string case_id FK
        string original_filename
        string stored_filename
        string storage_path
        bigint file_size
        string mime_type
        string sha256
        string sha512
        string md5
        enum evidence_category
        enum verification_status
        string created_by FK
        datetime imported_timestamp
    }

    EVIDENCE_METADATA {
        string id PK
        string evidence_id FK
        string key
        string value
    }

    TAGS {
        string id PK
        string name
    }

    EVIDENCE_TAGS {
        string evidence_id FK
        string tag_id FK
    }

    CHAIN_OF_CUSTODY {
        string id PK
        string event_id
        string case_id FK
        string evidence_id FK
        string user_id FK
        enum action
        string description
        datetime timestamp
        string previous_hash
        string event_hash
    }

    AUDIT_LOGS {
        string id PK
        string user_id FK
        enum action
        string entity_type
        string entity_id
        string description
        datetime timestamp
        string source_ip
    }

    REPORTS {
        string id PK
        string report_id
        string case_id FK
        string evidence_id FK
        string title
        string generated_by FK
        datetime generated_at
    }

    USERS ||--o{ CASES : "investigates"
    USERS ||--o{ EVIDENCE : "imports"
    USERS ||--o{ CHAIN_OF_CUSTODY : "performs"
    USERS ||--o{ AUDIT_LOGS : "generates"
    USERS ||--o{ REPORTS : "generates"
    CASES ||--o{ EVIDENCE : "contains"
    CASES ||--o{ CHAIN_OF_CUSTODY : "has"
    CASES ||--o{ REPORTS : "has"
    EVIDENCE ||--o{ EVIDENCE_METADATA : "has"
    EVIDENCE ||--o{ CHAIN_OF_CUSTODY : "tracked_by"
    EVIDENCE ||--o{ EVIDENCE_TAGS : "tagged_with"
    TAGS ||--o{ EVIDENCE_TAGS : "used_in"
```

---

## 14. Data Flow Diagram

```mermaid
flowchart TD
    Investigator([Investigator]) -->|Upload file| EI[Evidence Import]
    EI -->|Read chunks| HS[Hashing Service]
    HS -->|SHA-256/512/MD5| EI
    EI -->|Store copy| ER[Evidence Repository\nstorage/evidence/]
    EI -->|Write record| DB[(SQLite DB)]
    EI -->|Create event| COC[Chain of Custody\nService]
    COC -->|Append event| DB
    EI -->|Log action| AL[Audit Log Service]
    AL -->|Append entry| DB

    Investigator -->|Click Verify| VS[Verification Service]
    VS -->|Re-read file| ER
    VS -->|Re-hash| HS
    VS -->|Compare hashes| DB
    VS -->|Record result| COC
    VS -->|Log| AL

    Investigator -->|Generate Report| RS[Report Service]
    RS -->|Read case+evidence| DB
    RS -->|Read custody chain| DB
    RS -->|Write HTML| RF[reports/]
    RS -->|Store metadata| DB
```

---

## 15. Use-Case Diagram

```mermaid
graph LR
    Admin((Admin))
    Investigator((Investigator))
    Reviewer((Reviewer))

    Admin --> UC1[Manage Users]
    Admin --> UC2[View All Cases]
    Admin --> UC3[Import Evidence]
    Admin --> UC4[Verify Integrity]
    Admin --> UC5[Generate Reports]
    Admin --> UC6[View Audit Log]
    Admin --> UC7[Verify Chain]

    Investigator --> UC2
    Investigator --> UC3
    Investigator --> UC4
    Investigator --> UC5
    Investigator --> UC6
    Investigator --> UC7
    Investigator --> UC8[Create Cases]

    Reviewer --> UC9[View Evidence]
    Reviewer --> UC4
    Reviewer --> UC5
    Reviewer --> UC6
    Reviewer --> UC7
```

---

## 16. Sequence Diagram — Evidence Import

```mermaid
sequenceDiagram
    actor Investigator
    participant Browser
    participant FastAPI
    participant EvidenceService
    participant HashingService
    participant CustodyService
    participant AuditService
    participant Database
    participant FileSystem

    Investigator->>Browser: Select files + case, click Import
    Browser->>FastAPI: POST /evidence/import (multipart)
    FastAPI->>EvidenceService: import_evidence_file(case_id, file_data, ...)
    EvidenceService->>FileSystem: Write copy to storage/evidence/<generated_name>
    EvidenceService->>HashingService: calculate_hashes(file_path)
    loop 1 MB chunks
        HashingService->>FileSystem: Read chunk
        HashingService->>HashingService: Update MD5, SHA-256, SHA-512
    end
    HashingService-->>EvidenceService: {sha256, sha512, md5}
    EvidenceService->>Database: INSERT evidence record
    EvidenceService->>CustodyService: create_custody_event(EVIDENCE_IMPORTED)
    CustodyService->>Database: SELECT latest event hash
    CustodyService->>CustodyService: Compute new event_hash
    CustodyService->>Database: INSERT custody event
    EvidenceService->>AuditService: record_audit(EVIDENCE_IMPORTED)
    AuditService->>Database: INSERT audit log
    FastAPI-->>Browser: Redirect to /evidence/<id>
    Browser-->>Investigator: Evidence detail page with hashes
```

---

## 17. Sequence Diagram — Hash Verification

```mermaid
sequenceDiagram
    actor Investigator
    participant Browser
    participant FastAPI
    participant VerificationService
    participant HashingService
    participant CustodyService
    participant Database
    participant FileSystem

    Investigator->>Browser: Click "Verify Integrity"
    Browser->>FastAPI: POST /evidence/<id>/verify
    FastAPI->>VerificationService: verify_evidence_integrity(evidence, user_id)
    VerificationService->>FileSystem: Locate stored evidence file
    alt File exists
        VerificationService->>HashingService: calculate_hashes(path)
        loop 1 MB chunks
            HashingService->>FileSystem: Read chunk
        end
        HashingService-->>VerificationService: {sha256, sha512, md5}
        VerificationService->>VerificationService: Compare with stored hashes
        VerificationService->>Database: Update verification_status
        Note over VerificationService: Original hashes NEVER overwritten
        VerificationService->>CustodyService: create_custody_event(VERIFIED or FAILED)
    else File missing
        VerificationService->>CustodyService: create_custody_event(VERIFICATION_FAILED)
    end
    FastAPI-->>Browser: Evidence detail with INTEGRITY VERIFIED / FAILURE banner
```

---

## 18. Chain-of-Custody Explanation

The chain-of-custody is the forensic record of who handled evidence, when, and what they did. In DFEO, this is implemented as a cryptographic hash chain:

**Hash Formula:**
```
event_hash = SHA-256(
    previous_hash     (hex string)
    + event_id        (UUID)
    + evidence_id     (UUID)
    + action          (string)
    + description     (string)
    + timestamp       (ISO 8601)
)
```

**Properties:**
- **Genesis**: The first event uses `"GENESIS"` as `previous_hash`.
- **Chaining**: Each event's `previous_hash` is the previous event's `event_hash`.
- **Tamper detection**: Modifying any field in any event invalidates all subsequent event hashes.
- **Append-only**: The UI and API never allow deleting or updating custody events.
- **Verification**: `verify_custody_chain()` walks all events and recomputes hashes independently.

---

## 19. Security Considerations

| Concern | Mitigation |
|---------|-----------|
| Plaintext passwords | bcrypt hashing via passlib |
| Session hijacking | HTTP-only JWT cookies, configurable expiry |
| SQL injection | SQLAlchemy ORM parameterized queries |
| Path traversal | Storage filenames are always generated UUIDs |
| Malware execution | Files are NEVER executed; only read for hashing and download |
| Privilege escalation | Role checked on every protected route |
| Upload abuse | Max file size limit (default 2 GB) |
| Evidence tampering | Hashes stored at import and never overwritten |
| Log tampering | Audit log is append-only; no delete endpoint |

---

## 20. Testing Strategy

The test suite uses pytest with an in-memory (temporary) SQLite database.

**Test Categories:**

| Category | File | Tests |
|----------|------|-------|
| Hashing | test_hashing.py | SHA-256/512/MD5 known values, large files, streaming |
| Evidence | test_evidence.py | Import, metadata, hashes, tags, relationships, search |
| Custody | test_custody.py | Chain creation, linking, tamper detection, genesis |
| Verification | test_verification.py | Pass, fail, tamper, missing file, hash preservation |
| Authentication | test_auth.py | Password hash, token, login, wrong password, roles |
| API | test_api.py | All major routes, report generation, reviewer blocking |
| Importers | test_importers.py | JSON, CSV, TXT parsing with edge cases |

**Running tests:**
```bash
pytest -v
pytest --cov=app --cov-report=html
```

---

## 21. Results

The implemented system successfully demonstrates:
- Accurate cryptographic hashing (verified against NIST test vectors)
- Tamper detection in both evidence files and custody chains
- Functional web UI with case/evidence management
- Role-based access control enforced at every route
- Complete audit trail
- Printable forensic reports

---

## 22. Limitations

- SQLite suitable for single-user/lab; PostgreSQL recommended for production
- No real-time collaboration features
- Reports are HTML only (PDF via browser print)
- No built-in forensic analysis (only evidence management)
- No hardware write-blocker integration

---

## 23. Future Enhancements

- PostgreSQL backend for multi-user production deployment
- Two-factor authentication (TOTP/FIDO2)
- RESTful JSON API with Swagger documentation
- Integration with Autopsy, Volatility, YARA
- Digital signatures on reports (GPG/PKI)
- Evidence retention policies and automated expiry
- Real-time notifications (WebSocket)
- Timeline visualization of evidence events
- BYOK (Bring Your Own Key) encryption for evidence at rest

---

## 24. Conclusion

The Digital Forensics Evidence Organizer demonstrates a complete, practical implementation of a forensic evidence management system. The system correctly implements core forensic principles: evidence integrity through cryptographic hashing, tamper-evident chain of custody, complete audit logging, and role-based access control. The codebase is structured, tested, and documented to a professional standard suitable for academic submission and real-world educational use.

---

## 25. References

1. NIST Special Publication 800-86: *Guide to Integrating Forensic Techniques into Incident Response*
2. ISO/IEC 27037:2012: *Guidelines for identification, collection, acquisition and preservation of digital evidence*
3. Casey, E. (2011). *Digital Evidence and Computer Crime*. Academic Press.
4. Python Software Foundation: *hashlib — Secure hashes and message digests*. https://docs.python.org/3/library/hashlib.html
5. FastAPI Documentation: https://fastapi.tiangolo.com
6. SQLAlchemy Documentation: https://docs.sqlalchemy.org
7. OWASP: *Cryptographic Storage Cheat Sheet*. https://cheatsheetseries.owasp.org
8. Carrier, B. (2005). *File System Forensic Analysis*. Addison-Wesley.
