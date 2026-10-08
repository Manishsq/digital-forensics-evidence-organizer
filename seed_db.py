"""
Database seed script.

Creates the database schema and optionally seeds:
  - Admin user
  - 2 sample cases
  - 5 sample evidence items
  - Sample audit and custody events

Run with:
    python seed_db.py [--admin-password <password>]
"""

import argparse
import sys
from pathlib import Path

# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent))


def seed(admin_password: str = "Admin@123!"):
    from app.database.database import engine, SessionLocal, init_db
    from app.database.models import (
        User, Case, Evidence, UserRole, CaseStatus, EvidenceCategory,
        VerificationStatus, gen_uuid,
    )
    from app.auth import hash_password
    from app.services.evidence_service import import_evidence_file
    from app.services.custody_service import create_custody_event
    from app.database.models import CustodyAction
    from datetime import datetime, timezone

    init_db()
    db = SessionLocal()

    def utcnow():
        return datetime.now(timezone.utc).replace(tzinfo=None)

    print("🔧  Seeding database…")

    # ── Admin user ────────────────────────────────────────────────────────
    admin = db.query(User).filter(User.username == "admin").first()
    if not admin:
        admin = User(
            id=gen_uuid(),
            username="admin",
            email="admin@forensics.local",
            full_name="System Administrator",
            hashed_password=hash_password(admin_password),
            role=UserRole.ADMIN,
            organization="Forensics Lab",
        )
        db.add(admin)
        db.flush()
        print(f"  ✅  Admin user created: username=admin  password={admin_password}")
    else:
        print("  ℹ️   Admin user already exists — skipping.")

    # ── Investigator user ──────────────────────────────────────────────────
    inv = db.query(User).filter(User.username == "investigator").first()
    if not inv:
        inv = User(
            id=gen_uuid(),
            username="investigator",
            email="investigator@forensics.local",
            full_name="Jane Investigator",
            hashed_password=hash_password("Investigator@123!"),
            role=UserRole.INVESTIGATOR,
            organization="Forensics Lab",
        )
        db.add(inv)
        db.flush()
        print("  ✅  Investigator user created: username=investigator  password=Investigator@123!")

    # ── Reviewer user ──────────────────────────────────────────────────────
    rev = db.query(User).filter(User.username == "reviewer").first()
    if not rev:
        rev = User(
            id=gen_uuid(),
            username="reviewer",
            email="reviewer@forensics.local",
            full_name="Robert Reviewer",
            hashed_password=hash_password("Reviewer@123!"),
            role=UserRole.REVIEWER,
            organization="Forensics Lab",
        )
        db.add(rev)
        db.flush()
        print("  ✅  Reviewer user created: username=reviewer  password=Reviewer@123!")

    db.commit()

    # ── Case 1 ─────────────────────────────────────────────────────────────
    case1 = db.query(Case).filter(Case.case_id == "CASE-2026-001").first()
    if not case1:
        case1 = Case(
            id=gen_uuid(),
            case_id="CASE-2026-001",
            name="Operation Blue Shield",
            description="Investigation into unauthorized data access at a financial institution.",
            investigator_id=inv.id,
            organization="Forensics Lab",
            status=CaseStatus.OPEN,
            notes="High priority. Report due end of month.",
        )
        db.add(case1)
        db.commit()
        print("  ✅  Case 1 created: CASE-2026-001")
    else:
        print("  ℹ️   Case CASE-2026-001 already exists — skipping.")

    # ── Case 2 ─────────────────────────────────────────────────────────────
    case2 = db.query(Case).filter(Case.case_id == "CASE-2026-002").first()
    if not case2:
        case2 = Case(
            id=gen_uuid(),
            case_id="CASE-2026-002",
            name="Ransomware Incident Response",
            description="Post-incident forensic analysis of ransomware deployment.",
            investigator_id=admin.id,
            organization="Forensics Lab",
            status=CaseStatus.IN_REVIEW,
            notes="Evidence images ready for analysis.",
        )
        db.add(case2)
        db.commit()
        print("  ✅  Case 2 created: CASE-2026-002")
    else:
        print("  ℹ️   Case CASE-2026-002 already exists — skipping.")

    db.refresh(case1)
    db.refresh(case2)

    # ── Sample evidence ────────────────────────────────────────────────────
    ev_count = db.query(Evidence).count()
    if ev_count == 0:
        sample_files = [
            {
                "filename": "disk_image_laptop.dd",
                "data": b"[SAMPLE DISK IMAGE - NOT A REAL DD FILE] Demo evidence item 1.",
                "category": EvidenceCategory.DISK_IMAGE,
                "description": "Full disk image of suspect laptop acquired with FTK Imager.",
                "source": "Suspect laptop – Dell XPS 15",
                "device": "Dell XPS 15 SN:DX15-2026-001",
                "acquisition_method": "FTK Imager v4.7 – write blocked",
                "tags": ["disk", "laptop", "ntfs"],
                "case_id": case1.id,
                "user_id": inv.id,
            },
            {
                "filename": "memory_dump.dmp",
                "data": b"[SAMPLE MEMORY DUMP - NOT REAL] Demo evidence item 2.",
                "category": EvidenceCategory.MEMORY_DUMP,
                "description": "Live RAM capture from suspect workstation.",
                "source": "Suspect workstation WS-01",
                "device": "Dell OptiPlex SN:OP7090-042",
                "acquisition_method": "WinPmem v4.0",
                "tags": ["memory", "ram", "windows"],
                "case_id": case1.id,
                "user_id": inv.id,
            },
            {
                "filename": "network_capture.pcap",
                "data": b"[SAMPLE PCAP - NOT REAL TRAFFIC] Demo evidence item 3.",
                "category": EvidenceCategory.NETWORK_CAPTURE,
                "description": "Network capture during incident window (2026-01-10 08:00 to 12:00 UTC).",
                "source": "Network tap on VLAN 10",
                "acquisition_method": "Wireshark tap",
                "tags": ["network", "pcap", "incident"],
                "case_id": case1.id,
                "user_id": inv.id,
            },
            {
                "filename": "server_syslog.log",
                "data": b"Jan 10 08:31:14 webserver sshd[1234]: Accepted password for admin from 192.168.1.105\n"
                        b"Jan 10 08:31:20 webserver sshd[1234]: pam_unix(sshd:session): session opened for user admin\n"
                        b"Jan 10 09:15:04 webserver sudo: admin : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash\n"
                        b"[SAMPLE LOG - DEMO DATA ONLY]",
                "category": EvidenceCategory.LOG,
                "description": "System log from web server during incident period.",
                "source": "Web server WEB-PROD-01",
                "acquisition_method": "SSH collection",
                "tags": ["log", "syslog", "linux"],
                "case_id": case2.id,
                "user_id": admin.id,
            },
            {
                "filename": "ransomware_sample.bin",
                "data": b"[SAMPLE BINARY - NOT MALWARE - DEMO ONLY] This is placeholder data.",
                "category": EvidenceCategory.MALWARE_SAMPLE,
                "description": "Suspected ransomware binary recovered from quarantine.",
                "source": "Endpoint EDR quarantine – WS-FINANCE-07",
                "acquisition_method": "EDR quarantine export",
                "tags": ["malware", "ransomware", "binary"],
                "case_id": case2.id,
                "user_id": admin.id,
            },
        ]

        for s in sample_files:
            ev = import_evidence_file(
                db=db,
                case_id=s["case_id"],
                original_filename=s["filename"],
                file_data=s["data"],
                created_by=s["user_id"],
                evidence_category=s["category"],
                description=s["description"],
                source=s.get("source"),
                device=s.get("device"),
                acquisition_method=s.get("acquisition_method"),
                tags=s["tags"],
            )
            print(f"  ✅  Evidence imported: {ev.evidence_id} – {s['filename']}")

    else:
        print(f"  ℹ️   Evidence already seeded ({ev_count} items) — skipping.")

    db.commit()
    print("\n✅  Database seeding complete!")
    print("\nDefault login credentials:")
    print("  Admin:        username=admin         password=Admin@123!")
    print("  Investigator: username=investigator  password=Investigator@123!")
    print("  Reviewer:     username=reviewer      password=Reviewer@123!")
    db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed the DFEO database.")
    parser.add_argument("--admin-password", default="Admin@123!", help="Admin user password")
    args = parser.parse_args()
    seed(admin_password=args.admin_password)
