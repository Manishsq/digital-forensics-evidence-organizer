"""
Evidence service.

Handles import, storage, retrieval and search of forensic evidence.
Original files are NEVER modified. Copies are stored under generated names.
"""

import mimetypes
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session, joinedload

from app.config import get_settings
from app.database.models import (
    Evidence,
    EvidenceCategory,
    EvidenceMetadata,
    EvidenceTag,
    Tag,
    VerificationStatus,
    CustodyAction,
    AuditAction,
    gen_uuid,
)
from app.services.hashing import calculate_hashes
from app.services.custody_service import create_custody_event
from app.services.audit_service import record_audit

settings = get_settings()


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _safe_extension(filename: str) -> str:
    """Return the lowercase file extension (e.g. '.pcap') or empty string."""
    return Path(filename).suffix.lower()


def _detect_mime(filename: str) -> str:
    mime, _ = mimetypes.guess_type(filename)
    return mime or "application/octet-stream"


def generate_evidence_id() -> str:
    """Return a human-readable unique evidence identifier."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    short = uuid.uuid4().hex[:8].upper()
    return f"EVD-{ts}-{short}"


def import_evidence_file(
    db: Session,
    *,
    case_id: str,
    original_filename: str,
    file_data: bytes,
    created_by: str,
    evidence_category: EvidenceCategory = EvidenceCategory.OTHER,
    description: Optional[str] = None,
    source: Optional[str] = None,
    device: Optional[str] = None,
    suspect_reference: Optional[str] = None,
    acquisition_method: Optional[str] = None,
    evidence_type: Optional[str] = None,
    tags: Optional[list[str]] = None,
    source_ip: Optional[str] = None,
) -> Evidence:
    """
    Import an evidence file:
    1. Validate case exists.
    2. Generate unique evidence ID and storage filename.
    3. Write the file to the evidence repository (never original path).
    4. Calculate MD5, SHA-256, SHA-512 via streaming.
    5. Persist evidence record.
    6. Create chain-of-custody event.
    7. Create audit record.

    Original data is NEVER modified. File is NEVER executed.
    """
    from app.database.models import Case
    from sqlalchemy import select

    case = db.get(Case, case_id)
    if case is None:
        raise ValueError(f"Case not found: {case_id}")

    evidence_id = generate_evidence_id()

    # Generate a safe, unique storage filename
    ext = _safe_extension(original_filename)
    stored_filename = f"{evidence_id}{ext}"
    storage_dir = settings.evidence_storage_dir
    storage_path = storage_dir / stored_filename

    # Write evidence file – never modify the original source
    storage_path.write_bytes(file_data)
    file_size = len(file_data)

    # Compute hashes over the stored copy
    hashes = calculate_hashes(storage_path)

    now = utcnow()
    evidence = Evidence(
        id=gen_uuid(),
        evidence_id=evidence_id,
        case_id=case_id,
        original_filename=original_filename,
        stored_filename=stored_filename,
        storage_path=str(storage_path),
        file_size=file_size,
        mime_type=_detect_mime(original_filename),
        file_extension=ext,
        sha256=hashes["sha256"],
        sha512=hashes["sha512"],
        md5=hashes["md5"],
        evidence_category=evidence_category,
        evidence_type=evidence_type,
        source=source,
        device=device,
        suspect_reference=suspect_reference,
        acquisition_method=acquisition_method,
        description=description,
        imported_timestamp=now,
        acquisition_timestamp=now,
        verification_status=VerificationStatus.UNVERIFIED,
        created_by=created_by,
        created_at=now,
        updated_at=now,
    )
    db.add(evidence)
    db.flush()  # get evidence.id

    # Handle tags
    if tags:
        _apply_tags(db, evidence.id, tags)

    # Chain of custody: initial import event
    create_custody_event(
        db=db,
        case_id=case_id,
        evidence_id=evidence.id,
        user_id=created_by,
        action=CustodyAction.EVIDENCE_IMPORTED,
        description=f"Evidence imported: {original_filename} ({file_size} bytes). "
                    f"SHA-256: {hashes['sha256']}",
        source_ip=source_ip,
    )

    # Audit record
    record_audit(
        db=db,
        action=AuditAction.EVIDENCE_IMPORTED,
        user_id=created_by,
        entity_type="evidence",
        entity_id=evidence.id,
        description=f"Imported evidence '{original_filename}' into case {case.case_id}.",
        source_ip=source_ip,
    )

    db.commit()
    db.refresh(evidence)
    return evidence


def _apply_tags(db: Session, evidence_id: str, tag_names: list[str]) -> None:
    for name in tag_names:
        name = name.strip().lower()
        if not name:
            continue
        tag = db.query(Tag).filter(Tag.name == name).first()
        if not tag:
            tag = Tag(id=gen_uuid(), name=name)
            db.add(tag)
            db.flush()
        # Avoid duplicates
        existing = (
            db.query(EvidenceTag)
            .filter_by(evidence_id=evidence_id, tag_id=tag.id)
            .first()
        )
        if not existing:
            db.add(EvidenceTag(evidence_id=evidence_id, tag_id=tag.id))


def get_evidence(db: Session, evidence_id: str) -> Optional[Evidence]:
    """Fetch evidence by internal UUID (id column)."""
    return (
        db.query(Evidence)
        .options(
            joinedload(Evidence.case),
            joinedload(Evidence.creator),
            joinedload(Evidence.metadata_entries),
            joinedload(Evidence.evidence_tags).joinedload(EvidenceTag.tag),
        )
        .filter(Evidence.id == evidence_id)
        .first()
    )


def get_evidence_by_eid(db: Session, evidence_id: str) -> Optional[Evidence]:
    """Fetch evidence by human-readable evidence_id (EVD-...) column."""
    return (
        db.query(Evidence)
        .options(
            joinedload(Evidence.case),
            joinedload(Evidence.creator),
            joinedload(Evidence.metadata_entries),
            joinedload(Evidence.evidence_tags).joinedload(EvidenceTag.tag),
        )
        .filter(Evidence.evidence_id == evidence_id)
        .first()
    )


def search_evidence(
    db: Session,
    query: Optional[str] = None,
    case_id: Optional[str] = None,
    category: Optional[str] = None,
    investigator_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
) -> list[Evidence]:
    """Full-text search across key evidence fields."""
    from sqlalchemy import or_

    q = db.query(Evidence).options(joinedload(Evidence.case), joinedload(Evidence.creator))

    if case_id:
        q = q.filter(Evidence.case_id == case_id)
    if category:
        q = q.filter(Evidence.evidence_category == category)
    if investigator_id:
        q = q.filter(Evidence.created_by == investigator_id)
    if query:
        term = f"%{query}%"
        q = q.filter(
            or_(
                Evidence.evidence_id.ilike(term),
                Evidence.original_filename.ilike(term),
                Evidence.sha256.ilike(term),
                Evidence.sha512.ilike(term),
                Evidence.md5.ilike(term),
                Evidence.description.ilike(term),
                Evidence.source.ilike(term),
                Evidence.suspect_reference.ilike(term),
            )
        )

    return q.order_by(Evidence.imported_timestamp.desc()).offset(skip).limit(limit).all()


def add_metadata(
    db: Session, evidence_id: str, key: str, value: str
) -> EvidenceMetadata:
    entry = EvidenceMetadata(
        id=gen_uuid(),
        evidence_id=evidence_id,
        key=key,
        value=value,
    )
    db.add(entry)
    db.flush()
    return entry
