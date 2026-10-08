"""
Evidence integrity verification service.

Recalculates hashes and compares them with stored originals.
Never replaces or alters the original stored hashes.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from app.database.models import (
    Evidence,
    VerificationStatus,
    CustodyAction,
    AuditAction,
    gen_uuid,
)
from app.services.hashing import calculate_sha256, calculate_hashes
from app.services.custody_service import create_custody_event
from app.services.audit_service import record_audit


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def verify_evidence_integrity(
    db: Session,
    evidence: Evidence,
    user_id: str,
    source_ip: Optional[str] = None,
    full: bool = True,
) -> dict:
    """
    Recalculate hashes for stored evidence and compare with originals.

    Args:
        full: if True, verify SHA-256, SHA-512 and MD5.
              if False, verify SHA-256 only (faster).

    Returns a dict:
        {
            "valid":        bool,
            "sha256_match": bool,
            "sha512_match": bool | None,
            "md5_match":    bool | None,
            "calculated":   { "sha256": ..., "sha512": ..., "md5": ... },
            "stored":       { "sha256": ..., "sha512": ..., "md5": ... },
            "message":      str,
        }
    """
    path = Path(evidence.storage_path)
    if not path.exists():
        result = {
            "valid": False,
            "sha256_match": False,
            "sha512_match": None,
            "md5_match": None,
            "calculated": {},
            "stored": {
                "sha256": evidence.sha256,
                "sha512": evidence.sha512,
                "md5": evidence.md5,
            },
            "message": "INTEGRITY FAILURE – Evidence file not found on disk.",
        }
        _record_failure(db, evidence, user_id, result["message"], source_ip)
        return result

    if full:
        calculated = calculate_hashes(path)
    else:
        sha = calculate_sha256(path)
        calculated = {"sha256": sha, "sha512": None, "md5": None}

    sha256_match = calculated["sha256"] == evidence.sha256
    sha512_match = (calculated["sha512"] == evidence.sha512) if full else None
    md5_match    = (calculated["md5"]    == evidence.md5)    if full else None

    valid = sha256_match and (sha512_match is not False) and (md5_match is not False)

    stored = {
        "sha256": evidence.sha256,
        "sha512": evidence.sha512,
        "md5":    evidence.md5,
    }

    message = "INTEGRITY VERIFIED" if valid else "INTEGRITY FAILURE"

    now = utcnow()
    evidence.last_verified_at = now
    evidence.last_verified_by = user_id
    evidence.verification_status = (
        VerificationStatus.VERIFIED if valid else VerificationStatus.FAILED
    )
    # Never touch original hashes (sha256/sha512/md5 columns)

    action = CustodyAction.EVIDENCE_VERIFIED if valid else CustodyAction.VERIFICATION_FAILED
    desc = (
        f"Hash verification {'passed' if valid else 'FAILED'}. "
        f"SHA-256 {'matched' if sha256_match else 'MISMATCH'}. "
        f"Calculated SHA-256: {calculated['sha256']}"
    )
    create_custody_event(
        db=db,
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        user_id=user_id,
        action=action,
        description=desc,
        source_ip=source_ip,
    )

    record_audit(
        db=db,
        action=AuditAction.HASH_VERIFIED,
        user_id=user_id,
        entity_type="evidence",
        entity_id=evidence.id,
        description=desc,
        source_ip=source_ip,
    )

    db.flush()

    return {
        "valid": valid,
        "sha256_match": sha256_match,
        "sha512_match": sha512_match,
        "md5_match": md5_match,
        "calculated": calculated,
        "stored": stored,
        "message": message,
    }


def _record_failure(
    db: Session, evidence: Evidence, user_id: str, message: str, source_ip: Optional[str]
) -> None:
    evidence.verification_status = VerificationStatus.FAILED
    create_custody_event(
        db=db,
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        user_id=user_id,
        action=CustodyAction.VERIFICATION_FAILED,
        description=message,
        source_ip=source_ip,
    )
    record_audit(
        db=db,
        action=AuditAction.HASH_VERIFIED,
        user_id=user_id,
        entity_type="evidence",
        entity_id=evidence.id,
        description=message,
        source_ip=source_ip,
    )
    db.flush()
