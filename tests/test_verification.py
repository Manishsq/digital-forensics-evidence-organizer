"""
Tests for evidence integrity verification service.
"""

import hashlib
import pytest
from pathlib import Path


def test_verify_integrity_pass(db_session, admin_user, sample_case):
    from app.services.evidence_service import import_evidence_file
    from app.services.verification_service import verify_evidence_integrity

    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="verify_ok.txt",
        file_data=b"original evidence content",
        created_by=admin_user["id"],
    )
    result = verify_evidence_integrity(db_session, ev, admin_user["id"])
    assert result["valid"] is True
    assert result["sha256_match"] is True
    assert "VERIFIED" in result["message"]


def test_verify_integrity_fail_on_tamper(db_session, admin_user, sample_case):
    """If the stored file is modified externally, verification must fail."""
    from app.services.evidence_service import import_evidence_file
    from app.services.verification_service import verify_evidence_integrity

    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="tamper_evidence.bin",
        file_data=b"untampered evidence",
        created_by=admin_user["id"],
    )
    # Directly corrupt the stored file (simulating external tampering)
    Path(ev.storage_path).write_bytes(b"TAMPERED CONTENT")

    result = verify_evidence_integrity(db_session, ev, admin_user["id"])
    assert result["valid"] is False
    assert result["sha256_match"] is False
    assert "FAILURE" in result["message"]


def test_verify_does_not_overwrite_original_hash(db_session, admin_user, sample_case):
    """Original hash must NEVER change even after a failed verification."""
    from app.services.evidence_service import import_evidence_file
    from app.services.verification_service import verify_evidence_integrity

    content = b"preserve my hash"
    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="preserve_hash.bin",
        file_data=content,
        created_by=admin_user["id"],
    )
    original_sha256 = ev.sha256
    assert original_sha256 == hashlib.sha256(content).hexdigest()

    # Tamper the file
    Path(ev.storage_path).write_bytes(b"different content")
    verify_evidence_integrity(db_session, ev, admin_user["id"])

    # Original hash must not change
    db_session.refresh(ev)
    assert ev.sha256 == original_sha256


def test_verify_missing_file(db_session, admin_user, sample_case):
    """Missing stored file should return valid=False with appropriate message."""
    from app.services.evidence_service import import_evidence_file
    from app.services.verification_service import verify_evidence_integrity

    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="missing_file.bin",
        file_data=b"data",
        created_by=admin_user["id"],
    )
    # Remove the file
    Path(ev.storage_path).unlink(missing_ok=True)

    result = verify_evidence_integrity(db_session, ev, admin_user["id"])
    assert result["valid"] is False
