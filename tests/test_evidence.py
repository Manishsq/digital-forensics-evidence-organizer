"""
Tests for evidence import and metadata.
"""

import pytest


def test_evidence_import(db_session, admin_user, sample_case):
    from app.services.evidence_service import import_evidence_file
    from app.database.models import EvidenceCategory

    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="test_evidence.txt",
        file_data=b"sample forensic evidence content",
        created_by=admin_user["id"],
        evidence_category=EvidenceCategory.DOCUMENT,
        description="Unit test evidence",
    )
    assert ev.id is not None
    assert ev.evidence_id.startswith("EVD-")
    assert ev.original_filename == "test_evidence.txt"
    assert ev.sha256 is not None
    assert len(ev.sha256) == 64
    assert ev.sha512 is not None
    assert len(ev.sha512) == 128
    assert ev.md5 is not None
    assert len(ev.md5) == 32
    assert ev.file_size == len(b"sample forensic evidence content")
    assert ev.case_id == sample_case["id"]


def test_evidence_original_filename_preserved(db_session, admin_user, sample_case):
    """Original filename must be preserved exactly."""
    from app.services.evidence_service import import_evidence_file

    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="My Evidence File (with spaces).pcap",
        file_data=b"pcap data",
        created_by=admin_user["id"],
    )
    assert ev.original_filename == "My Evidence File (with spaces).pcap"
    assert "My Evidence" not in ev.stored_filename  # stored name is generated


def test_evidence_stored_filename_is_safe(db_session, admin_user, sample_case):
    """Stored filename must not contain the original (potentially unsafe) name."""
    from app.services.evidence_service import import_evidence_file

    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="../../../etc/passwd",
        file_data=b"injection attempt",
        created_by=admin_user["id"],
    )
    assert ".." not in ev.stored_filename
    assert "etc" not in ev.stored_filename


def test_evidence_has_hashes(db_session, admin_user, sample_case):
    import hashlib
    from app.services.evidence_service import import_evidence_file

    content = b"known content for hash verification"
    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="known.bin",
        file_data=content,
        created_by=admin_user["id"],
    )
    assert ev.sha256 == hashlib.sha256(content).hexdigest()
    assert ev.sha512 == hashlib.sha512(content).hexdigest()
    assert ev.md5    == hashlib.md5(content).hexdigest()


def test_evidence_has_custody_event(db_session, admin_user, sample_case):
    from app.services.evidence_service import import_evidence_file
    from app.database.models import ChainOfCustody

    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="custody_check.txt",
        file_data=b"data",
        created_by=admin_user["id"],
    )
    events = db_session.query(ChainOfCustody).filter(
        ChainOfCustody.evidence_id == ev.id
    ).all()
    assert len(events) >= 1
    assert events[0].action.value == "EVIDENCE_IMPORTED"


def test_evidence_case_relationship(db_session, admin_user, sample_case):
    from app.services.evidence_service import import_evidence_file, get_evidence

    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="rel_test.log",
        file_data=b"log data",
        created_by=admin_user["id"],
    )
    fetched = get_evidence(db_session, ev.id)
    assert fetched is not None
    assert fetched.case.case_id == sample_case["case_id"]


def test_evidence_with_tags(db_session, admin_user, sample_case):
    from app.services.evidence_service import import_evidence_file

    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="tagged.bin",
        file_data=b"tag test",
        created_by=admin_user["id"],
        tags=["network", "pcap", "windows"],
    )
    tag_names = {et.tag.name for et in ev.evidence_tags}
    assert "network" in tag_names
    assert "pcap" in tag_names
    assert "windows" in tag_names


def test_evidence_search_by_hash(db_session, admin_user, sample_case):
    import hashlib
    from app.services.evidence_service import import_evidence_file, search_evidence

    content = b"searchable evidence content xyz"
    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="search_test.bin",
        file_data=content,
        created_by=admin_user["id"],
    )
    sha = hashlib.sha256(content).hexdigest()
    results = search_evidence(db_session, query=sha)
    ids = [r.id for r in results]
    assert ev.id in ids


def test_case_invalid_raises(db_session, admin_user):
    from app.services.evidence_service import import_evidence_file

    with pytest.raises(ValueError):
        import_evidence_file(
            db=db_session,
            case_id="nonexistent-case-id",
            original_filename="fail.txt",
            file_data=b"data",
            created_by=admin_user["id"],
        )
