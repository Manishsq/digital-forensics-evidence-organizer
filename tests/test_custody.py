"""
Tests for chain-of-custody service.
"""

import pytest


def test_custody_event_created(db_session, admin_user, sample_case):
    from app.services.evidence_service import import_evidence_file
    from app.services.custody_service import get_custody_events

    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="custody_test.txt",
        file_data=b"custody test data",
        created_by=admin_user["id"],
    )
    events = get_custody_events(db_session, evidence_id=ev.id)
    assert len(events) >= 1


def test_custody_genesis_first_event(db_session, admin_user, sample_case):
    from app.services.evidence_service import import_evidence_file
    from app.database.models import ChainOfCustody

    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="genesis_test.bin",
        file_data=b"genesis",
        created_by=admin_user["id"],
    )
    events = (
        db_session.query(ChainOfCustody)
        .filter(ChainOfCustody.evidence_id == ev.id)
        .order_by(ChainOfCustody.timestamp.asc())
        .all()
    )
    assert events[0].previous_hash == "GENESIS"


def test_custody_chain_links(db_session, admin_user, sample_case):
    """Each event's previous_hash must equal the previous event's event_hash."""
    from app.services.evidence_service import import_evidence_file
    from app.services.custody_service import create_custody_event, get_custody_events
    from app.database.models import CustodyAction

    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="chain_link_test.bin",
        file_data=b"chain link test",
        created_by=admin_user["id"],
    )
    # Add a second event
    create_custody_event(
        db=db_session,
        case_id=sample_case["id"],
        evidence_id=ev.id,
        user_id=admin_user["id"],
        action=CustodyAction.EVIDENCE_VIEWED,
        description="Viewed by test",
    )
    db_session.flush()

    events = get_custody_events(db_session, evidence_id=ev.id, limit=100)
    events_asc = list(reversed(events))  # events returned newest-first, reverse for chronological

    for i in range(1, len(events_asc)):
        assert events_asc[i].previous_hash == events_asc[i - 1].event_hash


def test_custody_chain_verify_valid(db_session, admin_user, sample_case):
    from app.services.evidence_service import import_evidence_file
    from app.services.custody_service import verify_custody_chain

    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="verify_chain_ok.bin",
        file_data=b"valid chain data",
        created_by=admin_user["id"],
    )
    result = verify_custody_chain(db_session, ev.id)
    assert result["valid"] is True
    assert result["checked_events"] >= 1
    assert "verified" in result["message"].lower()


def test_custody_chain_tamper_detection(db_session, admin_user, sample_case):
    """Modifying a custody event description should cause chain verification to fail."""
    from app.services.evidence_service import import_evidence_file
    from app.services.custody_service import verify_custody_chain, create_custody_event
    from app.database.models import ChainOfCustody, CustodyAction

    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="tamper_test.bin",
        file_data=b"tamper test",
        created_by=admin_user["id"],
    )
    # Add a second event
    create_custody_event(
        db=db_session,
        case_id=sample_case["id"],
        evidence_id=ev.id,
        user_id=admin_user["id"],
        action=CustodyAction.EVIDENCE_VIEWED,
        description="Original description",
    )
    db_session.flush()

    # Tamper: modify the first event's description directly
    first_event = (
        db_session.query(ChainOfCustody)
        .filter(ChainOfCustody.evidence_id == ev.id)
        .order_by(ChainOfCustody.timestamp.asc())
        .first()
    )
    first_event.description = "TAMPERED DESCRIPTION"
    db_session.flush()

    result = verify_custody_chain(db_session, ev.id)
    assert result["valid"] is False
    assert "failure" in result["message"].lower()


def test_custody_no_events(db_session, admin_user):
    """Evidence with no custody events should return valid with 0 events."""
    from app.services.custody_service import verify_custody_chain

    result = verify_custody_chain(db_session, "nonexistent-evidence-id")
    assert result["valid"] is True
    assert result["checked_events"] == 0
