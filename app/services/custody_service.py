"""
Chain-of-Custody service.

Each custody event references the previous event's hash so that
the entire chain can be verified for tampering.

Chain hash formula:
    event_hash = SHA-256(previous_hash + event_id + evidence_id +
                         action + description + timestamp_iso)

The genesis event uses the literal string "GENESIS" as previous_hash.
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.database.models import ChainOfCustody, CustodyAction, gen_uuid

GENESIS = "GENESIS"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _compute_event_hash(
    previous_hash: str,
    event_id: str,
    evidence_id: str,
    action: str,
    description: str,
    timestamp: datetime,
) -> str:
    payload = (
        previous_hash
        + event_id
        + evidence_id
        + action
        + description
        + timestamp.isoformat()
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def create_custody_event(
    db: Session,
    case_id: str,
    evidence_id: str,
    user_id: str,
    action: CustodyAction,
    description: str,
    source_ip: Optional[str] = None,
) -> ChainOfCustody:
    """
    Append a new custody event to the chain.

    1. Fetch the latest event for this evidence item (if any).
    2. Use its event_hash as previous_hash (or GENESIS for the first event).
    3. Compute the new event_hash over (previous_hash + event fields).
    4. Persist and return the new event.
    """
    # Get the previous event's hash
    latest = (
        db.query(ChainOfCustody)
        .filter(ChainOfCustody.evidence_id == evidence_id)
        .order_by(ChainOfCustody.timestamp.desc())
        .first()
    )
    previous_hash = latest.event_hash if latest else GENESIS

    now = utcnow()
    event_id = gen_uuid()

    event_hash = _compute_event_hash(
        previous_hash=previous_hash,
        event_id=event_id,
        evidence_id=evidence_id,
        action=action.value,
        description=description,
        timestamp=now,
    )

    event = ChainOfCustody(
        id=gen_uuid(),
        event_id=event_id,
        case_id=case_id,
        evidence_id=evidence_id,
        user_id=user_id,
        action=action,
        description=description,
        timestamp=now,
        source_ip=source_ip,
        previous_hash=previous_hash,
        event_hash=event_hash,
    )
    db.add(event)
    db.flush()
    return event


def verify_custody_chain(db: Session, evidence_id: str) -> dict:
    """
    Walk the entire custody chain for *evidence_id* and verify that
    no event has been tampered with.

    Returns a dict with keys:
        valid           – bool
        checked_events  – int
        message         – str
        failed_event_id – str or None
    """
    events = (
        db.query(ChainOfCustody)
        .filter(ChainOfCustody.evidence_id == evidence_id)
        .order_by(ChainOfCustody.timestamp.asc())
        .all()
    )

    if not events:
        return {
            "valid": True,
            "checked_events": 0,
            "message": "No custody events found for this evidence item.",
            "failed_event_id": None,
        }

    previous_hash = GENESIS
    for event in events:
        if event.previous_hash != previous_hash:
            return {
                "valid": False,
                "checked_events": events.index(event),
                "message": f"Chain integrity failure at event {event.event_id}: previous_hash mismatch.",
                "failed_event_id": event.event_id,
            }

        expected_hash = _compute_event_hash(
            previous_hash=event.previous_hash,
            event_id=event.event_id,
            evidence_id=event.evidence_id,
            action=event.action.value,
            description=event.description,
            timestamp=event.timestamp,
        )
        if expected_hash != event.event_hash:
            return {
                "valid": False,
                "checked_events": events.index(event) + 1,
                "message": f"Chain integrity failure at event {event.event_id}: event_hash mismatch.",
                "failed_event_id": event.event_id,
            }

        previous_hash = event.event_hash

    return {
        "valid": True,
        "checked_events": len(events),
        "message": f"Chain verified successfully. {len(events)} event(s) checked.",
        "failed_event_id": None,
    }


def get_custody_events(
    db: Session,
    evidence_id: Optional[str] = None,
    case_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 200,
):
    """Return custody events, newest first."""
    from sqlalchemy import desc

    q = db.query(ChainOfCustody)
    if evidence_id:
        q = q.filter(ChainOfCustody.evidence_id == evidence_id)
    if case_id:
        q = q.filter(ChainOfCustody.case_id == case_id)
    return q.order_by(desc(ChainOfCustody.timestamp)).offset(skip).limit(limit).all()
