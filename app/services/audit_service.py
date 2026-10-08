"""
Audit logging service.

Records every significant user action to the audit_logs table.
Never modify or delete audit records.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.database.models import AuditLog, AuditAction, gen_uuid


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def record_audit(
    db: Session,
    action: AuditAction,
    user_id: Optional[str] = None,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    description: Optional[str] = None,
    source_ip: Optional[str] = None,
) -> AuditLog:
    """
    Append an audit event.  Returns the created AuditLog row.
    This operation never raises – a failure is silently swallowed
    so that audit failures never break normal application flow.
    """
    try:
        entry = AuditLog(
            id=gen_uuid(),
            user_id=user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            description=description,
            timestamp=utcnow(),
            source_ip=source_ip,
        )
        db.add(entry)
        db.flush()
        return entry
    except Exception:
        # Audit failure must not interrupt normal operations
        db.rollback()
        raise


def get_audit_logs(
    db: Session,
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    skip: int = 0,
    limit: int = 200,
):
    """Return filtered audit log entries, newest first."""
    from sqlalchemy import desc

    q = db.query(AuditLog)
    if user_id:
        q = q.filter(AuditLog.user_id == user_id)
    if action:
        q = q.filter(AuditLog.action == action)
    if entity_type:
        q = q.filter(AuditLog.entity_type == entity_type)
    if entity_id:
        q = q.filter(AuditLog.entity_id == entity_id)
    if date_from:
        q = q.filter(AuditLog.timestamp >= date_from)
    if date_to:
        q = q.filter(AuditLog.timestamp <= date_to)
    return q.order_by(desc(AuditLog.timestamp)).offset(skip).limit(limit).all()
