"""
Chain-of-custody router.
"""

from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Optional

from app.database.database import get_db
from app.database.models import Evidence, User, Case, AuditAction
from app.auth import get_current_user_from_request
from app.services.custody_service import get_custody_events, verify_custody_chain
from app.services.audit_service import record_audit

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _require_login(request: Request, db: Session):
    user_data = get_current_user_from_request(request)
    if not user_data:
        return None, RedirectResponse(url="/login", status_code=302)
    return db.get(User, user_data["sub"]), None


def _get_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.get("/custody", response_class=HTMLResponse)
async def custody_list(
    request: Request,
    db: Session = Depends(get_db),
    evidence_id: Optional[str] = Query(default=None),
    case_id: Optional[str] = Query(default=None),
):
    user, redir = _require_login(request, db)
    if redir:
        return redir

    events = get_custody_events(db, evidence_id=evidence_id, case_id=case_id, limit=300)
    evidence = db.get(Evidence, evidence_id) if evidence_id else None
    case = db.get(Case, case_id) if case_id else None

    return templates.TemplateResponse("custody.html", {
        "request": request,
        "current_user": user,
        "events": events,
        "evidence": evidence,
        "case": case,
        "filter_evidence_id": evidence_id or "",
        "filter_case_id": case_id or "",
    })


@router.post("/custody/verify/{evidence_pk}")
async def verify_chain(evidence_pk: str, request: Request, db: Session = Depends(get_db)):
    user, redir = _require_login(request, db)
    if redir:
        return redir

    ev = db.get(Evidence, evidence_pk)
    if not ev:
        return RedirectResponse(url="/custody?error=notfound", status_code=302)

    result = verify_custody_chain(db, evidence_id=ev.id)

    from app.services.custody_service import create_custody_event
    from app.database.models import CustodyAction

    create_custody_event(
        db=db,
        case_id=ev.case_id,
        evidence_id=ev.id,
        user_id=user.id,
        action=CustodyAction.CHAIN_VERIFIED,
        description=(
            f"Custody chain verification: {'PASSED' if result['valid'] else 'FAILED'}. "
            f"{result['message']}"
        ),
        source_ip=_get_ip(request),
    )
    record_audit(
        db=db,
        action=AuditAction.CHAIN_VERIFIED,
        user_id=user.id,
        entity_type="evidence",
        entity_id=ev.id,
        description=f"Chain verify for {ev.evidence_id}: {'PASSED' if result['valid'] else 'FAILED'}.",
        source_ip=_get_ip(request),
    )
    db.commit()

    events = get_custody_events(db, evidence_id=ev.id, limit=300)
    return templates.TemplateResponse("custody.html", {
        "request": request,
        "current_user": user,
        "events": events,
        "evidence": ev,
        "case": db.get(Case, ev.case_id),
        "filter_evidence_id": ev.id,
        "filter_case_id": "",
        "chain_result": result,
    })
