"""
Cases router — create, list, view, update cases.
"""

from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.database import get_db
from app.database.models import Case, Evidence, User, CaseStatus, AuditAction, gen_uuid
from app.auth import get_current_user_from_request
from app.services.audit_service import record_audit

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _require_login(request: Request, db: Session):
    user_data = get_current_user_from_request(request)
    if not user_data:
        return None, RedirectResponse(url="/login", status_code=302)
    user = db.get(User, user_data["sub"])
    return user, None


def _get_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.get("/cases", response_class=HTMLResponse)
async def cases_list(request: Request, db: Session = Depends(get_db)):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    cases = db.query(Case).order_by(Case.created_at.desc()).all()
    case_evidence_counts = {
        row[0]: row[1]
        for row in db.query(Evidence.case_id, func.count(Evidence.id))
        .group_by(Evidence.case_id)
        .all()
    }
    return templates.TemplateResponse("cases.html", {
        "request": request,
        "current_user": user,
        "cases": cases,
        "evidence_counts": case_evidence_counts,
        "statuses": [s.value for s in CaseStatus],
    })


@router.get("/cases/new", response_class=HTMLResponse)
async def new_case_form(request: Request, db: Session = Depends(get_db)):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    if user.role.value == "REVIEWER":
        return RedirectResponse(url="/cases?error=permission", status_code=302)
    return templates.TemplateResponse("case_form.html", {
        "request": request,
        "current_user": user,
        "error": None,
        "form": {},
    })


@router.post("/cases/new")
async def create_case(
    request: Request,
    case_id_input: str = Form(..., alias="case_id"),
    name: str = Form(...),
    description: str = Form(""),
    organization: str = Form(""),
    notes: str = Form(""),
    db: Session = Depends(get_db),
):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    if user.role.value == "REVIEWER":
        return RedirectResponse(url="/cases?error=permission", status_code=302)

    # Duplicate check
    existing = db.query(Case).filter(Case.case_id == case_id_input.strip()).first()
    if existing:
        return templates.TemplateResponse("case_form.html", {
            "request": request,
            "current_user": user,
            "error": f"Case ID '{case_id_input}' already exists.",
            "form": {"case_id": case_id_input, "name": name, "description": description,
                     "organization": organization, "notes": notes},
        })

    case = Case(
        id=gen_uuid(),
        case_id=case_id_input.strip().upper(),
        name=name.strip(),
        description=description.strip() or None,
        investigator_id=user.id,
        organization=organization.strip() or None,
        notes=notes.strip() or None,
        status=CaseStatus.OPEN,
    )
    db.add(case)
    record_audit(
        db=db,
        action=AuditAction.CASE_CREATED,
        user_id=user.id,
        entity_type="case",
        entity_id=case.id,
        description=f"Created case '{case.case_id}': {name}.",
        source_ip=_get_ip(request),
    )
    db.commit()
    return RedirectResponse(url=f"/cases/{case.id}", status_code=302)


@router.get("/cases/{case_pk}", response_class=HTMLResponse)
async def case_detail(case_pk: str, request: Request, db: Session = Depends(get_db)):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    case = db.get(Case, case_pk)
    if not case:
        return RedirectResponse(url="/cases?error=notfound", status_code=302)

    evidence_items = (
        db.query(Evidence)
        .filter(Evidence.case_id == case_pk)
        .order_by(Evidence.imported_timestamp.desc())
        .all()
    )

    from app.database.models import ChainOfCustody
    custody_events = (
        db.query(ChainOfCustody)
        .filter(ChainOfCustody.case_id == case_pk)
        .order_by(ChainOfCustody.timestamp.desc())
        .limit(20)
        .all()
    )

    from app.database.models import Report
    reports = (
        db.query(Report)
        .filter(Report.case_id == case_pk)
        .order_by(Report.generated_at.desc())
        .all()
    )

    record_audit(
        db=db,
        action=AuditAction.CASE_VIEWED,
        user_id=user.id,
        entity_type="case",
        entity_id=case.id,
        description=f"Viewed case '{case.case_id}'.",
        source_ip=_get_ip(request),
    )
    db.commit()

    return templates.TemplateResponse("case_detail.html", {
        "request": request,
        "current_user": user,
        "case": case,
        "evidence_items": evidence_items,
        "custody_events": custody_events,
        "reports": reports,
        "statuses": [s.value for s in CaseStatus],
    })


@router.post("/cases/{case_pk}/update")
async def update_case(
    case_pk: str,
    request: Request,
    status: str = Form(...),
    name: str = Form(...),
    description: str = Form(""),
    notes: str = Form(""),
    db: Session = Depends(get_db),
):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    if user.role.value == "REVIEWER":
        return RedirectResponse(url=f"/cases/{case_pk}?error=permission", status_code=302)

    case = db.get(Case, case_pk)
    if not case:
        return RedirectResponse(url="/cases", status_code=302)

    case.name = name.strip()
    case.description = description.strip() or None
    case.notes = notes.strip() or None
    try:
        case.status = CaseStatus(status)
    except ValueError:
        pass

    record_audit(
        db=db,
        action=AuditAction.CASE_MODIFIED,
        user_id=user.id,
        entity_type="case",
        entity_id=case.id,
        description=f"Updated case '{case.case_id}'.",
        source_ip=_get_ip(request),
    )
    db.commit()
    return RedirectResponse(url=f"/cases/{case_pk}", status_code=302)
