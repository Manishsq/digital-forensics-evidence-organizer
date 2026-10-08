"""
Dashboard router — summary statistics and recent activity.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.database import get_db
from app.database.models import Case, Evidence, ChainOfCustody, User, CaseStatus, VerificationStatus, AuditLog
from app.auth import get_current_user_from_request

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return RedirectResponse(url="/dashboard", status_code=302)


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    user_data = get_current_user_from_request(request)
    if not user_data:
        return RedirectResponse(url="/login", status_code=302)

    current_user = db.get(User, user_data["sub"])

    # Statistics
    total_cases   = db.query(func.count(Case.id)).scalar()
    open_cases    = db.query(func.count(Case.id)).filter(Case.status == CaseStatus.OPEN).scalar()
    closed_cases  = db.query(func.count(Case.id)).filter(Case.status == CaseStatus.CLOSED).scalar()
    total_evidence = db.query(func.count(Evidence.id)).scalar()
    verified_evidence = db.query(func.count(Evidence.id)).filter(
        Evidence.verification_status == VerificationStatus.VERIFIED
    ).scalar()
    pending_verification = db.query(func.count(Evidence.id)).filter(
        Evidence.verification_status == VerificationStatus.UNVERIFIED
    ).scalar()

    # Total storage used
    storage_bytes = db.query(func.sum(Evidence.file_size)).scalar() or 0

    # Recent custody events (latest 10)
    recent_custody = (
        db.query(ChainOfCustody)
        .order_by(ChainOfCustody.timestamp.desc())
        .limit(10)
        .all()
    )

    # Recent evidence imports (latest 5)
    recent_evidence = (
        db.query(Evidence)
        .order_by(Evidence.imported_timestamp.desc())
        .limit(5)
        .all()
    )

    # Recent audit events
    recent_audit = (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .limit(8)
        .all()
    )

    def fmt_size(b):
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} PB"

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "current_user": current_user,
        "stats": {
            "total_cases": total_cases,
            "open_cases": open_cases,
            "closed_cases": closed_cases,
            "total_evidence": total_evidence,
            "verified_evidence": verified_evidence,
            "pending_verification": pending_verification,
            "storage_used": fmt_size(storage_bytes),
            "storage_bytes": storage_bytes,
        },
        "recent_custody": recent_custody,
        "recent_evidence": recent_evidence,
        "recent_audit": recent_audit,
    })
