"""
Reports router.
"""

from pathlib import Path

from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Optional

from app.database.database import get_db
from app.database.models import Case, Evidence, Report, User
from app.auth import get_current_user_from_request
from app.services.report_service import generate_case_report, generate_evidence_report

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _require_login(request: Request, db: Session):
    user_data = get_current_user_from_request(request)
    if not user_data:
        return None, RedirectResponse(url="/login", status_code=302)
    return db.get(User, user_data["sub"]), None


def _get_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.get("/reports", response_class=HTMLResponse)
async def reports_list(request: Request, db: Session = Depends(get_db)):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    reports = db.query(Report).order_by(Report.generated_at.desc()).all()
    return templates.TemplateResponse("reports.html", {
        "request": request,
        "current_user": user,
        "reports": reports,
    })


@router.post("/reports/generate/case/{case_pk}")
async def gen_case_report(case_pk: str, request: Request, db: Session = Depends(get_db)):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    try:
        report = generate_case_report(db, case_id=case_pk, generated_by=user.id, source_ip=_get_ip(request))
    except ValueError as exc:
        return RedirectResponse(url=f"/cases/{case_pk}?error={exc}", status_code=302)
    return RedirectResponse(url=f"/reports/{report.id}", status_code=302)


@router.post("/reports/generate/evidence/{evidence_pk}")
async def gen_evidence_report(evidence_pk: str, request: Request, db: Session = Depends(get_db)):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    try:
        report = generate_evidence_report(db, evidence_id=evidence_pk, generated_by=user.id, source_ip=_get_ip(request))
    except ValueError as exc:
        return RedirectResponse(url=f"/evidence/{evidence_pk}?error={exc}", status_code=302)
    return RedirectResponse(url=f"/reports/{report.id}", status_code=302)


@router.get("/reports/{report_pk}", response_class=HTMLResponse)
async def view_report(report_pk: str, request: Request, db: Session = Depends(get_db)):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    report = db.get(Report, report_pk)
    if not report:
        return RedirectResponse(url="/reports?error=notfound", status_code=302)

    html_content = ""
    if report.storage_path:
        p = Path(report.storage_path)
        if p.exists():
            html_content = p.read_text(encoding="utf-8")

    return templates.TemplateResponse("report_view.html", {
        "request": request,
        "current_user": user,
        "report": report,
        "html_content": html_content,
    })


@router.get("/reports/{report_pk}/download")
async def download_report(report_pk: str, request: Request, db: Session = Depends(get_db)):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    report = db.get(Report, report_pk)
    if not report or not report.storage_path:
        return RedirectResponse(url="/reports?error=notfound", status_code=302)
    p = Path(report.storage_path)
    if not p.exists():
        return RedirectResponse(url="/reports?error=file_missing", status_code=302)
    return FileResponse(
        path=str(p),
        media_type="text/html",
        filename=f"{report.report_id}.html",
    )
