"""
Evidence router — import, list, view, verify, download, search.
Evidence files are NEVER executed or modified.
"""

import io
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Request, Form, UploadFile, File, Query
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import (
    Case, Evidence, User, EvidenceCategory, EvidenceTag,
    AuditAction, CustodyAction, VerificationStatus, gen_uuid,
)
from app.auth import get_current_user_from_request
from app.services.evidence_service import (
    import_evidence_file, get_evidence, search_evidence, add_metadata,
)
from app.services.verification_service import verify_evidence_integrity
from app.services.custody_service import create_custody_event, get_custody_events
from app.services.audit_service import record_audit
from app.config import get_settings

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
settings = get_settings()


def _require_login(request: Request, db: Session):
    user_data = get_current_user_from_request(request)
    if not user_data:
        return None, RedirectResponse(url="/login", status_code=302)
    user = db.get(User, user_data["sub"])
    return user, None


def _get_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _fmt_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


# ─── Evidence list / search ───────────────────────────────────────────────────

@router.get("/evidence", response_class=HTMLResponse)
async def evidence_list(
    request: Request,
    db: Session = Depends(get_db),
    q: Optional[str] = Query(default=None),
    case_id: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
):
    user, redir = _require_login(request, db)
    if redir:
        return redir

    items = search_evidence(db, query=q, case_id=case_id, category=category, limit=200)
    cases = db.query(Case).order_by(Case.case_id).all()
    categories = [c.value for c in EvidenceCategory]

    if q:
        record_audit(
            db=db,
            action=AuditAction.SEARCH_PERFORMED,
            user_id=user.id,
            description=f"Evidence search: '{q}'.",
            source_ip=_get_ip(request),
        )
        db.commit()

    return templates.TemplateResponse("evidence.html", {
        "request": request,
        "current_user": user,
        "evidence_items": items,
        "cases": cases,
        "categories": categories,
        "query": q or "",
        "selected_case": case_id or "",
        "selected_category": category or "",
        "fmt_size": _fmt_size,
    })


# ─── Import form ─────────────────────────────────────────────────────────────

@router.get("/evidence/import", response_class=HTMLResponse)
async def import_form(request: Request, db: Session = Depends(get_db)):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    if user.role.value == "REVIEWER":
        return RedirectResponse(url="/evidence?error=permission", status_code=302)
    cases = db.query(Case).filter(Case.status != "ARCHIVED").order_by(Case.case_id).all()
    return templates.TemplateResponse("evidence_import.html", {
        "request": request,
        "current_user": user,
        "cases": cases,
        "categories": [c.value for c in EvidenceCategory],
        "error": None,
    })


@router.post("/evidence/import")
async def import_evidence(
    request: Request,
    db: Session = Depends(get_db),
    case_id: str = Form(...),
    files: list[UploadFile] = File(...),
    evidence_category: str = Form("Other"),
    description: str = Form(""),
    source: str = Form(""),
    device: str = Form(""),
    suspect_reference: str = Form(""),
    acquisition_method: str = Form(""),
    evidence_type: str = Form(""),
    tags_input: str = Form(""),
):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    if user.role.value == "REVIEWER":
        return RedirectResponse(url="/evidence?error=permission", status_code=302)

    case = db.get(Case, case_id)
    if not case:
        cases = db.query(Case).order_by(Case.case_id).all()
        return templates.TemplateResponse("evidence_import.html", {
            "request": request,
            "current_user": user,
            "cases": cases,
            "categories": [c.value for c in EvidenceCategory],
            "error": "Selected case not found.",
        })

    try:
        category_enum = EvidenceCategory(evidence_category)
    except ValueError:
        category_enum = EvidenceCategory.OTHER

    tags = [t.strip() for t in tags_input.split(",") if t.strip()]
    imported_ids = []
    ip = _get_ip(request)

    for upload in files:
        if not upload.filename:
            continue
        data = await upload.read()
        if len(data) > settings.max_upload_size:
            continue  # Skip files that exceed the size limit

        ev = import_evidence_file(
            db=db,
            case_id=case.id,
            original_filename=upload.filename,
            file_data=data,
            created_by=user.id,
            evidence_category=category_enum,
            description=description.strip() or None,
            source=source.strip() or None,
            device=device.strip() or None,
            suspect_reference=suspect_reference.strip() or None,
            acquisition_method=acquisition_method.strip() or None,
            evidence_type=evidence_type.strip() or None,
            tags=tags,
            source_ip=ip,
        )
        imported_ids.append(ev.id)

    if len(imported_ids) == 1:
        return RedirectResponse(url=f"/evidence/{imported_ids[0]}", status_code=302)
    return RedirectResponse(url=f"/cases/{case.id}?imported={len(imported_ids)}", status_code=302)


# ─── Evidence detail ─────────────────────────────────────────────────────────

@router.get("/evidence/{evidence_pk}", response_class=HTMLResponse)
async def evidence_detail(evidence_pk: str, request: Request, db: Session = Depends(get_db)):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    ev = get_evidence(db, evidence_pk)
    if not ev:
        return RedirectResponse(url="/evidence?error=notfound", status_code=302)

    tag_names = [et.tag.name for et in ev.evidence_tags] if ev.evidence_tags else []
    custody = get_custody_events(db, evidence_id=ev.id, limit=50)

    record_audit(
        db=db,
        action=AuditAction.EVIDENCE_VIEWED,
        user_id=user.id,
        entity_type="evidence",
        entity_id=ev.id,
        description=f"Viewed evidence '{ev.evidence_id}'.",
        source_ip=_get_ip(request),
    )
    create_custody_event(
        db=db,
        case_id=ev.case_id,
        evidence_id=ev.id,
        user_id=user.id,
        action=CustodyAction.EVIDENCE_VIEWED,
        description=f"Evidence viewed by user {user.username}.",
        source_ip=_get_ip(request),
    )
    db.commit()

    return templates.TemplateResponse("evidence_detail.html", {
        "request": request,
        "current_user": user,
        "evidence": ev,
        "tags": tag_names,
        "custody_events": custody,
        "fmt_size": _fmt_size,
    })


# ─── Verify integrity ────────────────────────────────────────────────────────

@router.post("/evidence/{evidence_pk}/verify")
async def verify_evidence(evidence_pk: str, request: Request, db: Session = Depends(get_db)):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    ev = db.get(Evidence, evidence_pk)
    if not ev:
        return RedirectResponse(url="/evidence?error=notfound", status_code=302)

    result = verify_evidence_integrity(db, ev, user.id, source_ip=_get_ip(request))
    db.commit()

    tag_names = [et.tag.name for et in ev.evidence_tags] if ev.evidence_tags else []
    custody = get_custody_events(db, evidence_id=ev.id, limit=50)
    db.refresh(ev)

    return templates.TemplateResponse("evidence_detail.html", {
        "request": request,
        "current_user": user,
        "evidence": ev,
        "tags": tag_names,
        "custody_events": custody,
        "fmt_size": _fmt_size,
        "verification_result": result,
    })


# ─── Download ────────────────────────────────────────────────────────────────

@router.get("/evidence/{evidence_pk}/download")
async def download_evidence(evidence_pk: str, request: Request, db: Session = Depends(get_db)):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    ev = db.get(Evidence, evidence_pk)
    if not ev:
        return RedirectResponse(url="/evidence?error=notfound", status_code=302)

    path = Path(ev.storage_path)
    if not path.exists():
        return RedirectResponse(url=f"/evidence/{evidence_pk}?error=file_missing", status_code=302)

    record_audit(
        db=db,
        action=AuditAction.EVIDENCE_DOWNLOADED,
        user_id=user.id,
        entity_type="evidence",
        entity_id=ev.id,
        description=f"Evidence '{ev.evidence_id}' downloaded by {user.username}.",
        source_ip=_get_ip(request),
    )
    create_custody_event(
        db=db,
        case_id=ev.case_id,
        evidence_id=ev.id,
        user_id=user.id,
        action=CustodyAction.EVIDENCE_DOWNLOADED,
        description=f"Evidence downloaded by {user.username}.",
        source_ip=_get_ip(request),
    )
    db.commit()

    data = path.read_bytes()
    return StreamingResponse(
        io.BytesIO(data),
        media_type=ev.mime_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{ev.original_filename}"'},
    )


# ─── Tool output import ───────────────────────────────────────────────────────

@router.get("/evidence/import-tool-output", response_class=HTMLResponse)
async def tool_output_form(request: Request, db: Session = Depends(get_db)):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    if user.role.value == "REVIEWER":
        return RedirectResponse(url="/evidence?error=permission", status_code=302)
    cases = db.query(Case).filter(Case.status != "ARCHIVED").order_by(Case.case_id).all()
    return templates.TemplateResponse("tool_output_import.html", {
        "request": request,
        "current_user": user,
        "cases": cases,
        "result": None,
        "error": None,
    })


@router.post("/evidence/import-tool-output")
async def tool_output_import(
    request: Request,
    db: Session = Depends(get_db),
    case_id: str = Form(...),
    tool_file: UploadFile = File(...),
):
    user, redir = _require_login(request, db)
    if redir:
        return redir
    if user.role.value == "REVIEWER":
        return RedirectResponse(url="/evidence?error=permission", status_code=302)

    case = db.get(Case, case_id)
    if not case:
        cases = db.query(Case).order_by(Case.case_id).all()
        return templates.TemplateResponse("tool_output_import.html", {
            "request": request, "current_user": user,
            "cases": cases, "result": None, "error": "Case not found.",
        })

    content = (await tool_file.read()).decode("utf-8", errors="replace")
    filename = tool_file.filename or "unknown"

    from app.importers.json_importer import JSONImporter
    from app.importers.csv_importer import CSVImporter
    from app.importers.text_importer import TextImporter

    importer = None
    for imp in [JSONImporter(), CSVImporter(), TextImporter()]:
        if imp.can_handle(filename):
            importer = imp
            break

    if importer is None:
        # Default to text
        importer = TextImporter()

    try:
        records = importer.parse(content)
    except Exception as exc:
        cases = db.query(Case).order_by(Case.case_id).all()
        return templates.TemplateResponse("tool_output_import.html", {
            "request": request, "current_user": user,
            "cases": cases, "result": None,
            "error": f"Parse error: {exc}",
        })

    # Store each parsed record as EvidenceMetadata entries attached to the case
    saved = []
    for rec in records:
        from app.database.models import EvidenceMetadata
        from app.services.evidence_service import generate_evidence_id
        from datetime import datetime, timezone

        ev_id = generate_evidence_id()
        # Create a lightweight evidence placeholder for tool-output records
        ev = Evidence(
            id=gen_uuid(),
            evidence_id=ev_id,
            case_id=case.id,
            original_filename=rec.filename or filename,
            stored_filename=f"TOOL_OUTPUT_{ev_id}",
            storage_path="",
            file_size=rec.file_size or 0,
            mime_type="application/x-forensic-tool-output",
            file_extension=Path(filename).suffix.lower(),
            sha256=rec.sha256,
            sha512=rec.sha512,
            md5=rec.md5,
            evidence_category=EvidenceCategory.OTHER,
            source=rec.source,
            description=rec.description or f"Imported from tool output: {filename}",
            imported_timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
            verification_status=VerificationStatus.UNVERIFIED,
            created_by=user.id,
        )
        db.add(ev)
        db.flush()

        for k, v in rec.extra_metadata.items():
            db.add(EvidenceMetadata(id=gen_uuid(), evidence_id=ev.id, key=k, value=str(v)))

        create_custody_event(
            db=db, case_id=case.id, evidence_id=ev.id, user_id=user.id,
            action=CustodyAction.EVIDENCE_IMPORTED,
            description=f"Evidence metadata imported from tool output file '{filename}'.",
            source_ip=_get_ip(request),
        )
        saved.append(ev_id)

    record_audit(
        db=db, action=AuditAction.TOOL_OUTPUT_IMPORTED, user_id=user.id,
        entity_type="case", entity_id=case.id,
        description=f"Imported {len(saved)} record(s) from tool output '{filename}'.",
        source_ip=_get_ip(request),
    )
    db.commit()

    cases = db.query(Case).order_by(Case.case_id).all()
    return templates.TemplateResponse("tool_output_import.html", {
        "request": request, "current_user": user,
        "cases": cases,
        "result": {"count": len(saved), "ids": saved},
        "error": None,
    })
