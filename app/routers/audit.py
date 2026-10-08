"""
Audit log router.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import User, AuditAction
from app.auth import get_current_user_from_request
from app.services.audit_service import get_audit_logs

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _require_login(request: Request, db: Session):
    user_data = get_current_user_from_request(request)
    if not user_data:
        return None, RedirectResponse(url="/login", status_code=302)
    return db.get(User, user_data["sub"]), None


@router.get("/audit", response_class=HTMLResponse)
async def audit_log(
    request: Request,
    db: Session = Depends(get_db),
    user_filter: Optional[str] = Query(default=None),
    action_filter: Optional[str] = Query(default=None),
    date_from: Optional[str] = Query(default=None),
    date_to: Optional[str] = Query(default=None),
    entity_type: Optional[str] = Query(default=None),
):
    user, redir = _require_login(request, db)
    if redir:
        return redir

    df = None
    dt = None
    if date_from:
        try:
            df = datetime.fromisoformat(date_from)
        except ValueError:
            pass
    if date_to:
        try:
            dt = datetime.fromisoformat(date_to)
        except ValueError:
            pass

    logs = get_audit_logs(
        db,
        user_id=user_filter or None,
        action=action_filter or None,
        entity_type=entity_type or None,
        date_from=df,
        date_to=dt,
        limit=300,
    )

    all_users = db.query(User).order_by(User.username).all()
    actions = [a.value for a in AuditAction]

    return templates.TemplateResponse("audit.html", {
        "request": request,
        "current_user": user,
        "logs": logs,
        "all_users": all_users,
        "actions": actions,
        "filter_user": user_filter or "",
        "filter_action": action_filter or "",
        "filter_date_from": date_from or "",
        "filter_date_to": date_to or "",
        "filter_entity_type": entity_type or "",
    })
