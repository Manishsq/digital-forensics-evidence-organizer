"""
Authentication router — login, logout, user creation.
"""

from fastapi import APIRouter, Depends, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import User, UserRole, AuditAction, gen_uuid
from app.auth import hash_password, verify_password, create_access_token, SESSION_COOKIE, get_current_user_from_request
from app.services.audit_service import record_audit

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _get_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = get_current_user_from_request(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    ip = _get_ip(request)
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active or not verify_password(password, user.hashed_password):
        record_audit(
            db=db,
            action=AuditAction.LOGIN,
            description=f"Failed login attempt for username '{username}'.",
            source_ip=ip,
        )
        db.commit()
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid username or password."},
            status_code=401,
        )

    token = create_access_token({"sub": user.id, "username": user.username, "role": user.role.value})
    record_audit(
        db=db,
        action=AuditAction.LOGIN,
        user_id=user.id,
        description=f"User '{username}' logged in.",
        source_ip=ip,
    )
    db.commit()

    response = RedirectResponse(url="/dashboard", status_code=302)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=28800,
    )
    return response


@router.get("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    user_data = get_current_user_from_request(request)
    if user_data:
        record_audit(
            db=db,
            action=AuditAction.LOGOUT,
            user_id=user_data.get("sub"),
            description=f"User '{user_data.get('username')}' logged out.",
            source_ip=_get_ip(request),
        )
        db.commit()
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response


# ─── User management (ADMIN only) ───────────────────────────────────────────

@router.get("/admin/users", response_class=HTMLResponse)
async def users_list(request: Request, db: Session = Depends(get_db)):
    user_data = _require_admin(request)
    if isinstance(user_data, RedirectResponse):
        return user_data
    users = db.query(User).order_by(User.created_at.desc()).all()
    current_user = db.get(User, user_data["sub"])
    return templates.TemplateResponse(
        "admin_users.html",
        {"request": request, "users": users, "current_user": current_user},
    )


@router.post("/admin/users/create")
async def create_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    full_name: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    organization: str = Form(""),
    db: Session = Depends(get_db),
):
    user_data = _require_admin(request)
    if isinstance(user_data, RedirectResponse):
        return user_data

    # Check duplicate
    existing = db.query(User).filter(
        (User.username == username) | (User.email == email)
    ).first()
    if existing:
        return RedirectResponse(url="/admin/users?error=duplicate", status_code=302)

    try:
        role_enum = UserRole(role.upper())
    except ValueError:
        role_enum = UserRole.INVESTIGATOR

    new_user = User(
        id=gen_uuid(),
        username=username,
        email=email,
        full_name=full_name,
        hashed_password=hash_password(password),
        role=role_enum,
        organization=organization or None,
    )
    db.add(new_user)
    record_audit(
        db=db,
        action=AuditAction.USER_CREATED,
        user_id=user_data["sub"],
        entity_type="user",
        entity_id=new_user.id,
        description=f"Created user '{username}' with role {role_enum.value}.",
        source_ip=_get_ip(request),
    )
    db.commit()
    return RedirectResponse(url="/admin/users?success=created", status_code=302)


def _require_admin(request: Request):
    user_data = get_current_user_from_request(request)
    if not user_data or user_data.get("role") != UserRole.ADMIN.value:
        return RedirectResponse(url="/login", status_code=302)
    return user_data


def require_login(request: Request):
    """Return user_data or a RedirectResponse."""
    user_data = get_current_user_from_request(request)
    if not user_data:
        return None
    return user_data
