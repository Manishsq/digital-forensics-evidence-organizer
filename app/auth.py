"""
Authentication utilities — password hashing, token generation, session handling.
Passwords are NEVER stored as plaintext.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Request

from app.config import get_settings

settings = get_settings()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"
SESSION_COOKIE = "forensics_session"


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_minutes: Optional[int] = None) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes or settings.session_expire_minutes
    )
    payload = {**data, "exp": expire}
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except JWTError:
        return None


def get_current_user_from_request(request: Request):
    """Return user dict from session cookie, or None."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    return decode_token(token)
