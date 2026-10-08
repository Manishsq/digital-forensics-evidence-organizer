"""
Tests for authentication: password hashing, token creation/decode, roles.
"""

import pytest


def test_password_hashing():
    from app.auth import hash_password, verify_password
    hashed = hash_password("MySecurePassword123!")
    assert hashed != "MySecurePassword123!"
    assert verify_password("MySecurePassword123!", hashed)


def test_wrong_password_rejected():
    from app.auth import hash_password, verify_password
    hashed = hash_password("correct-password")
    assert not verify_password("wrong-password", hashed)


def test_token_encode_decode():
    from app.auth import create_access_token, decode_token
    token = create_access_token({"sub": "user-id-123", "username": "alice", "role": "INVESTIGATOR"})
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "user-id-123"
    assert payload["username"] == "alice"


def test_invalid_token_returns_none():
    from app.auth import decode_token
    result = decode_token("this.is.not.valid")
    assert result is None


def test_tampered_token_returns_none():
    from app.auth import create_access_token, decode_token
    token = create_access_token({"sub": "user"})
    tampered = token[:-5] + "XXXXX"
    assert decode_token(tampered) is None


def test_login_success(client, admin_user):
    resp = client.post("/login", data={"username": "test_admin", "password": "TestPass123!"})
    assert resp.status_code == 302
    assert "forensics_session" in resp.cookies


def test_login_wrong_password(client):
    resp = client.post("/login", data={"username": "test_admin", "password": "WrongPassword!"})
    assert resp.status_code == 401


def test_login_nonexistent_user(client):
    resp = client.post("/login", data={"username": "ghost_user_xyz", "password": "pass"})
    assert resp.status_code == 401


def test_logout_clears_cookie(client, admin_user):
    # Login first
    login_resp = client.post("/login", data={"username": "test_admin", "password": "TestPass123!"})
    assert login_resp.status_code == 302
    # Logout
    logout_resp = client.get("/logout")
    assert logout_resp.status_code == 302


def test_dashboard_requires_auth(client):
    """Dashboard should redirect unauthenticated users to login."""
    # Use a fresh client without session cookie
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app, follow_redirects=False) as c:
        resp = c.get("/dashboard")
    assert resp.status_code == 302
    assert "/login" in resp.headers.get("location", "")
