# tests/conftest.py
"""
Shared pytest fixtures for the DFEO test suite.
"""

import os
import pytest
import tempfile
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

# ── Point tests at a temporary SQLite DB and storage dir ──────────────────────
@pytest.fixture(scope="session", autouse=True)
def setup_test_env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("dfeo_test")
    ev_dir  = tmp / "evidence"
    rpt_dir = tmp / "reports"
    ev_dir.mkdir()
    rpt_dir.mkdir()
    db_path = tmp / "test.db"

    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["EVIDENCE_STORAGE_PATH"] = str(ev_dir)
    os.environ["REPORTS_STORAGE_PATH"]  = str(rpt_dir)
    os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
    yield
    # Cleanup handled automatically by tmp_path_factory


@pytest.fixture(scope="session")
def db_engine(setup_test_env):
    from app.config import get_settings
    get_settings.cache_clear()
    from app.database.database import engine
    from app.database.models import Base
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture
def db_session(db_engine):
    SessionLocal = sessionmaker(bind=db_engine)
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


@pytest.fixture(scope="session")
def client(db_engine):
    from app.config import get_settings
    get_settings.cache_clear()
    from app.main import app
    from app.database.database import get_db, SessionLocal
    from app.database.models import Base
    Base.metadata.create_all(bind=db_engine)

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, follow_redirects=False) as c:
        yield c


@pytest.fixture(scope="session")
def admin_user(db_engine):
    """Create a single admin user for the session."""
    from sqlalchemy.orm import sessionmaker
    from app.database.models import User, UserRole, gen_uuid
    from app.auth import hash_password

    SessionLocal = sessionmaker(bind=db_engine)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "test_admin").first()
        if not user:
            user = User(
                id=gen_uuid(),
                username="test_admin",
                email="admin@test.local",
                full_name="Test Admin",
                hashed_password=hash_password("TestPass123!"),
                role=UserRole.ADMIN,
                organization="Test Lab",
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        return {"id": user.id, "username": user.username}
    finally:
        db.close()


@pytest.fixture(scope="session")
def sample_case(db_engine, admin_user):
    from sqlalchemy.orm import sessionmaker
    from app.database.models import Case, CaseStatus, gen_uuid

    SessionLocal = sessionmaker(bind=db_engine)
    db = SessionLocal()
    try:
        case = db.query(Case).filter(Case.case_id == "TEST-2026-001").first()
        if not case:
            case = Case(
                id=gen_uuid(),
                case_id="TEST-2026-001",
                name="Test Investigation",
                description="Automated test case",
                investigator_id=admin_user["id"],
                status=CaseStatus.OPEN,
            )
            db.add(case)
            db.commit()
            db.refresh(case)
        return {"id": case.id, "case_id": case.case_id}
    finally:
        db.close()
