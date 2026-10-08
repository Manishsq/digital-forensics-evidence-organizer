"""
Database connection and session management.
"""

from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session

from app.config import get_settings
from app.database.models import Base

settings = get_settings()

# Ensure storage directory exists before creating the engine
db_path_str = settings.database_url.replace("sqlite:///", "")
db_dir = Path(db_path_str).parent
db_dir.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
    echo=settings.debug,
)


# Enable foreign key support for SQLite
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Create all tables."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI dependency that provides a database session."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
