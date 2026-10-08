"""
Application configuration using pydantic-settings.
Settings are loaded from environment variables / .env file.
"""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Core
    app_name: str = "Digital Forensics Evidence Organizer"
    app_version: str = "1.0.0"
    debug: bool = False

    # Security
    secret_key: str = "change-this-secret-key"
    session_expire_minutes: int = 480

    # Database
    database_url: str = "sqlite:///./storage/forensics.db"

    # Storage
    evidence_storage_path: str = "./storage/evidence"
    reports_storage_path: str = "./storage/reports"

    # Upload limits (2 GB default)
    max_upload_size: int = 2_147_483_648

    # Hashing chunk size (1 MB)
    hash_chunk_size: int = 1_048_576

    @property
    def evidence_storage_dir(self) -> Path:
        p = Path(self.evidence_storage_path)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def reports_storage_dir(self) -> Path:
        p = Path(self.reports_storage_path)
        p.mkdir(parents=True, exist_ok=True)
        return p


@lru_cache()
def get_settings() -> Settings:
    return Settings()
