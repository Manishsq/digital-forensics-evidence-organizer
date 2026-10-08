"""
SQLAlchemy ORM models for the Digital Forensics Evidence Organizer.
All tables use UTC timestamps. Original evidence is never modified.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    BigInteger,
)
from sqlalchemy.orm import DeclarativeBase, relationship
import enum


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def gen_uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    INVESTIGATOR = "INVESTIGATOR"
    REVIEWER = "REVIEWER"


class CaseStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"


class VerificationStatus(str, enum.Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"


class EvidenceCategory(str, enum.Enum):
    DISK_IMAGE = "Disk Image"
    MEMORY_DUMP = "Memory Dump"
    NETWORK_CAPTURE = "Network Capture"
    LOG = "Log"
    DOCUMENT = "Document"
    IMAGE = "Image"
    VIDEO = "Video"
    AUDIO = "Audio"
    ARCHIVE = "Archive"
    MALWARE_SAMPLE = "Malware Sample"
    OTHER = "Other"


class CustodyAction(str, enum.Enum):
    EVIDENCE_IMPORTED = "EVIDENCE_IMPORTED"
    HASH_CALCULATED = "HASH_CALCULATED"
    EVIDENCE_VIEWED = "EVIDENCE_VIEWED"
    EVIDENCE_DOWNLOADED = "EVIDENCE_DOWNLOADED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    EVIDENCE_TRANSFERRED = "EVIDENCE_TRANSFERRED"
    EVIDENCE_EXPORTED = "EVIDENCE_EXPORTED"
    EVIDENCE_UPDATED = "EVIDENCE_UPDATED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    CHAIN_VERIFIED = "CHAIN_VERIFIED"


class AuditAction(str, enum.Enum):
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    CASE_CREATED = "CASE_CREATED"
    CASE_MODIFIED = "CASE_MODIFIED"
    CASE_VIEWED = "CASE_VIEWED"
    EVIDENCE_IMPORTED = "EVIDENCE_IMPORTED"
    EVIDENCE_VIEWED = "EVIDENCE_VIEWED"
    EVIDENCE_DOWNLOADED = "EVIDENCE_DOWNLOADED"
    HASH_VERIFIED = "HASH_VERIFIED"
    REPORT_GENERATED = "REPORT_GENERATED"
    CHAIN_VERIFIED = "CHAIN_VERIFIED"
    ADMIN_OPERATION = "ADMIN_OPERATION"
    USER_CREATED = "USER_CREATED"
    SEARCH_PERFORMED = "SEARCH_PERFORMED"
    TOOL_OUTPUT_IMPORTED = "TOOL_OUTPUT_IMPORTED"


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.INVESTIGATOR)
    organization = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    # Relationships
    cases = relationship("Case", back_populates="investigator_user", foreign_keys="Case.investigator_id")
    evidence_items = relationship("Evidence", back_populates="creator", foreign_keys="Evidence.created_by")
    custody_events = relationship("ChainOfCustody", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")
    reports = relationship("Report", back_populates="generated_by_user")


class Case(Base):
    __tablename__ = "cases"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    case_id = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    investigator_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    organization = Column(String(255), nullable=True)
    status = Column(Enum(CaseStatus), nullable=False, default=CaseStatus.OPEN)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    # Relationships
    investigator_user = relationship("User", back_populates="cases", foreign_keys=[investigator_id])
    evidence_items = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    custody_events = relationship("ChainOfCustody", back_populates="case")
    reports = relationship("Report", back_populates="case")

    __table_args__ = (
        Index("ix_cases_status", "status"),
        Index("ix_cases_created_at", "created_at"),
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    evidence_id = Column(String(64), unique=True, nullable=False, index=True)
    case_id = Column(String(36), ForeignKey("cases.id"), nullable=False, index=True)

    # File identity - original is NEVER modified
    original_filename = Column(String(512), nullable=False)
    stored_filename = Column(String(512), nullable=False)
    storage_path = Column(String(1024), nullable=False)
    file_size = Column(BigInteger, nullable=False, default=0)
    mime_type = Column(String(255), nullable=True)
    file_extension = Column(String(32), nullable=True)

    # Cryptographic hashes — computed immediately at import
    sha256 = Column(String(64), nullable=True, index=True)
    sha512 = Column(String(128), nullable=True, index=True)
    md5 = Column(String(32), nullable=True, index=True)

    # Classification
    evidence_category = Column(Enum(EvidenceCategory), nullable=False, default=EvidenceCategory.OTHER)
    evidence_type = Column(String(128), nullable=True)
    source = Column(String(512), nullable=True)
    device = Column(String(255), nullable=True)
    suspect_reference = Column(String(255), nullable=True)
    acquisition_method = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)

    # Timestamps (all UTC, stored naive)
    acquisition_timestamp = Column(DateTime, nullable=True)
    imported_timestamp = Column(DateTime, default=utcnow, nullable=False, index=True)
    original_created_timestamp = Column(DateTime, nullable=True)
    original_modified_timestamp = Column(DateTime, nullable=True)

    # Integrity
    verification_status = Column(
        Enum(VerificationStatus),
        nullable=False,
        default=VerificationStatus.UNVERIFIED,
    )
    last_verified_at = Column(DateTime, nullable=True)
    last_verified_by = Column(String(36), ForeignKey("users.id"), nullable=True)

    # Authorship
    created_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="evidence_items")
    creator = relationship("User", back_populates="evidence_items", foreign_keys=[created_by])
    verifier = relationship("User", foreign_keys=[last_verified_by])
    metadata_entries = relationship("EvidenceMetadata", back_populates="evidence", cascade="all, delete-orphan")
    custody_events = relationship("ChainOfCustody", back_populates="evidence")
    evidence_tags = relationship("EvidenceTag", back_populates="evidence", cascade="all, delete-orphan")
    tags = relationship("Tag", secondary="evidence_tags", viewonly=True)

    __table_args__ = (
        Index("ix_evidence_sha256", "sha256"),
        Index("ix_evidence_sha512", "sha512"),
        Index("ix_evidence_md5", "md5"),
        Index("ix_evidence_imported_timestamp", "imported_timestamp"),
    )


class EvidenceMetadata(Base):
    __tablename__ = "evidence_metadata"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    evidence_id = Column(String(36), ForeignKey("evidence.id"), nullable=False, index=True)
    key = Column(String(255), nullable=False)
    value = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    evidence = relationship("Evidence", back_populates="metadata_entries")


class Tag(Base):
    __tablename__ = "tags"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    name = Column(String(128), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    evidence_tags = relationship("EvidenceTag", back_populates="tag")


class EvidenceTag(Base):
    __tablename__ = "evidence_tags"

    evidence_id = Column(String(36), ForeignKey("evidence.id"), primary_key=True)
    tag_id = Column(String(36), ForeignKey("tags.id"), primary_key=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    evidence = relationship("Evidence", back_populates="evidence_tags")
    tag = relationship("Tag", back_populates="evidence_tags")


class ChainOfCustody(Base):
    __tablename__ = "chain_of_custody"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    case_id = Column(String(36), ForeignKey("cases.id"), nullable=False, index=True)
    evidence_id = Column(String(36), ForeignKey("evidence.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    action = Column(Enum(CustodyAction), nullable=False)
    description = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=utcnow, nullable=False, index=True)
    source_ip = Column(String(45), nullable=True)
    previous_hash = Column(String(64), nullable=False)
    event_hash = Column(String(64), nullable=False, index=True)

    # Relationships
    case = relationship("Case", back_populates="custody_events")
    evidence = relationship("Evidence", back_populates="custody_events")
    user = relationship("User", back_populates="custody_events")

    __table_args__ = (
        Index("ix_custody_timestamp", "timestamp"),
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    action = Column(Enum(AuditAction), nullable=False, index=True)
    entity_type = Column(String(64), nullable=True)
    entity_id = Column(String(64), nullable=True)
    description = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False, index=True)
    source_ip = Column(String(45), nullable=True)

    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_timestamp", "timestamp"),
        Index("ix_audit_user_id", "user_id"),
    )


class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    report_id = Column(String(64), unique=True, nullable=False, index=True)
    case_id = Column(String(36), ForeignKey("cases.id"), nullable=False, index=True)
    evidence_id = Column(String(36), ForeignKey("evidence.id"), nullable=True)
    title = Column(String(512), nullable=False)
    report_type = Column(String(64), nullable=False, default="CASE_REPORT")
    storage_path = Column(String(1024), nullable=True)
    generated_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    generated_at = Column(DateTime, default=utcnow, nullable=False)
    notes = Column(Text, nullable=True)

    case = relationship("Case", back_populates="reports")
    generated_by_user = relationship("User", back_populates="reports")
