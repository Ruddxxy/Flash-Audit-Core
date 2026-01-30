"""
FlashAudit Backend - Data Models

Pydantic schemas for API validation and SQLAlchemy models for persistence.
Security: Pydantic models use `extra='forbid'` to reject unknown fields,
preventing accidental storage of raw secret content.
"""

from datetime import datetime
from enum import Enum
from typing import Annotated, Optional
import re

from pydantic import BaseModel, Field, field_validator, ConfigDict
from sqlalchemy import (
    Column, String, Integer, DateTime, ForeignKey, Index, Enum as SQLEnum,
    UniqueConstraint, Text
)
from sqlalchemy.orm import relationship, declarative_base

# =============================================================================
# Constants & Validators
# =============================================================================

# SHA256 hex string: exactly 64 lowercase hex characters
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")

# Maximum batch size for POST /events to prevent DoS
MAX_BATCH_SIZE = 50

# Maximum string lengths to prevent memory exhaustion
MAX_FILE_PATH_LENGTH = 1024
MAX_RULE_ID_LENGTH = 128
MAX_ORG_NAME_LENGTH = 128
MAX_REPO_NAME_LENGTH = 256


def validate_sha256(value: str) -> str:
    """Validate that a string is a valid SHA256 hex digest."""
    if not SHA256_PATTERN.match(value):
        raise ValueError("Must be a valid SHA256 hex string (64 lowercase hex chars)")
    return value


# =============================================================================
# Enums
# =============================================================================

class FindingStatus(str, Enum):
    """Status of a finding in the system."""
    ACTIVE = "active"
    FIXED = "fixed"


class EventType(str, Enum):
    """Type of event from the CLI scanner."""
    FOUND = "found"
    REMOVED = "removed"


# =============================================================================
# Pydantic Schemas (API Layer)
# =============================================================================

class EventPayload(BaseModel):
    """
    Single event from the CLI scanner.

    Security: Uses `extra='forbid'` to reject any fields not explicitly defined.
    This prevents accidental ingestion of raw secret content.
    """
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    # Required fields
    event_type: EventType = Field(..., alias="status", description="Event type: 'found' or 'removed'")
    secret_hash: str = Field(
        ...,
        alias="fingerprint",
        min_length=64,
        max_length=64,
        description="SHA256 fingerprint of the secret"
    )

    # Optional metadata (only stored for 'found' events)
    rule_id: Optional[str] = Field(
        None,
        max_length=MAX_RULE_ID_LENGTH,
        description="Rule ID that triggered the finding"
    )
    file_path: Optional[str] = Field(
        None,
        alias="file",
        max_length=MAX_FILE_PATH_LENGTH,
        description="File path where secret was found"
    )
    line_number: Optional[int] = Field(
        None,
        alias="line",
        ge=0,
        le=10_000_000,
        description="Line number in the file"
    )
    risk_class: Optional[str] = Field(
        None,
        max_length=64,
        description="Risk classification"
    )
    risk_impact: Optional[str] = Field(
        None,
        max_length=64,
        description="Risk impact level"
    )

    @field_validator("secret_hash")
    @classmethod
    def validate_secret_hash(cls, v: str) -> str:
        """Ensure secret_hash is a valid SHA256 hex string."""
        return validate_sha256(v.lower())

    @field_validator("file_path")
    @classmethod
    def sanitize_file_path(cls, v: Optional[str]) -> Optional[str]:
        """Sanitize file path to prevent path traversal in logs/displays."""
        if v is None:
            return None
        # Remove null bytes and control characters
        sanitized = "".join(c for c in v if c.isprintable() and c != "\x00")
        return sanitized[:MAX_FILE_PATH_LENGTH]


class EventBatch(BaseModel):
    """
    Batch of events from the CLI scanner.

    Security: Enforces maximum batch size to prevent DoS attacks.
    """
    model_config = ConfigDict(extra="forbid")

    events: list[EventPayload] = Field(
        ...,
        min_length=1,
        max_length=MAX_BATCH_SIZE,
        description=f"List of events (max {MAX_BATCH_SIZE})"
    )

    # Context fields (optional, for logging/attribution)
    org: Optional[str] = Field(None, max_length=MAX_ORG_NAME_LENGTH)
    repo: Optional[str] = Field(None, max_length=MAX_REPO_NAME_LENGTH)


class StateResponse(BaseModel):
    """Response for GET /state endpoint."""
    model_config = ConfigDict(extra="forbid")

    active_hashes: list[str] = Field(
        default_factory=list,
        description="List of active secret hashes for this repository"
    )


class EventResponse(BaseModel):
    """Response for POST /events endpoint."""
    model_config = ConfigDict(extra="forbid")

    processed: int = Field(..., description="Number of events processed")
    new_findings: int = Field(default=0, description="Number of new findings created")
    updated_findings: int = Field(default=0, description="Number of findings updated")
    fixed_findings: int = Field(default=0, description="Number of findings marked as fixed")


class ErrorResponse(BaseModel):
    """Standard error response."""
    model_config = ConfigDict(extra="forbid")

    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Additional error details")


class HealthResponse(BaseModel):
    """Health check response."""
    model_config = ConfigDict(extra="forbid")

    status: str = "healthy"
    version: str = "1.0.0"


# =============================================================================
# SQLAlchemy Models (Database Layer)
# =============================================================================

Base = declarative_base()


class Organization(Base):
    """
    Organization/Tenant model.

    Security: API keys are stored as SHA256 hashes, never in plaintext.
    """
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(MAX_ORG_NAME_LENGTH), nullable=False, unique=True)
    api_key_hash = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_active = Column(Integer, default=1, nullable=False)  # SQLite boolean

    # Relationships
    repositories = relationship("Repository", back_populates="organization", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_org_api_key_active", "api_key_hash", "is_active"),
    )


class Repository(Base):
    """Repository within an organization."""
    __tablename__ = "repositories"

    id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(MAX_REPO_NAME_LENGTH), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    organization = relationship("Organization", back_populates="repositories")
    findings = relationship("Finding", back_populates="repository", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_repo_org_name"),
        Index("ix_repo_org_id", "org_id"),
    )


class Finding(Base):
    """
    Secret finding record.

    Security: Only stores metadata (hash, rule_id, file path, line number).
    Raw secret content is NEVER stored.
    """
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    repo_id = Column(Integer, ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False)

    # The SHA256 fingerprint - this is the only identifier for the secret
    secret_hash = Column(String(64), nullable=False)

    # Metadata only - NO raw secret content
    rule_id = Column(String(MAX_RULE_ID_LENGTH), nullable=True)
    file_path = Column(Text, nullable=True)  # Text for longer paths
    line_number = Column(Integer, nullable=True)
    risk_class = Column(String(64), nullable=True)
    risk_impact = Column(String(64), nullable=True)

    # Status tracking
    status = Column(SQLEnum(FindingStatus), default=FindingStatus.ACTIVE, nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    fixed_at = Column(DateTime, nullable=True)

    # Relationships
    repository = relationship("Repository", back_populates="findings")

    __table_args__ = (
        # Unique constraint: one finding per secret_hash per repo
        UniqueConstraint("repo_id", "secret_hash", name="uq_finding_repo_hash"),
        # Index for efficient state queries
        Index("ix_finding_repo_status", "repo_id", "status"),
        Index("ix_finding_hash", "secret_hash"),
    )


# =============================================================================
# Database Initialization Helper
# =============================================================================

def create_tables(engine):
    """Create all tables in the database."""
    Base.metadata.create_all(engine)
