"""
FlashAudit Backend - Data Models

Pydantic schemas for API validation and SQLAlchemy models for persistence.
Security: Pydantic models use `extra='forbid'` to reject unknown fields,
preventing accidental storage of raw secret content.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import re

from pydantic import BaseModel, Field, field_validator, ConfigDict
from sqlalchemy import (
    Column,
    String,
    Integer,
    DateTime,
    ForeignKey,
    Index,
    Enum as SQLEnum,
    UniqueConstraint,
    Text,
    Boolean,
    JSON,
)
from sqlalchemy.orm import relationship, DeclarativeBase

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

# Email format validation
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


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
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"
    ROTATED = "rotated"


class UserRole(str, Enum):
    """User roles for dashboard access control."""

    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class PolicyAction(str, Enum):
    """Action to take when a policy condition is met."""

    BLOCK = "block"
    ALERT = "alert"


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
    event_type: EventType = Field(
        ..., alias="status", description="Event type: 'found' or 'removed'"
    )
    secret_hash: str = Field(
        ...,
        alias="fingerprint",
        min_length=64,
        max_length=64,
        description="SHA256 fingerprint of the secret",
    )

    # Optional metadata (only stored for 'found' events)
    rule_id: Optional[str] = Field(
        None,
        max_length=MAX_RULE_ID_LENGTH,
        description="Rule ID that triggered the finding",
    )
    file_path: Optional[str] = Field(
        None,
        alias="file",
        max_length=MAX_FILE_PATH_LENGTH,
        description="File path where secret was found",
    )
    line_number: Optional[int] = Field(
        None, alias="line", ge=0, le=10_000_000, description="Line number in the file"
    )
    risk_class: Optional[str] = Field(
        None, max_length=64, description="Risk classification"
    )
    risk_impact: Optional[str] = Field(
        None, max_length=64, description="Risk impact level"
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
        description=f"List of events (max {MAX_BATCH_SIZE})",
    )

    # Context fields (optional, for logging/attribution)
    org: Optional[str] = Field(None, max_length=MAX_ORG_NAME_LENGTH)
    repo: Optional[str] = Field(None, max_length=MAX_REPO_NAME_LENGTH)


class StateResponse(BaseModel):
    """Response for GET /state endpoint."""

    model_config = ConfigDict(extra="forbid")

    active_hashes: list[str] = Field(
        default_factory=list,
        description="List of active secret hashes for this repository",
    )


class EventResponse(BaseModel):
    """Response for POST /events endpoint."""

    model_config = ConfigDict(extra="forbid")

    processed: int = Field(..., description="Number of events processed")
    new_findings: int = Field(default=0, description="Number of new findings created")
    updated_findings: int = Field(default=0, description="Number of findings updated")
    fixed_findings: int = Field(
        default=0, description="Number of findings marked as fixed"
    )
    policy_violations: list[dict] = Field(
        default_factory=list, description="Policies triggered by findings in this batch"
    )


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


class Base(DeclarativeBase):
    pass


class Organization(Base):
    """
    Organization/Tenant model.

    Security: API keys are stored as SHA256 hashes, never in plaintext.
    """

    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(MAX_ORG_NAME_LENGTH), nullable=False, unique=True)
    api_key_hash = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    is_active = Column(Integer, default=1, nullable=False)  # SQLite boolean

    # Relationships
    repositories = relationship(
        "Repository", back_populates="organization", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_org_api_key_active", "api_key_hash", "is_active"),)


class Repository(Base):
    """Repository within an organization."""

    __tablename__ = "repositories"

    id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name = Column(String(MAX_REPO_NAME_LENGTH), nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    organization = relationship("Organization", back_populates="repositories")
    findings = relationship(
        "Finding", back_populates="repository", cascade="all, delete-orphan"
    )

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
    repo_id = Column(
        Integer, ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False
    )

    # The SHA256 fingerprint - this is the only identifier for the secret
    secret_hash = Column(String(64), nullable=False)

    # Metadata only - NO raw secret content
    rule_id = Column(String(MAX_RULE_ID_LENGTH), nullable=True)
    file_path = Column(Text, nullable=True)  # Text for longer paths
    line_number = Column(Integer, nullable=True)
    risk_class = Column(String(64), nullable=True)
    risk_impact = Column(String(64), nullable=True)

    # Status tracking
    status = Column(
        SQLEnum(FindingStatus), default=FindingStatus.ACTIVE, nullable=False
    )
    first_seen = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_seen = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    fixed_at = Column(DateTime, nullable=True)
    rotated_at = Column(DateTime, nullable=True)

    # Relationships
    repository = relationship("Repository", back_populates="findings")

    __table_args__ = (
        # Unique constraint: one finding per secret_hash per repo
        UniqueConstraint("repo_id", "secret_hash", name="uq_finding_repo_hash"),
        # Index for efficient state queries
        Index("ix_finding_repo_status", "repo_id", "status"),
        Index("ix_finding_hash", "secret_hash"),
    )


class User(Base):
    """
    Dashboard user for web UI access.

    Security: Passwords stored as bcrypt hashes. Sessions are separate tokens.
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    email = Column(String(256), nullable=False, unique=True)
    password_hash = Column(String(128), nullable=False)
    name = Column(String(128), nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.MEMBER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_login = Column(DateTime, nullable=True)

    organization = relationship("Organization", backref="users")
    sessions = relationship(
        "Session", back_populates="user", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_user_org_id", "org_id"),
        Index("ix_user_email", "email"),
    )


class Session(Base):
    """
    Session token for dashboard auth.

    Security: Token stored as SHA256 hash. HttpOnly + Secure + SameSite=Strict cookies.
    """

    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    user = relationship("User", back_populates="sessions")


class Webhook(Base):
    """Webhook configuration for notification delivery.

    Security: `secret` is the shared HMAC key used to sign outgoing payloads.
    Stored as plaintext because HMAC requires the receiver to hold the same key.
    Follows the industry convention used by Stripe, GitHub, and Shopify.
    """

    __tablename__ = "webhooks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    url = Column(String(2048), nullable=False)
    events = Column(JSON, nullable=False, default=list)
    secret = Column(String(256), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    organization = relationship("Organization", backref="webhooks")

    __table_args__ = (Index("ix_webhook_org_id", "org_id"),)


class Policy(Base):
    """Organization policy rule (e.g., block deploy if critical finding)."""

    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name = Column(String(256), nullable=False)
    conditions = Column(JSON, nullable=False, default=dict)
    action = Column(SQLEnum(PolicyAction), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    organization = relationship("Organization", backref="policies")

    __table_args__ = (Index("ix_policy_org_id", "org_id"),)


class FindingHistory(Base):
    """Records metadata changes when a finding is re-scanned with different values."""

    __tablename__ = "finding_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(
        Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    field_name = Column(String(64), nullable=False)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    changed_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (Index("ix_finding_history_finding_id", "finding_id"),)


class AuditLog(Base):
    """Tracks write operations for compliance and security review."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    user_id = Column(Integer, nullable=True)  # null for API key actions
    action = Column(String(64), nullable=False)
    resource_type = Column(String(64), nullable=True)
    resource_id = Column(Integer, nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        Index("ix_audit_org_id", "org_id"),
        Index("ix_audit_created_at", "created_at"),
    )


# =============================================================================
# Dashboard Pydantic Schemas
# =============================================================================


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(..., min_length=3, max_length=256)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        if not EMAIL_PATTERN.match(v):
            raise ValueError("Invalid email format")
        return v.lower()


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(..., min_length=3, max_length=256)
    password: str = Field(..., min_length=8, max_length=128)
    name: str = Field(..., min_length=1, max_length=128)
    role: UserRole = UserRole.MEMBER

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        if not EMAIL_PATTERN.match(v):
            raise ValueError("Invalid email format")
        return v.lower()


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    org_id: int
    email: str
    name: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    repo_id: int
    secret_hash: str
    rule_id: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    risk_class: Optional[str] = None
    risk_impact: Optional[str] = None
    status: FindingStatus
    first_seen: datetime
    last_seen: datetime
    fixed_at: Optional[datetime] = None
    rotated_at: Optional[datetime] = None
    repo_name: Optional[str] = None


class RemediationPlaybook(BaseModel):
    """Remediation playbook for a specific secret type."""

    model_config = ConfigDict(extra="forbid")
    rule_id: str
    provider: str
    blast_radius: str
    steps: list[str]
    console_url: Optional[str] = None
    estimated_minutes: Optional[int] = None
    auto_revocable: bool = False
    vault_alternative: Optional[str] = None
    references: list[str] = Field(default_factory=list)


class FindingTriageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: FindingStatus = Field(
        ..., description="New status: ignored or false_positive"
    )

    @field_validator("status")
    @classmethod
    def validate_triage_status(cls, v: FindingStatus) -> FindingStatus:
        allowed = {
            FindingStatus.IGNORED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACTIVE,
            FindingStatus.ROTATED,
        }
        if v not in allowed:
            raise ValueError(
                f"Triage status must be one of: {[s.value for s in allowed]}"
            )
        return v


class RepositoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    org_id: int
    name: str
    created_at: datetime
    active_findings: int = 0
    fixed_findings: int = 0
    ignored_findings: int = 0
    total_findings: int = 0


class RepositorySummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: int
    name: str
    by_risk_class: dict = Field(default_factory=dict)
    by_risk_impact: dict = Field(default_factory=dict)
    by_rule: dict = Field(default_factory=dict)
    timeline: list = Field(default_factory=list)


class TrendPoint(BaseModel):
    date: str
    new_findings: int = 0
    fixed_findings: int = 0
    total_active: int = 0


class AnalyticsTrendsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trends: list[TrendPoint] = Field(default_factory=list)
    period: str = "day"


class AnalyticsSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total_repositories: int = 0
    total_findings: int = 0
    active_findings: int = 0
    fixed_findings: int = 0
    ignored_findings: int = 0
    by_severity: dict = Field(default_factory=dict)
    avg_mttr_hours: Optional[float] = None
    rotated_findings: int = 0
    avg_rotation_time_hours: Optional[float] = None
    clean_repos: int = 0


class WebhookRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(..., min_length=8, max_length=2048)
    events: list[str] = Field(default_factory=lambda: ["new_finding", "finding_fixed"])
    secret: Optional[str] = Field(
        None,
        min_length=16,
        max_length=256,
        description="HMAC signing secret (min 16 chars). Returned once on creation, never again.",
    )
    is_active: bool = True


class WebhookResponse(BaseModel):
    """Public webhook representation. The `secret` is intentionally excluded."""

    model_config = ConfigDict(from_attributes=True)
    id: int
    org_id: int
    url: str
    events: list
    is_active: bool
    created_at: datetime


class WebhookCreatedResponse(WebhookResponse):
    """Returned only on creation — includes the plaintext secret for one-time reveal."""

    secret: Optional[str] = Field(
        None,
        description="Store this securely — it will not be shown again.",
    )


class PolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1, max_length=256)
    conditions: dict = Field(default_factory=dict)
    action: PolicyAction
    is_active: bool = True


class PolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    org_id: int
    name: str
    conditions: dict
    action: PolicyAction
    is_active: bool
    created_at: datetime


class PaginatedResponse(BaseModel):
    items: list
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# Database Initialization Helper
# =============================================================================


def create_tables(engine):
    """Create all tables in the database."""
    Base.metadata.create_all(engine)
