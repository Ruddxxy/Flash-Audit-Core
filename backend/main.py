"""
FlashAudit Backend - FastAPI Application

Security-hardened API for ingesting scan findings and syncing state.
Implements authentication, rate limiting, and strict input validation.
"""

import hashlib
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Optional

from fastapi import (
    FastAPI,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.sqlite import insert as sqlite_upsert
from sqlalchemy.dialects.postgresql import insert as pg_upsert

from database import get_session, init_db, close_db, DATABASE_URL
from models import (
    Organization,
    Repository,
    Finding,
    FindingStatus,
    EventType,
    EventBatch,
    EventPayload,
    StateResponse,
    EventResponse,
    ErrorResponse,
    HealthResponse,
    MAX_BATCH_SIZE,
)

# =============================================================================
# Configuration
# =============================================================================

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("flashaudit")


# =============================================================================
# Rate Limiting (In-Memory Stub - Use Redis in Production)
# =============================================================================

class RateLimiter:
    """
    Simple in-memory rate limiter.

    Production: Replace with Redis-based implementation for distributed systems.
    """

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = {}

    def is_allowed(self, key: str) -> bool:
        """Check if a request is allowed under the rate limit."""
        now = time.time()
        window_start = now - self.window_seconds

        # Get existing timestamps for this key
        timestamps = self._requests.get(key, [])

        # Filter to only timestamps within the window
        valid_timestamps = [ts for ts in timestamps if ts > window_start]

        # Check if under limit
        if len(valid_timestamps) >= self.max_requests:
            return False

        # Record this request
        valid_timestamps.append(now)
        self._requests[key] = valid_timestamps

        return True

    def get_retry_after(self, key: str) -> int:
        """Get seconds until rate limit resets."""
        timestamps = self._requests.get(key, [])
        if not timestamps:
            return 0

        oldest = min(timestamps)
        retry_after = int(self.window_seconds - (time.time() - oldest))
        return max(0, retry_after)


# Global rate limiter instance
rate_limiter = RateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)


# =============================================================================
# Authentication
# =============================================================================

def hash_api_key(api_key: str) -> str:
    """
    Hash an API key using SHA256.

    Security: API keys are never stored in plaintext.
    """
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


async def verify_api_key(
    x_api_key: Annotated[str | None, Header(description="API Key for authentication")] = None,
    authorization: Annotated[str | None, Header(description="Bearer token authentication")] = None,
    session: AsyncSession = Depends(get_session),
) -> Organization:
    """
    Dependency to verify API key and return the associated organization.

    Supports both X-API-Key header and Authorization: Bearer token.

    Security:
    - Uses constant-time comparison via secrets.compare_digest to prevent timing attacks
    - Hashes the provided key before comparison
    - Returns 401 with generic message to prevent enumeration
    """
    # Extract API key from either header format
    api_key: Optional[str] = None

    if x_api_key:
        api_key = x_api_key
    elif authorization:
        # Support "Bearer <token>" format
        if authorization.lower().startswith("bearer "):
            api_key = authorization[7:].strip()
        else:
            api_key = authorization.strip()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "X-API-Key"},
        )

    # Hash the provided API key
    provided_hash = hash_api_key(api_key)

    # Query for active organizations
    result = await session.execute(
        select(Organization).where(Organization.is_active == 1)
    )
    organizations = result.scalars().all()

    # Constant-time comparison against all org hashes
    # This prevents timing attacks by always comparing against all hashes
    matched_org: Optional[Organization] = None
    for org in organizations:
        # SECURITY: Use constant-time comparison to prevent timing attacks
        if secrets.compare_digest(provided_hash, org.api_key_hash):
            matched_org = org
            # Don't break early - continue comparing to maintain constant time

    if matched_org is None:
        logger.warning("Invalid API key attempt")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "X-API-Key"},
        )

    return matched_org


# =============================================================================
# Rate Limiting Middleware
# =============================================================================

async def check_rate_limit(
    request: Request,
    org: Organization = Depends(verify_api_key),
) -> Organization:
    """
    Dependency to check rate limits after authentication.

    Returns 429 Too Many Requests if limit exceeded.
    """
    rate_key = f"org:{org.id}"

    if not rate_limiter.is_allowed(rate_key):
        retry_after = rate_limiter.get_retry_after(rate_key)
        logger.warning(f"Rate limit exceeded for org {org.id}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )

    return org


# =============================================================================
# Application Lifecycle
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # Startup
    logger.info("Starting FlashAudit Backend...")
    await init_db()
    logger.info("Database initialized")
    yield
    # Shutdown
    logger.info("Shutting down FlashAudit Backend...")
    await close_db()


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="FlashAudit Backend",
    description="Security-hardened API for secrets scanning findings",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if os.getenv("ENABLE_DOCS", "true").lower() == "true" else None,
    redoc_url="/redoc" if os.getenv("ENABLE_DOCS", "true").lower() == "true" else None,
)

# CORS configuration (restrict in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Authorization", "Content-Type"],
)


# =============================================================================
# Exception Handlers
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler with consistent error format."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error=exc.detail).model_dump(),
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Catch-all exception handler to prevent information leakage."""
    logger.exception("Unhandled exception")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(error="Internal server error").model_dump(),
    )


# =============================================================================
# Health Check (No Auth)
# =============================================================================

@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Health check endpoint",
)
async def health_check():
    """Health check endpoint for load balancers and monitoring."""
    return HealthResponse()


# =============================================================================
# API Routes
# =============================================================================

@app.get(
    "/api/v1/state",
    response_model=StateResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid API key"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
    },
    tags=["State"],
    summary="Get active secret hashes for a repository",
)
async def get_state(
    repo: Annotated[str, Query(
        description="Repository in format 'org/repo'",
        min_length=3,
        max_length=256,
        pattern=r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$"
    )],
    org: Organization = Depends(check_rate_limit),
    session: AsyncSession = Depends(get_session),
):
    """
    Get all active (non-fixed) secret hashes for a repository.

    Used by the CLI to determine which secrets are new vs known.
    """
    # Parse repo name from query
    repo_name = repo.strip()

    # Find or create repository
    repository = await _get_or_create_repo(session, org.id, repo_name)

    # Query active findings
    result = await session.execute(
        select(Finding.secret_hash)
        .where(Finding.repo_id == repository.id)
        .where(Finding.status == FindingStatus.ACTIVE)
    )

    hashes = [row[0] for row in result.fetchall()]

    logger.info(f"State query: org={org.name}, repo={repo_name}, active_hashes={len(hashes)}")

    return StateResponse(active_hashes=hashes)


@app.post(
    "/api/v1/events",
    response_model=EventResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request"},
        401: {"model": ErrorResponse, "description": "Invalid API key"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
    },
    tags=["Events"],
    summary="Ingest scan events",
)
async def post_events(
    batch: EventBatch,
    org: Organization = Depends(check_rate_limit),
    session: AsyncSession = Depends(get_session),
):
    """
    Ingest a batch of scan events (found/removed secrets).

    Security:
    - Maximum batch size enforced (50 events)
    - Only metadata is stored, never raw secret content
    - Pydantic validation rejects unknown fields
    """
    # Determine repository from batch context or default
    repo_name = batch.repo or f"{org.name}/default"

    # Find or create repository
    repository = await _get_or_create_repo(session, org.id, repo_name)

    # Process events
    new_count = 0
    updated_count = 0
    fixed_count = 0

    for event in batch.events:
        if event.event_type == EventType.FOUND:
            is_new = await _upsert_finding(session, repository.id, event)
            if is_new:
                new_count += 1
            else:
                updated_count += 1

        elif event.event_type == EventType.REMOVED:
            was_fixed = await _mark_finding_fixed(session, repository.id, event.secret_hash)
            if was_fixed:
                fixed_count += 1

    await session.commit()

    logger.info(
        f"Events processed: org={org.name}, repo={repo_name}, "
        f"new={new_count}, updated={updated_count}, fixed={fixed_count}"
    )

    return EventResponse(
        processed=len(batch.events),
        new_findings=new_count,
        updated_findings=updated_count,
        fixed_findings=fixed_count,
    )


# =============================================================================
# Database Helper Functions
# =============================================================================

async def _get_or_create_repo(
    session: AsyncSession,
    org_id: int,
    repo_name: str,
) -> Repository:
    """Get or create a repository for the organization."""
    # Try to find existing
    result = await session.execute(
        select(Repository)
        .where(Repository.org_id == org_id)
        .where(Repository.name == repo_name)
    )
    repository = result.scalar_one_or_none()

    if repository is None:
        # Create new repository
        repository = Repository(org_id=org_id, name=repo_name)
        session.add(repository)
        await session.flush()  # Get the ID
        logger.info(f"Created repository: {repo_name}")

    return repository


async def _upsert_finding(
    session: AsyncSession,
    repo_id: int,
    event: EventPayload,
) -> bool:
    """
    Upsert a finding (create or update).

    Returns True if this was a new finding, False if updated.

    Security: Uses parameterized queries via SQLAlchemy ORM to prevent SQL injection.
    """
    now = datetime.utcnow()

    # Check if finding exists
    result = await session.execute(
        select(Finding)
        .where(Finding.repo_id == repo_id)
        .where(Finding.secret_hash == event.secret_hash)
    )
    existing = result.scalar_one_or_none()

    if existing:
        # Update existing finding
        existing.status = FindingStatus.ACTIVE
        existing.last_seen = now
        existing.fixed_at = None

        # Update metadata if provided
        if event.rule_id is not None:
            existing.rule_id = event.rule_id
        if event.file_path is not None:
            existing.file_path = event.file_path
        if event.line_number is not None:
            existing.line_number = event.line_number
        if event.risk_class is not None:
            existing.risk_class = event.risk_class
        if event.risk_impact is not None:
            existing.risk_impact = event.risk_impact

        return False  # Not new
    else:
        # Create new finding
        finding = Finding(
            repo_id=repo_id,
            secret_hash=event.secret_hash,
            rule_id=event.rule_id,
            file_path=event.file_path,
            line_number=event.line_number,
            risk_class=event.risk_class,
            risk_impact=event.risk_impact,
            status=FindingStatus.ACTIVE,
            first_seen=now,
            last_seen=now,
        )
        session.add(finding)
        return True  # New finding


async def _mark_finding_fixed(
    session: AsyncSession,
    repo_id: int,
    secret_hash: str,
) -> bool:
    """
    Mark a finding as fixed (soft delete).

    Returns True if a finding was updated, False if not found.

    Security: Uses parameterized queries via SQLAlchemy ORM to prevent SQL injection.
    """
    result = await session.execute(
        update(Finding)
        .where(Finding.repo_id == repo_id)
        .where(Finding.secret_hash == secret_hash)
        .where(Finding.status == FindingStatus.ACTIVE)
        .values(status=FindingStatus.FIXED, fixed_at=datetime.utcnow())
    )

    return result.rowcount > 0


# =============================================================================
# Admin Endpoints (Protected, for management)
# =============================================================================

@app.post(
    "/api/v1/admin/organizations",
    tags=["Admin"],
    summary="Create a new organization (requires admin key)",
    include_in_schema=os.getenv("ENABLE_ADMIN_DOCS", "false").lower() == "true",
)
async def create_organization(
    name: str = Query(..., min_length=1, max_length=128),
    admin_key: str = Header(..., alias="X-Admin-Key"),
    session: AsyncSession = Depends(get_session),
):
    """
    Create a new organization and generate an API key.

    Requires X-Admin-Key header matching ADMIN_KEY environment variable.
    """
    expected_admin_key = os.getenv("ADMIN_KEY", "")
    if not expected_admin_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API not configured",
        )

    # Constant-time comparison for admin key
    if not secrets.compare_digest(admin_key, expected_admin_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin key",
        )

    # Generate new API key
    new_api_key = secrets.token_urlsafe(32)
    api_key_hash = hash_api_key(new_api_key)

    # Create organization
    org = Organization(
        name=name,
        api_key_hash=api_key_hash,
    )
    session.add(org)
    await session.commit()

    logger.info(f"Created organization: {name}")

    # Return the plaintext API key (only time it's visible)
    return {
        "id": org.id,
        "name": org.name,
        "api_key": new_api_key,  # Only returned once!
        "message": "Store this API key securely - it cannot be retrieved later",
    }


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "false").lower() == "true",
        log_level=LOG_LEVEL.lower(),
    )
