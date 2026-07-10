"""
CLI-facing endpoints — extracted from the original main.py.

These endpoints use API key auth (X-API-Key header) and are consumed
by the Rust CLI scanner. Their behavior is preserved exactly.
"""

import asyncio
import hashlib
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from models import (
    Organization,
    Repository,
    Finding,
    FindingHistory,
    FindingStatus,
    EventType,
    EventBatch,
    EventPayload,
    StateResponse,
    EventResponse,
    ErrorResponse,
)

logger = logging.getLogger("flashaudit.cli")

router = APIRouter(tags=["CLI"])


# =============================================================================
# Authentication (API Key — unchanged)
# =============================================================================


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


async def verify_api_key(
    x_api_key: Annotated[
        str | None, Header(description="API Key for authentication")
    ] = None,
    authorization: Annotated[
        str | None, Header(description="Bearer token authentication")
    ] = None,
    session: AsyncSession = Depends(get_session),
) -> Organization:
    api_key: Optional[str] = None

    if x_api_key:
        api_key = x_api_key
    elif authorization:
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

    provided_hash = hash_api_key(api_key)

    result = await session.execute(
        select(Organization).where(Organization.is_active == 1)
    )
    organizations = result.scalars().all()

    matched_org: Optional[Organization] = None
    for org in organizations:
        if secrets.compare_digest(provided_hash, org.api_key_hash):
            matched_org = org

    if matched_org is None:
        logger.warning("Invalid API key attempt")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "X-API-Key"},
        )

    return matched_org


# =============================================================================
# Rate Limiting (In-Memory — unchanged)
# =============================================================================

from services.rate_limiter import cli_rate_limiter  # noqa: E402  (late import avoids circular dependency)


async def check_rate_limit(
    request: Request,
    org: Organization = Depends(verify_api_key),
) -> Organization:
    rate_key = f"org:{org.id}"

    if not await cli_rate_limiter.is_allowed(rate_key):
        retry_after = await cli_rate_limiter.get_retry_after(rate_key)
        logger.warning(f"Rate limit exceeded for org {org.id}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )

    return org


# =============================================================================
# Endpoints
# =============================================================================


@router.get(
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
    repo: Annotated[
        str,
        Query(
            description="Repository in format 'org/repo'",
            min_length=3,
            max_length=256,
            pattern=r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$",
        ),
    ],
    org: Organization = Depends(check_rate_limit),
    session: AsyncSession = Depends(get_session),
):
    repo_name = repo.strip()
    repository = await _get_or_create_repo(session, org.id, repo_name)

    result = await session.execute(
        select(Finding.secret_hash)
        .where(Finding.repo_id == repository.id)
        .where(Finding.status == FindingStatus.ACTIVE)
    )

    hashes = [row[0] for row in result.fetchall()]

    logger.info(
        f"State query: org={org.name}, repo={repo_name}, active_hashes={len(hashes)}"
    )

    return StateResponse(active_hashes=hashes)


@router.post(
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
    repo_name = batch.repo or f"{org.name}/default"
    repository = await _get_or_create_repo(session, org.id, repo_name)

    new_count = 0
    updated_count = 0
    fixed_count = 0
    upserted_findings: list[Finding] = []

    # Atomic batch: all events succeed or all roll back
    async with session.begin_nested():
        for event in batch.events:
            if event.event_type == EventType.FOUND:
                is_new, finding = await _upsert_finding(session, repository.id, event)
                upserted_findings.append(finding)
                if is_new:
                    new_count += 1
                else:
                    updated_count += 1
            elif event.event_type == EventType.REMOVED:
                was_fixed = await _mark_finding_fixed(
                    session, repository.id, event.secret_hash
                )
                if was_fixed:
                    fixed_count += 1

    # Evaluate policies against new/updated findings
    from services.policies import evaluate_policies

    all_violations: list[dict] = []
    for finding in upserted_findings:
        violations = await evaluate_policies(session, org.id, finding)
        all_violations.extend(violations)

    await session.commit()

    logger.info(
        f"Events processed: org={org.name}, repo={repo_name}, "
        f"new={new_count}, updated={updated_count}, fixed={fixed_count}"
    )

    # Fire-and-forget webhook delivery (non-blocking)
    from services.webhooks import dispatch_webhooks

    if new_count > 0:
        asyncio.create_task(
            dispatch_webhooks(
                session,
                org.id,
                "new_finding",
                {"repo": repo_name, "new_findings": new_count},
            )
        )
    if fixed_count > 0:
        asyncio.create_task(
            dispatch_webhooks(
                session,
                org.id,
                "finding_fixed",
                {"repo": repo_name, "fixed_findings": fixed_count},
            )
        )

    return EventResponse(
        processed=len(batch.events),
        new_findings=new_count,
        updated_findings=updated_count,
        fixed_findings=fixed_count,
        policy_violations=all_violations,
    )


# =============================================================================
# Admin
# =============================================================================


@router.post(
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
    expected_admin_key = os.getenv("ADMIN_KEY", "")
    if not expected_admin_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API not configured",
        )

    if not secrets.compare_digest(admin_key, expected_admin_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin key",
        )

    new_api_key = secrets.token_urlsafe(32)
    api_key_hash = hash_api_key(new_api_key)

    org = Organization(
        name=name,
        api_key_hash=api_key_hash,
    )
    session.add(org)
    await session.commit()

    logger.info(f"Created organization: {name}")

    return {
        "id": org.id,
        "name": org.name,
        "api_key": new_api_key,
        "message": "Store this API key securely - it cannot be retrieved later",
    }


@router.post(
    "/api/v1/admin/organizations/{org_id}/rotate-key",
    tags=["Admin"],
    summary="Rotate an organization's API key",
    include_in_schema=os.getenv("ENABLE_ADMIN_DOCS", "false").lower() == "true",
)
async def rotate_api_key(
    org_id: int,
    admin_key: str = Header(..., alias="X-Admin-Key"),
    session: AsyncSession = Depends(get_session),
):
    expected_admin_key = os.getenv("ADMIN_KEY", "")
    if not expected_admin_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API not configured",
        )

    if not secrets.compare_digest(admin_key, expected_admin_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin key",
        )

    result = await session.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    new_api_key = secrets.token_urlsafe(32)
    org.api_key_hash = hash_api_key(new_api_key)
    await session.commit()

    logger.info(f"API key rotated for org: {org.name}")

    return {
        "id": org.id,
        "name": org.name,
        "api_key": new_api_key,
        "message": "New API key generated. Old key is now invalid.",
    }


# =============================================================================
# DB Helpers
# =============================================================================


async def _get_or_create_repo(
    session: AsyncSession,
    org_id: int,
    repo_name: str,
) -> Repository:
    result = await session.execute(
        select(Repository)
        .where(Repository.org_id == org_id)
        .where(Repository.name == repo_name)
    )
    repository = result.scalar_one_or_none()

    if repository is None:
        repository = Repository(org_id=org_id, name=repo_name)
        session.add(repository)
        await session.flush()
        logger.info(f"Created repository: {repo_name}")

    return repository


async def _upsert_finding(
    session: AsyncSession,
    repo_id: int,
    event: EventPayload,
) -> tuple[bool, Finding]:
    """Upsert a finding. Returns (is_new, finding)."""
    now = datetime.now(timezone.utc)

    result = await session.execute(
        select(Finding)
        .where(Finding.repo_id == repo_id)
        .where(Finding.secret_hash == event.secret_hash)
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.status = FindingStatus.ACTIVE
        existing.last_seen = now
        existing.fixed_at = None

        # Record metadata changes before overwriting
        for field in (
            "rule_id",
            "file_path",
            "line_number",
            "risk_class",
            "risk_impact",
        ):
            new_val = getattr(event, field)
            if new_val is not None:
                old_val = getattr(existing, field)
                if str(old_val) != str(new_val) and old_val is not None:
                    session.add(
                        FindingHistory(
                            finding_id=existing.id,
                            field_name=field,
                            old_value=str(old_val),
                            new_value=str(new_val),
                        )
                    )
                setattr(existing, field, new_val)

        return False, existing
    else:
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
        return True, finding


async def _mark_finding_fixed(
    session: AsyncSession,
    repo_id: int,
    secret_hash: str,
) -> bool:
    result = await session.execute(
        update(Finding)
        .where(Finding.repo_id == repo_id)
        .where(Finding.secret_hash == secret_hash)
        .where(Finding.status == FindingStatus.ACTIVE)
        .values(status=FindingStatus.FIXED, fixed_at=datetime.now(timezone.utc))
    )
    return result.rowcount > 0
