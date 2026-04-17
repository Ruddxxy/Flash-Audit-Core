"""
Findings endpoints for the dashboard.

Provides paginated, filterable access to findings and triage capability.

Security:
- All queries scoped to user's org_id (IDOR prevention)
- XSS mitigated by React auto-escaping on frontend
"""

import logging
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from dependencies.auth import get_current_user
from models import (
    User,
    Finding,
    FindingStatus,
    Repository,
    FindingResponse,
    FindingTriageRequest,
    RemediationPlaybook,
    PaginatedResponse,
    ErrorResponse,
)
from services.remediation import get_playbook
from services.audit import log_action

logger = logging.getLogger("flashaudit.findings")

router = APIRouter(prefix="/api/v1/findings", tags=["Findings"])


@router.get(
    "",
    response_model=PaginatedResponse,
    summary="List findings with pagination and filters",
)
async def list_findings(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(25, ge=1, le=100, description="Items per page"),
    repo_id: Optional[int] = Query(None, description="Filter by repository ID"),
    status_filter: Optional[FindingStatus] = Query(None, alias="status", description="Filter by status"),
    risk_class: Optional[str] = Query(None, max_length=64, description="Filter by risk class"),
    risk_impact: Optional[str] = Query(None, max_length=64, description="Filter by risk impact"),
    rule_id: Optional[str] = Query(None, max_length=128, description="Filter by rule ID"),
    date_from: Optional[datetime] = Query(None, description="Findings seen after this date"),
    date_to: Optional[datetime] = Query(None, description="Findings seen before this date"),
    search: Optional[str] = Query(None, max_length=256, description="Search rule_id, file_path, secret_hash"),
    sort_by: Optional[str] = Query("last_seen", description="Sort field"),
    sort_order: Optional[str] = Query("desc", pattern="^(asc|desc)$", description="Sort direction"),
):
    # Base query scoped to user's org
    org_repos = select(Repository.id).where(Repository.org_id == user.org_id).scalar_subquery()

    conditions = [Finding.repo_id.in_(org_repos)]

    if repo_id is not None:
        conditions.append(Finding.repo_id == repo_id)
    if status_filter is not None:
        conditions.append(Finding.status == status_filter)
    if risk_class is not None:
        conditions.append(Finding.risk_class == risk_class)
    if risk_impact is not None:
        conditions.append(Finding.risk_impact == risk_impact)
    if rule_id is not None:
        conditions.append(Finding.rule_id == rule_id)
    if date_from is not None:
        conditions.append(Finding.first_seen >= date_from)
    if date_to is not None:
        conditions.append(Finding.first_seen <= date_to)
    if search:
        search_term = f"%{search}%"
        conditions.append(or_(
            Finding.rule_id.ilike(search_term),
            Finding.file_path.ilike(search_term),
            Finding.secret_hash.ilike(search_term),
        ))

    where_clause = and_(*conditions)

    # Count total
    count_q = select(func.count(Finding.id)).where(where_clause)
    total = (await db.execute(count_q)).scalar() or 0

    # Resolve sort column
    sort_columns = {
        "last_seen": Finding.last_seen,
        "first_seen": Finding.first_seen,
        "rule_id": Finding.rule_id,
        "risk_impact": Finding.risk_impact,
        "status": Finding.status,
    }
    sort_col = sort_columns.get(sort_by, Finding.last_seen)
    order = sort_col.asc() if sort_order == "asc" else sort_col.desc()

    # Fetch page
    offset = (page - 1) * page_size
    items_q = (
        select(Finding, Repository.name.label("repo_name"))
        .join(Repository, Finding.repo_id == Repository.id)
        .where(where_clause)
        .order_by(order)
        .offset(offset)
        .limit(page_size)
    )
    results = (await db.execute(items_q)).all()

    items = []
    for finding, repo_name in results:
        resp = FindingResponse.model_validate(finding)
        resp.repo_name = repo_name
        items.append(resp.model_dump())

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, math.ceil(total / page_size)),
    )


@router.get(
    "/{finding_id}/remediation",
    response_model=RemediationPlaybook,
    responses={404: {"model": ErrorResponse}},
    summary="Get remediation playbook for a finding",
)
async def get_finding_remediation(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    org_repos = select(Repository.id).where(Repository.org_id == user.org_id).scalar_subquery()

    result = await db.execute(
        select(Finding)
        .where(Finding.id == finding_id)
        .where(Finding.repo_id.in_(org_repos))
    )
    finding = result.scalar_one_or_none()

    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    if not finding.rule_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No remediation playbook available — finding has no rule_id",
        )

    playbook = get_playbook(finding.rule_id)
    if playbook is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No remediation playbook available for rule: {finding.rule_id}",
        )

    return playbook


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    responses={404: {"model": ErrorResponse}},
    summary="Get finding detail",
)
async def get_finding(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    org_repos = select(Repository.id).where(Repository.org_id == user.org_id).scalar_subquery()

    result = await db.execute(
        select(Finding, Repository.name.label("repo_name"))
        .join(Repository, Finding.repo_id == Repository.id)
        .where(Finding.id == finding_id)
        .where(Finding.repo_id.in_(org_repos))
    )
    row = result.one_or_none()

    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    finding, repo_name = row
    resp = FindingResponse.model_validate(finding)
    resp.repo_name = repo_name
    return resp


@router.patch(
    "/{finding_id}",
    response_model=FindingResponse,
    responses={404: {"model": ErrorResponse}},
    summary="Triage a finding (mark as ignored/false_positive/active)",
)
async def triage_finding(
    finding_id: int,
    body: FindingTriageRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    org_repos = select(Repository.id).where(Repository.org_id == user.org_id).scalar_subquery()

    result = await db.execute(
        select(Finding)
        .where(Finding.id == finding_id)
        .where(Finding.repo_id.in_(org_repos))
    )
    finding = result.scalar_one_or_none()

    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    old_status = finding.status.value
    finding.status = body.status

    # Write-once: set rotated_at on first ROTATED transition only
    if body.status == FindingStatus.ROTATED and finding.rotated_at is None:
        finding.rotated_at = datetime.now(timezone.utc)

    await log_action(
        db, org_id=user.org_id, action="triage", user_id=user.id,
        resource_type="finding", resource_id=finding_id,
        details={"from": old_status, "to": body.status.value},
    )

    await db.commit()
    await db.refresh(finding)

    logger.info(f"Finding {finding_id} triaged to {body.status.value} by {user.email}")

    return FindingResponse.model_validate(finding)
