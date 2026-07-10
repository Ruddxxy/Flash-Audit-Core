"""
Repository endpoints for the dashboard.

Provides listing and summary views with aggregated finding counts.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func, case
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from dependencies.auth import get_current_user
from models import (
    User,
    Repository,
    Finding,
    FindingStatus,
    RepositoryResponse,
    RepositorySummaryResponse,
    ErrorResponse,
)

logger = logging.getLogger("flashaudit.repositories")

router = APIRouter(prefix="/api/v1/repositories", tags=["Repositories"])


@router.get(
    "",
    response_model=list[RepositoryResponse],
    summary="List repositories with aggregated finding counts",
)
async def list_repositories(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    # Subquery: count findings by status per repo
    active_count = func.count(
        case((Finding.status == FindingStatus.ACTIVE, Finding.id))
    )
    fixed_count = func.count(
        case((Finding.status == FindingStatus.FIXED, Finding.id))
    )
    ignored_count = func.count(
        case(
            (Finding.status.in_([FindingStatus.IGNORED, FindingStatus.FALSE_POSITIVE]), Finding.id)
        )
    )
    total_count = func.count(Finding.id)

    q = (
        select(
            Repository,
            active_count.label("active_findings"),
            fixed_count.label("fixed_findings"),
            ignored_count.label("ignored_findings"),
            total_count.label("total_findings"),
        )
        .outerjoin(Finding, Finding.repo_id == Repository.id)
        .where(Repository.org_id == user.org_id)
        .group_by(Repository.id)
        .order_by(Repository.name)
    )

    results = (await db.execute(q)).all()

    return [
        RepositoryResponse(
            id=repo.id,
            org_id=repo.org_id,
            name=repo.name,
            created_at=repo.created_at,
            active_findings=active or 0,
            fixed_findings=fixed or 0,
            ignored_findings=ignored or 0,
            total_findings=total or 0,
        )
        for repo, active, fixed, ignored, total in results
    ]


@router.get(
    "/{repo_id}/summary",
    response_model=RepositorySummaryResponse,
    responses={404: {"model": ErrorResponse}},
    summary="Get repository breakdown by risk class, rule, and dates",
)
async def get_repository_summary(
    repo_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(Repository)
        .where(Repository.id == repo_id)
        .where(Repository.org_id == user.org_id)
    )
    repo = result.scalar_one_or_none()

    if repo is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")

    # Breakdown by risk_class
    rc_q = (
        select(Finding.risk_class, func.count(Finding.id))
        .where(Finding.repo_id == repo_id)
        .where(Finding.status == FindingStatus.ACTIVE)
        .group_by(Finding.risk_class)
    )
    by_risk_class = {(rc or "unknown"): count for rc, count in (await db.execute(rc_q)).all()}

    # Breakdown by risk_impact
    ri_q = (
        select(Finding.risk_impact, func.count(Finding.id))
        .where(Finding.repo_id == repo_id)
        .where(Finding.status == FindingStatus.ACTIVE)
        .group_by(Finding.risk_impact)
    )
    by_risk_impact = {(ri or "unknown"): count for ri, count in (await db.execute(ri_q)).all()}

    # Breakdown by rule_id
    rule_q = (
        select(Finding.rule_id, func.count(Finding.id))
        .where(Finding.repo_id == repo_id)
        .where(Finding.status == FindingStatus.ACTIVE)
        .group_by(Finding.rule_id)
    )
    by_rule = {(rule or "unknown"): count for rule, count in (await db.execute(rule_q)).all()}

    return RepositorySummaryResponse(
        id=repo.id,
        name=repo.name,
        by_risk_class=by_risk_class,
        by_risk_impact=by_risk_impact,
        by_rule=by_rule,
    )
