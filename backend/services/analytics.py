"""
Analytics service — time-series aggregation and summary statistics.

All queries scoped to org_id for tenant isolation.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, func, and_, extract
from sqlalchemy.ext.asyncio import AsyncSession

from models import (
    Repository,
    Finding,
    FindingStatus,
    TrendPoint,
    AnalyticsTrendsResponse,
    AnalyticsSummaryResponse,
)


async def compute_trends(
    db: AsyncSession,
    org_id: int,
    period: str = "day",
    days: int = 30,
    repo_id: Optional[int] = None,
) -> AnalyticsTrendsResponse:
    """
    Compute time-series data: new findings, fixed findings, total active per period.

    Time complexity: O(n) where n = number of findings in the date range.
    Space complexity: O(d) where d = number of date buckets.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    org_repos = select(Repository.id).where(Repository.org_id == org_id).scalar_subquery()

    conditions = [Finding.repo_id.in_(org_repos)]
    if repo_id is not None:
        conditions.append(Finding.repo_id == repo_id)

    # Fetch all findings within the window
    q = (
        select(Finding)
        .where(and_(*conditions))
        .where(
            (Finding.first_seen >= cutoff) | (Finding.fixed_at >= cutoff) | (Finding.status == FindingStatus.ACTIVE)
        )
    )
    results = (await db.execute(q)).scalars().all()

    # Build date buckets
    buckets: dict[str, dict] = {}
    current = cutoff.date()
    end = datetime.now(timezone.utc).date()

    while current <= end:
        if period == "day":
            key = current.isoformat()
            current += timedelta(days=1)
        elif period == "week":
            key = current.isoformat()
            current += timedelta(weeks=1)
        elif period == "month":
            key = current.strftime("%Y-%m-01")
            if current.month == 12:
                current = current.replace(year=current.year + 1, month=1, day=1)
            else:
                current = current.replace(month=current.month + 1, day=1)
        else:
            key = current.isoformat()
            current += timedelta(days=1)

        buckets[key] = {"new_findings": 0, "fixed_findings": 0, "total_active": 0}

    # Populate buckets
    for finding in results:
        first_key = _date_to_bucket_key(finding.first_seen, period)
        if first_key in buckets:
            buckets[first_key]["new_findings"] += 1

        if finding.fixed_at:
            fixed_key = _date_to_bucket_key(finding.fixed_at, period)
            if fixed_key in buckets:
                buckets[fixed_key]["fixed_findings"] += 1

    # Compute running total_active
    running_active = 0
    # Count pre-existing active before cutoff
    for finding in results:
        if finding.first_seen < cutoff and finding.status == FindingStatus.ACTIVE:
            running_active += 1

    sorted_keys = sorted(buckets.keys())
    for key in sorted_keys:
        running_active += buckets[key]["new_findings"]
        running_active -= buckets[key]["fixed_findings"]
        buckets[key]["total_active"] = max(0, running_active)

    trends = [
        TrendPoint(
            date=key,
            new_findings=buckets[key]["new_findings"],
            fixed_findings=buckets[key]["fixed_findings"],
            total_active=buckets[key]["total_active"],
        )
        for key in sorted_keys
    ]

    return AnalyticsTrendsResponse(trends=trends, period=period)


def _date_to_bucket_key(dt: datetime, period: str) -> str:
    if period == "day":
        return dt.date().isoformat()
    elif period == "week":
        # Start of ISO week
        start = dt.date() - timedelta(days=dt.weekday())
        return start.isoformat()
    elif period == "month":
        return dt.strftime("%Y-%m-01")
    return dt.date().isoformat()


async def compute_summary(
    db: AsyncSession,
    org_id: int,
) -> AnalyticsSummaryResponse:
    """
    Compute org-wide summary statistics.

    Time complexity: O(1) — aggregate queries.
    """
    org_repos = select(Repository.id).where(Repository.org_id == org_id).scalar_subquery()

    # Total repositories
    repo_count = (await db.execute(
        select(func.count(Repository.id)).where(Repository.org_id == org_id)
    )).scalar() or 0

    # Finding counts by status
    status_counts = (await db.execute(
        select(Finding.status, func.count(Finding.id))
        .where(Finding.repo_id.in_(org_repos))
        .group_by(Finding.status)
    )).all()

    counts = {s.value: c for s, c in status_counts}
    active = counts.get("active", 0)
    fixed = counts.get("fixed", 0)
    ignored = counts.get("ignored", 0) + counts.get("false_positive", 0)
    rotated = counts.get("rotated", 0)
    total = sum(counts.values())

    # By severity (risk_impact)
    severity_q = (await db.execute(
        select(Finding.risk_impact, func.count(Finding.id))
        .where(Finding.repo_id.in_(org_repos))
        .where(Finding.status == FindingStatus.ACTIVE)
        .group_by(Finding.risk_impact)
    )).all()
    by_severity = {(s or "unknown"): c for s, c in severity_q}

    # Average MTTR (Mean Time To Remediate) in hours
    mttr_q = (await db.execute(
        select(
            func.avg(
                extract("epoch", Finding.fixed_at) - extract("epoch", Finding.first_seen)
            )
        )
        .where(Finding.repo_id.in_(org_repos))
        .where(Finding.status == FindingStatus.FIXED)
        .where(Finding.fixed_at.isnot(None))
    )).scalar()

    avg_mttr_hours = round(mttr_q / 3600, 1) if mttr_q else None

    # Average rotation time (time from first_seen to rotated_at) in hours
    rotation_q = (await db.execute(
        select(
            func.avg(
                extract("epoch", Finding.rotated_at) - extract("epoch", Finding.first_seen)
            )
        )
        .where(Finding.repo_id.in_(org_repos))
        .where(Finding.status == FindingStatus.ROTATED)
        .where(Finding.rotated_at.isnot(None))
    )).scalar()

    avg_rotation_time_hours = round(rotation_q / 3600, 1) if rotation_q else None

    # Clean repos (repos with zero active findings)
    repos_with_active = (await db.execute(
        select(func.count(func.distinct(Finding.repo_id)))
        .where(Finding.repo_id.in_(org_repos))
        .where(Finding.status == FindingStatus.ACTIVE)
    )).scalar() or 0
    clean_repos = max(0, repo_count - repos_with_active)

    return AnalyticsSummaryResponse(
        total_repositories=repo_count,
        total_findings=total,
        active_findings=active,
        fixed_findings=fixed,
        ignored_findings=ignored,
        by_severity=by_severity,
        avg_mttr_hours=avg_mttr_hours,
        rotated_findings=rotated,
        avg_rotation_time_hours=avg_rotation_time_hours,
        clean_repos=clean_repos,
    )
