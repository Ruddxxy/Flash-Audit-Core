"""
Analytics endpoints for the dashboard.

Provides trend data, summary stats, and MTTR calculations.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from dependencies.auth import get_current_user
from models import User, AnalyticsTrendsResponse, AnalyticsSummaryResponse
from services.analytics import compute_trends, compute_summary

logger = logging.getLogger("flashaudit.analytics")

router = APIRouter(prefix="/api/v1/analytics", tags=["Analytics"])


@router.get(
    "/trends",
    response_model=AnalyticsTrendsResponse,
    summary="Get time-series trend data for findings",
)
async def get_trends(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
    period: str = Query("day", pattern="^(day|week|month)$", description="Aggregation period"),
    days: int = Query(30, ge=7, le=365, description="Number of days to look back"),
    repo_id: Optional[int] = Query(None, description="Filter by repository ID"),
):
    return await compute_trends(db, user.org_id, period, days, repo_id)


@router.get(
    "/summary",
    response_model=AnalyticsSummaryResponse,
    summary="Get org-wide summary statistics",
)
async def get_summary(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    return await compute_summary(db, user.org_id)
