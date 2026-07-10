"""
Export endpoints for CSV and compliance PDF reports.

Security:
- CSV formula injection: cells starting with =, +, -, @ are prefixed with single quote
- All queries scoped to user's org_id
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from dependencies.auth import get_current_user
from models import User, FindingStatus
from services.exports import generate_findings_csv, generate_compliance_pdf

logger = logging.getLogger("flashaudit.exports")

router = APIRouter(prefix="/api/v1/exports", tags=["Exports"])


class ComplianceReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    framework: str = Field(..., pattern="^(SOC2|PCI-DSS|ISO27001|HIPAA|GENERAL)$")
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    repo_ids: Optional[list[int]] = None


@router.get(
    "/findings.csv",
    summary="Export findings as CSV",
)
async def export_findings_csv(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
    repo_id: Optional[int] = Query(None),
    status_filter: Optional[FindingStatus] = Query(None, alias="status"),
    risk_impact: Optional[str] = Query(None, max_length=64),
):
    csv_stream = await generate_findings_csv(
        db, user.org_id, repo_id=repo_id, status_filter=status_filter, risk_impact=risk_impact
    )

    filename = f"flashaudit_findings_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"

    return StreamingResponse(
        csv_stream,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post(
    "/compliance-report",
    summary="Generate compliance PDF report (SOC2/PCI-DSS/ISO27001/HIPAA)",
)
async def export_compliance_report(
    body: ComplianceReportRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    pdf_bytes = await generate_compliance_pdf(
        db,
        user.org_id,
        framework=body.framework,
        date_from=body.date_from,
        date_to=body.date_to,
        repo_ids=body.repo_ids,
    )

    filename = f"flashaudit_{body.framework.lower()}_report_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"

    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
