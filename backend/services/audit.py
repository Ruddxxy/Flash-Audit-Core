"""
Audit logging service.

Records write operations (login, triage, CRUD) for compliance tracking.
Read operations are not logged to avoid volume issues.
"""

import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditLog

logger = logging.getLogger("flashaudit.audit")


async def log_action(
    db: AsyncSession,
    org_id: int,
    action: str,
    user_id: Optional[int] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[int] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
) -> None:
    """Record an auditable action.

    Args:
        db: Database session (will be committed by the caller)
        org_id: Organization context
        action: Action name (e.g., "login", "triage", "webhook_create")
        user_id: Acting user (null for API key operations)
        resource_type: Type of resource affected (e.g., "finding", "webhook")
        resource_id: ID of the affected resource
        details: Additional context as JSON
        ip_address: Client IP address
    """
    entry = AuditLog(
        org_id=org_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
    )
    db.add(entry)
