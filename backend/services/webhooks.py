"""
Webhook delivery service.

Fires HTTP POST to all active webhooks matching the event type.
Supports HMAC-SHA256 signing when a webhook has a secret configured.
"""

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Webhook

logger = logging.getLogger("flashaudit.webhooks")

WEBHOOK_TIMEOUT = 10  # seconds
SIGNATURE_HEADER = "X-FlashAudit-Signature"


async def dispatch_webhooks(
    db: AsyncSession,
    org_id: int,
    event_type: str,
    payload: dict,
) -> None:
    """Fire HTTP POST to all active webhooks for this org matching the event type.

    Args:
        db: Database session
        org_id: Organization ID
        event_type: One of "new_finding", "finding_fixed"
        payload: Event data to send
    """
    result = await db.execute(
        select(Webhook).where(Webhook.org_id == org_id).where(Webhook.is_active == True)  # noqa: E712
    )
    webhooks = result.scalars().all()

    if not webhooks:
        return

    body = json.dumps(
        {
            "event": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": payload,
        },
        default=str,
    )

    for wh in webhooks:
        if event_type not in (wh.events or []):
            continue
        await _deliver(wh, body)


async def _deliver(webhook: Webhook, body: str) -> None:
    """Deliver payload to a single webhook. Never raises."""
    headers = {"Content-Type": "application/json"}

    if webhook.secret:
        sig = hmac.new(
            webhook.secret.encode(),
            body.encode(),
            hashlib.sha256,
        ).hexdigest()
        headers[SIGNATURE_HEADER] = f"sha256={sig}"

    try:
        async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT) as client:
            resp = await client.post(webhook.url, content=body, headers=headers)
            logger.info(
                f"Webhook delivered: url={webhook.url} status={resp.status_code}"
            )
    except httpx.TimeoutException:
        logger.warning(f"Webhook timeout: url={webhook.url}")
    except Exception:
        logger.exception(f"Webhook delivery failed: url={webhook.url}")
