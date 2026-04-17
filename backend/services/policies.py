"""
Policy evaluation engine.

Evaluates JSON-based conditions against findings and returns triggered actions.
Supports matching on: risk_class, risk_impact, rule_id, status.
Values can be a single string or a list of strings.
"""

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Finding, Policy

logger = logging.getLogger("flashaudit.policies")


async def evaluate_policies(
    db: AsyncSession,
    org_id: int,
    finding: Finding,
) -> list[dict]:
    """Evaluate all active policies against a finding.

    Returns a list of triggered policy actions, e.g.:
        [{"policy_id": 1, "policy_name": "Block criticals", "action": "block"}]
    """
    result = await db.execute(
        select(Policy)
        .where(Policy.org_id == org_id)
        .where(Policy.is_active == True)  # noqa: E712
    )
    policies = result.scalars().all()

    triggered = []
    for policy in policies:
        if _matches_conditions(policy.conditions, finding):
            triggered.append({
                "policy_id": policy.id,
                "policy_name": policy.name,
                "action": policy.action.value,
            })
            logger.info(
                f"Policy triggered: {policy.name} (action={policy.action.value}) "
                f"for finding hash={finding.secret_hash[:12]}..."
            )

    return triggered


def _matches_conditions(conditions: dict[str, Any], finding: Finding) -> bool:
    """Check if a finding matches all conditions in a policy.

    Each key in conditions maps to a Finding attribute.
    Values can be a string (exact match) or list of strings (any-of match).
    Empty conditions dict matches everything.
    """
    if not conditions:
        return True

    for key, expected in conditions.items():
        actual = getattr(finding, key, None)
        if actual is None:
            return False

        actual_str = str(actual.value) if hasattr(actual, "value") else str(actual)

        if isinstance(expected, list):
            if actual_str not in [str(e) for e in expected]:
                return False
        else:
            if actual_str != str(expected):
                return False

    return True
