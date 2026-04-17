"""
Remediation playbook service.

Loads per-rule-id rotation/revocation guidance from a YAML knowledge base.
Playbooks are loaded once and cached for O(1) lookups.

Security: Uses yaml.safe_load() exclusively — never yaml.load().
"""

import logging
import os
from functools import lru_cache
from typing import Optional

import yaml

from models import RemediationPlaybook

logger = logging.getLogger("flashaudit.remediation")

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
_PLAYBOOK_PATH = os.path.join(_DATA_DIR, "remediation_playbooks.yaml")


@lru_cache(maxsize=1)
def _load_playbooks() -> dict[str, dict]:
    """Load all playbooks from YAML. Cached after first call."""
    if not os.path.exists(_PLAYBOOK_PATH):
        logger.warning(f"Playbook file not found: {_PLAYBOOK_PATH}")
        return {}

    with open(_PLAYBOOK_PATH, "r") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        logger.error("Playbook file is not a valid YAML mapping")
        return {}

    logger.info(f"Loaded {len(data)} remediation playbooks")
    return data


def get_playbook(rule_id: str) -> Optional[RemediationPlaybook]:
    """
    Get the remediation playbook for a given rule_id.

    Returns None if no playbook exists for this rule_id.
    Time complexity: O(1) — dict lookup on cached data.
    """
    playbooks = _load_playbooks()
    data = playbooks.get(rule_id)
    if data is None:
        return None
    return RemediationPlaybook(rule_id=rule_id, **data)


def get_all_rule_ids() -> list[str]:
    """Return all rule_ids that have playbooks."""
    return list(_load_playbooks().keys())
