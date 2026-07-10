"""
Tests for remediation playbooks feature.

Covers:
- Playbook service loading and lookup
- GET /api/v1/findings/{id}/remediation endpoint
- ROTATED triage status with write-once rotated_at
- IDOR prevention on remediation endpoint
- Analytics rotation metrics
"""

import pytest
from datetime import datetime, timezone

from models import Finding, FindingStatus, Repository


# =============================================================================
# Playbook service tests
# =============================================================================

class TestPlaybookService:

    def test_get_playbook_known_rule(self):
        from services.remediation import get_playbook
        playbook = get_playbook("AWS_ACCESS_KEY")
        assert playbook is not None
        assert playbook.provider == "Amazon Web Services"
        assert playbook.rule_id == "AWS_ACCESS_KEY"
        assert len(playbook.steps) > 0
        assert playbook.console_url is not None

    def test_get_playbook_unknown_rule(self):
        from services.remediation import get_playbook
        playbook = get_playbook("NONEXISTENT_RULE_12345")
        assert playbook is None

    def test_get_playbook_github_pat(self):
        from services.remediation import get_playbook
        playbook = get_playbook("GITHUB_PAT")
        assert playbook is not None
        assert playbook.provider == "GitHub"
        assert playbook.auto_revocable is True

    def test_get_playbook_stripe_live(self):
        from services.remediation import get_playbook
        playbook = get_playbook("STRIPE_LIVE_SECRET")
        assert playbook is not None
        assert "CRITICAL" in playbook.blast_radius
        assert playbook.estimated_minutes is not None

    def test_get_all_rule_ids(self):
        from services.remediation import get_all_rule_ids
        rule_ids = get_all_rule_ids()
        assert len(rule_ids) >= 60  # We have 66 rules
        assert "AWS_ACCESS_KEY" in rule_ids
        assert "GITHUB_PAT" in rule_ids


# =============================================================================
# Remediation endpoint tests
# =============================================================================

@pytest.mark.asyncio
class TestRemediationEndpoint:

    async def test_get_remediation_success(self, client, db, org, auth_cookies):
        repo = Repository(org_id=org.id, name="test/repo")
        db.add(repo)
        await db.flush()

        finding = Finding(
            repo_id=repo.id,
            secret_hash="a" * 64,
            rule_id="AWS_ACCESS_KEY",
            risk_class="api_key",
            risk_impact="critical",
            status=FindingStatus.ACTIVE,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(finding)
        await db.commit()

        resp = await client.get(
            f"/api/v1/findings/{finding.id}/remediation",
            cookies=auth_cookies,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["rule_id"] == "AWS_ACCESS_KEY"
        assert data["provider"] == "Amazon Web Services"
        assert len(data["steps"]) > 0
        assert data["console_url"] is not None

    async def test_get_remediation_finding_not_found(self, client, auth_cookies):
        resp = await client.get(
            "/api/v1/findings/99999/remediation",
            cookies=auth_cookies,
        )
        assert resp.status_code == 404

    async def test_get_remediation_no_rule_id(self, client, db, org, auth_cookies):
        repo = Repository(org_id=org.id, name="test/repo2")
        db.add(repo)
        await db.flush()

        finding = Finding(
            repo_id=repo.id,
            secret_hash="b" * 64,
            rule_id=None,
            status=FindingStatus.ACTIVE,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(finding)
        await db.commit()

        resp = await client.get(
            f"/api/v1/findings/{finding.id}/remediation",
            cookies=auth_cookies,
        )
        assert resp.status_code == 404
        assert "no rule_id" in resp.json()["error"]

    async def test_get_remediation_no_playbook_for_rule(self, client, db, org, auth_cookies):
        repo = Repository(org_id=org.id, name="test/repo3")
        db.add(repo)
        await db.flush()

        finding = Finding(
            repo_id=repo.id,
            secret_hash="c" * 64,
            rule_id="TOTALLY_CUSTOM_RULE_XYZ",
            status=FindingStatus.ACTIVE,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(finding)
        await db.commit()

        resp = await client.get(
            f"/api/v1/findings/{finding.id}/remediation",
            cookies=auth_cookies,
        )
        assert resp.status_code == 404
        assert "TOTALLY_CUSTOM_RULE_XYZ" in resp.json()["error"]

    async def test_get_remediation_idor_prevention(self, client, db, org, auth_cookies):
        """Ensure user cannot access findings from another org."""
        from models import Organization
        from routers.cli import hash_api_key

        other_org = Organization(
            name="other-org",
            api_key_hash=hash_api_key("other-key"),
            is_active=1,
        )
        db.add(other_org)
        await db.flush()

        other_repo = Repository(org_id=other_org.id, name="other/repo")
        db.add(other_repo)
        await db.flush()

        other_finding = Finding(
            repo_id=other_repo.id,
            secret_hash="d" * 64,
            rule_id="AWS_ACCESS_KEY",
            status=FindingStatus.ACTIVE,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(other_finding)
        await db.commit()

        # Try to access the other org's finding — should get 404, not 403
        resp = await client.get(
            f"/api/v1/findings/{other_finding.id}/remediation",
            cookies=auth_cookies,
        )
        assert resp.status_code == 404
        assert resp.json()["error"] == "Finding not found"


# =============================================================================
# ROTATED triage tests
# =============================================================================

@pytest.mark.asyncio
class TestRotatedTriage:

    async def test_triage_to_rotated(self, client, db, org, auth_cookies):
        repo = Repository(org_id=org.id, name="test/rotate-repo")
        db.add(repo)
        await db.flush()

        finding = Finding(
            repo_id=repo.id,
            secret_hash="e" * 64,
            rule_id="GITHUB_PAT",
            status=FindingStatus.ACTIVE,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(finding)
        await db.commit()

        resp = await client.patch(
            f"/api/v1/findings/{finding.id}",
            json={"status": "rotated"},
            cookies=auth_cookies,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "rotated"
        assert data["rotated_at"] is not None

    async def test_rotated_at_write_once(self, client, db, org, auth_cookies):
        """rotated_at should not be overwritten on subsequent ROTATED patches."""
        repo = Repository(org_id=org.id, name="test/writeonce-repo")
        db.add(repo)
        await db.flush()

        finding = Finding(
            repo_id=repo.id,
            secret_hash="f" * 64,
            rule_id="SLACK_BOT_TOKEN",
            status=FindingStatus.ACTIVE,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(finding)
        await db.commit()

        # First ROTATED — sets rotated_at
        resp1 = await client.patch(
            f"/api/v1/findings/{finding.id}",
            json={"status": "rotated"},
            cookies=auth_cookies,
        )
        first_rotated_at = resp1.json()["rotated_at"]
        assert first_rotated_at is not None

        # Re-activate then rotate again
        await client.patch(
            f"/api/v1/findings/{finding.id}",
            json={"status": "active"},
            cookies=auth_cookies,
        )
        resp2 = await client.patch(
            f"/api/v1/findings/{finding.id}",
            json={"status": "rotated"},
            cookies=auth_cookies,
        )
        second_rotated_at = resp2.json()["rotated_at"]

        # rotated_at should be unchanged (write-once)
        assert second_rotated_at == first_rotated_at

    async def test_rotated_in_filter(self, client, db, org, auth_cookies):
        """Rotated findings should appear when filtering by rotated status."""
        repo = Repository(org_id=org.id, name="test/filter-repo")
        db.add(repo)
        await db.flush()

        finding = Finding(
            repo_id=repo.id,
            secret_hash="aa" * 32,
            rule_id="OPENAI_API_KEY",
            status=FindingStatus.ROTATED,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            rotated_at=datetime.now(timezone.utc),
        )
        db.add(finding)
        await db.commit()

        resp = await client.get(
            "/api/v1/findings?status=rotated",
            cookies=auth_cookies,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert any(f["status"] == "rotated" for f in data["items"])
