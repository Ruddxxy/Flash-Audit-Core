"""Tests for findings dashboard endpoints."""

import pytest
from models import Finding, FindingStatus, Repository


@pytest.mark.asyncio
async def test_list_findings_empty(client, auth_cookies):
    resp = await client.get("/api/v1/findings", cookies=auth_cookies)
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_list_findings_with_data(client, org, auth_cookies, db):
    # Create test data
    repo = Repository(org_id=org.id, name="test-org/repo")
    db.add(repo)
    await db.flush()

    from datetime import datetime, timezone
    finding = Finding(
        repo_id=repo.id,
        secret_hash="a" * 64,
        rule_id="AWS_ACCESS_KEY",
        file_path="config.env",
        line_number=5,
        risk_class="api_key",
        risk_impact="critical",
        status=FindingStatus.ACTIVE,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db.add(finding)
    await db.commit()

    resp = await client.get("/api/v1/findings", cookies=auth_cookies)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["rule_id"] == "AWS_ACCESS_KEY"


@pytest.mark.asyncio
async def test_list_findings_requires_auth(client):
    resp = await client.get("/api/v1/findings")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_triage_finding(client, org, auth_cookies, db):
    repo = Repository(org_id=org.id, name="test-org/repo")
    db.add(repo)
    await db.flush()

    from datetime import datetime, timezone
    finding = Finding(
        repo_id=repo.id,
        secret_hash="b" * 64,
        status=FindingStatus.ACTIVE,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db.add(finding)
    await db.commit()
    await db.refresh(finding)

    resp = await client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"status": "ignored"},
        cookies=auth_cookies,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"


@pytest.mark.asyncio
async def test_filter_by_status(client, org, auth_cookies, db):
    repo = Repository(org_id=org.id, name="test-org/repo")
    db.add(repo)
    await db.flush()

    from datetime import datetime, timezone
    for i, status in enumerate([FindingStatus.ACTIVE, FindingStatus.FIXED, FindingStatus.IGNORED]):
        f = Finding(
            repo_id=repo.id,
            secret_hash=f"{i:064x}",
            status=status,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(f)
    await db.commit()

    resp = await client.get("/api/v1/findings", params={"status": "active"}, cookies=auth_cookies)
    assert resp.status_code == 200
    assert resp.json()["total"] == 1
