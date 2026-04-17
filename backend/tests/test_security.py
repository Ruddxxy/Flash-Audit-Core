"""Security-focused tests: IDOR, injection, brute force."""

import pytest
from models import Organization, Repository, Finding, FindingStatus, User, UserRole
from routers.cli import hash_api_key
from passlib.hash import bcrypt
from datetime import datetime, timezone


@pytest.mark.asyncio
async def test_idor_cross_org_findings(client, db, auth_cookies):
    """User should not see findings from another org."""
    # Create another org with its own repo and finding
    other_org = Organization(
        name="other-org",
        api_key_hash=hash_api_key("other-key"),
        is_active=1,
    )
    db.add(other_org)
    await db.flush()

    other_repo = Repository(org_id=other_org.id, name="other-org/secret-repo")
    db.add(other_repo)
    await db.flush()

    secret_finding = Finding(
        repo_id=other_repo.id,
        secret_hash="c" * 64,
        rule_id="PRIVATE_KEY",
        status=FindingStatus.ACTIVE,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db.add(secret_finding)
    await db.commit()

    # Logged in as admin of test-org — should not see other-org's findings
    resp = await client.get("/api/v1/findings", cookies=auth_cookies)
    assert resp.status_code == 200
    assert resp.json()["total"] == 0  # No cross-org leakage

    # Try direct access by ID
    await db.refresh(secret_finding)
    resp2 = await client.get(f"/api/v1/findings/{secret_finding.id}", cookies=auth_cookies)
    assert resp2.status_code == 404  # Cannot access other org's finding


@pytest.mark.asyncio
async def test_idor_cross_org_repos(client, db, auth_cookies):
    """User should not see repositories from another org."""
    other_org = Organization(
        name="evil-org",
        api_key_hash=hash_api_key("evil-key"),
        is_active=1,
    )
    db.add(other_org)
    await db.flush()

    evil_repo = Repository(org_id=other_org.id, name="evil-org/secrets")
    db.add(evil_repo)
    await db.commit()

    resp = await client.get("/api/v1/repositories", cookies=auth_cookies)
    assert resp.status_code == 200
    repos = resp.json()
    for repo in repos:
        assert repo["name"] != "evil-org/secrets"


@pytest.mark.asyncio
async def test_extra_fields_rejected(client, org):
    """Pydantic extra='forbid' should reject unknown fields."""
    bad_payload = {
        "events": [{
            "status": "found",
            "fingerprint": "a" * 64,
            "raw_secret": "AKIAIOSFODNN7EXAMPLE",  # Must be rejected
        }],
        "repo": "test-org/repo",
    }
    resp = await client.post(
        "/api/v1/events",
        json=bad_payload,
        headers={"X-API-Key": "test-api-key"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_session_invalidated_after_logout(client, admin_user):
    """After logout, the session token must not work."""
    # Login
    login_resp = await client.post("/api/v1/auth/login", json={
        "email": "admin@test.com",
        "password": "testpass123",
    })
    cookies = login_resp.cookies

    # Logout
    await client.post("/api/v1/auth/logout", cookies=cookies)

    # Session should be dead
    me_resp = await client.get("/api/v1/auth/me", cookies=cookies)
    assert me_resp.status_code == 401


@pytest.mark.asyncio
async def test_viewer_cannot_create_webhook(client, db, org):
    """Viewer role should not be able to create webhooks."""
    viewer = User(
        org_id=org.id,
        email="view@test.com",
        password_hash=bcrypt.hash("testpass123"),
        name="Viewer",
        role=UserRole.VIEWER,
        is_active=True,
    )
    db.add(viewer)
    await db.commit()

    login_resp = await client.post("/api/v1/auth/login", json={
        "email": "view@test.com",
        "password": "testpass123",
    })
    cookies = login_resp.cookies

    resp = await client.post(
        "/api/v1/settings/webhooks",
        json={"url": "https://evil.com/hook", "events": ["new_finding"]},
        cookies=cookies,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_disabled_user_cannot_login(client, db, org):
    """Disabled users must not be able to authenticate."""
    user = User(
        org_id=org.id,
        email="disabled@test.com",
        password_hash=bcrypt.hash("testpass123"),
        name="Disabled User",
        role=UserRole.MEMBER,
        is_active=False,
    )
    db.add(user)
    await db.commit()

    resp = await client.post("/api/v1/auth/login", json={
        "email": "disabled@test.com",
        "password": "testpass123",
    })
    assert resp.status_code == 401
