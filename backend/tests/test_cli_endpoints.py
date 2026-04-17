"""
Tests for CLI-facing endpoints.

Verifies that the existing behavior is preserved after refactoring.
"""

import pytest


CLI_HEADERS = {"X-API-Key": "test-api-key"}

SAMPLE_EVENTS = {
    "events": [
        {
            "status": "found",
            "fingerprint": "a" * 64,
            "rule_id": "AWS_ACCESS_KEY",
            "file": "config.env",
            "line": 5,
            "risk_class": "api_key",
            "risk_impact": "critical",
        }
    ],
    "repo": "test-org/test-repo",
}


@pytest.mark.asyncio
async def test_post_events_success(client, org):
    resp = await client.post(
        "/api/v1/events",
        json=SAMPLE_EVENTS,
        headers=CLI_HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["processed"] == 1
    assert data["new_findings"] == 1


@pytest.mark.asyncio
async def test_post_events_unauthenticated(client):
    resp = await client.post("/api/v1/events", json=SAMPLE_EVENTS)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_post_events_invalid_key(client, org):
    resp = await client.post(
        "/api/v1/events",
        json=SAMPLE_EVENTS,
        headers={"X-API-Key": "wrong-key"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_state(client, org):
    # First post an event
    await client.post("/api/v1/events", json=SAMPLE_EVENTS, headers=CLI_HEADERS)

    resp = await client.get(
        "/api/v1/state",
        params={"repo": "test-org/test-repo"},
        headers=CLI_HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "a" * 64 in data["active_hashes"]


@pytest.mark.asyncio
async def test_get_state_empty_repo(client, org):
    resp = await client.get(
        "/api/v1/state",
        params={"repo": "test-org/empty-repo"},
        headers=CLI_HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json()["active_hashes"] == []


@pytest.mark.asyncio
async def test_events_fixed(client, org):
    # Create finding
    await client.post("/api/v1/events", json=SAMPLE_EVENTS, headers=CLI_HEADERS)

    # Fix it
    fix_events = {
        "events": [{"status": "removed", "fingerprint": "a" * 64}],
        "repo": "test-org/test-repo",
    }
    resp = await client.post("/api/v1/events", json=fix_events, headers=CLI_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["fixed_findings"] == 1

    # Verify state no longer has it
    state = await client.get(
        "/api/v1/state",
        params={"repo": "test-org/test-repo"},
        headers=CLI_HEADERS,
    )
    assert "a" * 64 not in state.json()["active_hashes"]


@pytest.mark.asyncio
async def test_events_invalid_hash(client, org):
    bad_events = {
        "events": [{"status": "found", "fingerprint": "not-a-hash"}],
        "repo": "test-org/test-repo",
    }
    resp = await client.post("/api/v1/events", json=bad_events, headers=CLI_HEADERS)
    assert resp.status_code == 422  # Pydantic validation


@pytest.mark.asyncio
async def test_events_batch_size_limit(client, org):
    """Max 50 events per batch."""
    events = {
        "events": [
            {"status": "found", "fingerprint": f"{i:064x}"}
            for i in range(51)
        ],
        "repo": "test-org/test-repo",
    }
    resp = await client.post("/api/v1/events", json=events, headers=CLI_HEADERS)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_organization(client):
    resp = await client.post(
        "/api/v1/admin/organizations",
        params={"name": "new-org"},
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "new-org"
    assert "api_key" in data


@pytest.mark.asyncio
async def test_create_organization_bad_admin_key(client):
    resp = await client.post(
        "/api/v1/admin/organizations",
        params={"name": "new-org"},
        headers={"X-Admin-Key": "wrong-key"},
    )
    assert resp.status_code == 401
