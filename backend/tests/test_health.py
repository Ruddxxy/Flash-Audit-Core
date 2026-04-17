"""Tests for health check endpoint."""

import pytest


@pytest.mark.asyncio
async def test_health_check(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"


@pytest.mark.asyncio
async def test_health_no_auth_required(client):
    """Health endpoint must not require authentication."""
    resp = await client.get("/health")
    assert resp.status_code == 200
