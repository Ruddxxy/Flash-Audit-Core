"""Tests for dashboard authentication endpoints."""

import pytest


@pytest.mark.asyncio
async def test_login_success(client, admin_user):
    resp = await client.post("/api/v1/auth/login", json={
        "email": "admin@test.com",
        "password": "testpass123",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["message"] == "Login successful"
    assert data["user"]["email"] == "admin@test.com"
    assert "flashaudit_session" in resp.cookies


@pytest.mark.asyncio
async def test_login_wrong_password(client, admin_user):
    resp = await client.post("/api/v1/auth/login", json={
        "email": "admin@test.com",
        "password": "wrong-password",
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_user(client):
    resp = await client.post("/api/v1/auth/login", json={
        "email": "nobody@test.com",
        "password": "testpass123",
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_short_password_rejected(client):
    resp = await client.post("/api/v1/auth/login", json={
        "email": "admin@test.com",
        "password": "short",
    })
    assert resp.status_code == 422  # Pydantic validation


@pytest.mark.asyncio
async def test_me_authenticated(client, auth_cookies):
    resp = await client.get("/api/v1/auth/me", cookies=auth_cookies)
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "admin@test.com"
    assert data["role"] == "admin"


@pytest.mark.asyncio
async def test_me_unauthenticated(client):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout(client, auth_cookies):
    resp = await client.post("/api/v1/auth/logout", cookies=auth_cookies)
    assert resp.status_code == 200

    # Session should be invalidated
    resp2 = await client.get("/api/v1/auth/me", cookies=auth_cookies)
    assert resp2.status_code == 401


@pytest.mark.asyncio
async def test_register_bootstrap(client):
    """First user registration should work without auth."""
    resp = await client.post("/api/v1/auth/register", json={
        "email": "first@test.com",
        "password": "testpass123",
        "name": "First User",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "first@test.com"
    assert data["role"] == "admin"  # Bootstrap user gets admin


@pytest.mark.asyncio
async def test_register_duplicate_email(client, admin_user, auth_cookies):
    resp = await client.post("/api/v1/auth/register", json={
        "email": "admin@test.com",
        "password": "newpass12345",
        "name": "Duplicate",
    }, cookies=auth_cookies)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_register_requires_auth_after_bootstrap(client, admin_user):
    """After first user exists, registration requires admin auth."""
    resp = await client.post("/api/v1/auth/register", json={
        "email": "second@test.com",
        "password": "testpass123",
        "name": "Second User",
    })
    assert resp.status_code == 401
