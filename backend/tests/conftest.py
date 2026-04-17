"""
Test fixtures for FlashAudit backend tests.

Key design: the `db` fixture and HTTP handlers share a SINGLE AsyncSession.
This eliminates cross-session visibility issues with SQLite StaticPool.
"""

import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["ADMIN_KEY"] = "test-admin-key"
os.environ["COOKIE_SECURE"] = "false"
os.environ["SESSION_TTL_HOURS"] = "24"

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import StaticPool
from passlib.hash import bcrypt

from models import Base, Organization, User, UserRole
from database import get_session

test_engine = create_async_engine(
    "sqlite+aiosqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False,
    autocommit=False, autoflush=False,
)

# Module-level reference so override_get_session can access the fixture's session
_shared_session: AsyncSession | None = None


async def override_get_session():
    """Yield the same session that the test fixture holds."""
    assert _shared_session is not None, "No shared session — did the test forget the `client` fixture?"
    yield _shared_session
    # No commit/rollback here; the fixture owns the session lifecycle.


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """Clear all in-memory rate-limiting state between tests."""
    from services.rate_limiter import cli_rate_limiter, login_rate_limiter
    cli_rate_limiter.reset()
    login_rate_limiter.reset()


@pytest_asyncio.fixture
async def db():
    """
    Provide a clean database and a session for each test.

    - Drops and recreates all tables (full isolation).
    - Sets the module-level _shared_session so HTTP handlers see the same data.
    """
    global _shared_session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        _shared_session = session
        yield session
        _shared_session = None


@pytest_asyncio.fixture
async def client(db):
    """
    HTTP test client.  Depends on `db` so tables always exist
    and the dependency override points to the shared session.
    """
    from main import app
    app.dependency_overrides[get_session] = override_get_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def org(db):
    from routers.cli import hash_api_key
    o = Organization(
        name="test-org",
        api_key_hash=hash_api_key("test-api-key"),
        is_active=1,
    )
    db.add(o)
    await db.commit()
    await db.refresh(o)
    return o


@pytest_asyncio.fixture
async def admin_user(db, org):
    user = User(
        org_id=org.id,
        email="admin@test.com",
        password_hash=bcrypt.hash("testpass123"),
        name="Admin User",
        role=UserRole.ADMIN,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@pytest_asyncio.fixture
async def auth_cookies(client, admin_user):
    resp = await client.post("/api/v1/auth/login", json={
        "email": "admin@test.com",
        "password": "testpass123",
    })
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.cookies
