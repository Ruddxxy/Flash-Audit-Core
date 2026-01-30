"""
FlashAudit Backend - Database Configuration

Supports SQLite (development/MVP) and PostgreSQL (production).
Uses SQLAlchemy async for non-blocking database operations.
"""

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.pool import StaticPool

from models import Base

# =============================================================================
# Configuration
# =============================================================================

# Database URL from environment or default to SQLite
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./flashaudit.db"
)

# Convert postgres:// to postgresql:// for SQLAlchemy 2.0 compatibility
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+asyncpg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

# =============================================================================
# Engine Configuration
# =============================================================================

def get_engine_kwargs() -> dict:
    """Get engine configuration based on database type."""
    is_sqlite = "sqlite" in DATABASE_URL

    if is_sqlite:
        return {
            "connect_args": {"check_same_thread": False},
            "poolclass": StaticPool,
            "echo": os.getenv("SQL_ECHO", "").lower() == "true",
        }
    else:
        # PostgreSQL configuration
        return {
            "pool_size": int(os.getenv("DB_POOL_SIZE", "5")),
            "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "10")),
            "pool_timeout": int(os.getenv("DB_POOL_TIMEOUT", "30")),
            "pool_recycle": int(os.getenv("DB_POOL_RECYCLE", "1800")),
            "echo": os.getenv("SQL_ECHO", "").lower() == "true",
        }


# Create the async engine
engine: AsyncEngine = create_async_engine(DATABASE_URL, **get_engine_kwargs())

# Create async session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# =============================================================================
# Session Management
# =============================================================================

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency that provides a database session.

    Usage:
        @app.get("/endpoint")
        async def endpoint(session: AsyncSession = Depends(get_session)):
            ...
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def get_session_context() -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager for database sessions (for use outside of FastAPI deps).

    Usage:
        async with get_session_context() as session:
            ...
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# =============================================================================
# Initialization
# =============================================================================

async def init_db():
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db():
    """Close database connections."""
    await engine.dispose()
