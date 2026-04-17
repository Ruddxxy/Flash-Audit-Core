"""
Alembic environment configuration.

Reads DATABASE_URL from environment and supports both sync (migration generation)
and async (online migration) modes.
"""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool, create_engine

# Import models so metadata is populated
from models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_database_url() -> str:
    """Get database URL from environment, converting to sync driver for Alembic."""
    url = os.getenv("DATABASE_URL", "sqlite:///./flashaudit.db")

    # Alembic runs synchronously — convert async drivers to sync equivalents
    url = url.replace("postgresql+asyncpg://", "postgresql://")
    url = url.replace("sqlite+aiosqlite://", "sqlite://")

    # Handle Render/Heroku postgres:// prefix
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)

    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — generates SQL script without DB connection."""
    url = get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode — connects to the database."""
    url = get_database_url()
    is_sqlite = "sqlite" in url

    connect_args = {}
    if is_sqlite:
        connect_args = {"check_same_thread": False}

    connectable = create_engine(
        url,
        poolclass=pool.NullPool if is_sqlite else None,
        connect_args=connect_args,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
