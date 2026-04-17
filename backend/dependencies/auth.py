"""
Dashboard authentication dependencies.

Provides session-based auth for the web dashboard, completely separate
from the CLI's API key auth.

Security:
- Session tokens are SHA256-hashed before storage
- Cookies are HttpOnly + Secure + SameSite=Strict
- Sessions expire after configurable TTL
- Every query is scoped to the user's org_id (IDOR prevention)
"""

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from models import User, Session, UserRole

SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "24"))
SESSION_COOKIE_NAME = "flashaudit_session"
LOGIN_RATE_LIMIT_MAX = int(os.getenv("LOGIN_RATE_LIMIT_MAX", "5"))


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_session_token() -> str:
    return secrets.token_urlsafe(48)


async def get_current_user(
    flashaudit_session: Optional[str] = Cookie(None, alias=SESSION_COOKIE_NAME),
    session: AsyncSession = Depends(get_session),
) -> User:
    """
    Extract and verify the session cookie.
    Returns the authenticated User or raises 401.
    """
    if not flashaudit_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    token_hash = hash_session_token(flashaudit_session)
    now = datetime.now(timezone.utc)

    result = await session.execute(
        select(Session)
        .where(Session.token_hash == token_hash)
        .where(Session.expires_at > now)
    )
    sess = result.scalar_one_or_none()

    if sess is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    result = await session.execute(
        select(User)
        .where(User.id == sess.user_id)
        .where(User.is_active == True)  # noqa: E712
    )
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
        )

    return user


def require_role(*roles: UserRole):
    """
    Dependency factory that checks the user has one of the specified roles.
    Usage: Depends(require_role(UserRole.ADMIN))
    """
    async def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user
    return checker


async def create_session(
    db: AsyncSession,
    user_id: int,
) -> tuple[str, datetime]:
    """
    Create a new session for a user.
    Returns (raw_token, expires_at).
    """
    token = generate_session_token()
    token_hash = hash_session_token(token)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)

    sess = Session(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.add(sess)
    await db.flush()

    return token, expires_at


async def destroy_session(
    db: AsyncSession,
    token: str,
) -> None:
    """Destroy a session by its raw token."""
    token_hash = hash_session_token(token)
    await db.execute(
        delete(Session).where(Session.token_hash == token_hash)
    )


async def cleanup_expired_sessions(db: AsyncSession) -> int:
    """Remove all expired sessions. Returns count deleted."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        delete(Session).where(Session.expires_at <= now)
    )
    return result.rowcount
