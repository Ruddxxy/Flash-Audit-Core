"""
Dashboard authentication endpoints.

Uses email/password + session cookies (HttpOnly, Secure, SameSite=Strict).
Completely separate from CLI API key auth.

Security:
- bcrypt for password hashing (inherently slow against brute force)
- Rate limiting: 5 attempts/min/IP, lockout after 10 failures
- New session token on every login (prevents session fixation)
- Session tokens stored as SHA256 hashes
"""

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from passlib.hash import bcrypt
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from dependencies.auth import (
    get_current_user,
    create_session,
    destroy_session,
    hash_session_token,
    SESSION_COOKIE_NAME,
)
from models import (
    User,
    Session as SessionModel,
    UserRole,
    Organization,
    LoginRequest,
    RegisterRequest,
    UserResponse,
    ErrorResponse,
)

logger = logging.getLogger("flashaudit.auth")

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])

from services.rate_limiter import login_rate_limiter  # noqa: E402  (late import avoids circular dependency)
from services.audit import log_action  # noqa: E402


async def _check_login_rate_limit(ip: str) -> None:
    if not await login_rate_limiter.is_allowed(f"login:{ip}"):
        retry_after = await login_rate_limiter.get_retry_after(f"login:{ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )


@router.post(
    "/login",
    responses={
        401: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    summary="Login with email and password",
)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_session),
):
    client_ip = request.client.host if request.client else "unknown"
    await _check_login_rate_limit(client_ip)

    result = await db.execute(
        select(User).where(User.email == body.email).where(User.is_active == True)  # noqa: E712
    )
    user = result.scalar_one_or_none()

    if user is None or not bcrypt.verify(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    user.last_login = datetime.now(timezone.utc)

    token, expires_at = await create_session(db, user.id)

    await log_action(
        db,
        org_id=user.org_id,
        action="login",
        user_id=user.id,
        ip_address=client_ip,
    )
    await db.commit()

    is_secure = os.getenv("COOKIE_SECURE", "true").lower() == "true"
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=is_secure,
        samesite="strict",
        max_age=int((expires_at - datetime.now(timezone.utc)).total_seconds()),
        path="/",
    )

    logger.info(f"User logged in: {user.email}")

    return {
        "message": "Login successful",
        "user": UserResponse.model_validate(user).model_dump(),
    }


@router.post("/logout", summary="Logout and clear session")
async def logout(
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        await destroy_session(db, token)
        await db.commit()

    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")

    logger.info(f"User logged out: {user.email}")
    return {"message": "Logged out"}


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user info",
)
async def get_me(user: User = Depends(get_current_user)):
    return UserResponse.model_validate(user)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user (admin-only or first-user bootstrap)",
    response_model_exclude_none=True,
)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_session),
):
    # Try to get current user from session cookie (optional — no 401 on failure)
    current_user: Optional[User] = None
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        token_hash = hash_session_token(token)
        sess_result = await db.execute(
            select(SessionModel)
            .where(SessionModel.token_hash == token_hash)
            .where(SessionModel.expires_at > datetime.now(timezone.utc))
        )
        sess = sess_result.scalar_one_or_none()
        if sess:
            user_result = await db.execute(
                select(User)
                .where(User.id == sess.user_id)
                .where(User.is_active == True)  # noqa: E712
            )
            current_user = user_result.scalar_one_or_none()

    user_count = await db.execute(select(func.count(User.id)))
    total_users = user_count.scalar() or 0

    is_bootstrap = total_users == 0

    if not is_bootstrap:
        if current_user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        if current_user.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can register new users",
            )

    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    if is_bootstrap:
        org_result = await db.execute(select(Organization).limit(1))
        org = org_result.scalar_one_or_none()
        if org is None:
            org = Organization(
                name="Default",
                api_key_hash="bootstrap-placeholder",
                is_active=1,
            )
            db.add(org)
            await db.flush()
        org_id = org.id
        role = UserRole.ADMIN
    else:
        org_id = current_user.org_id
        role = body.role

    password_hash = bcrypt.hash(body.password)

    user = User(
        org_id=org_id,
        email=body.email,
        password_hash=password_hash,
        name=body.name,
        role=role,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    logger.info(f"User registered: {user.email} (bootstrap={is_bootstrap})")

    return UserResponse.model_validate(user)
