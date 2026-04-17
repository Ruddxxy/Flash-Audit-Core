"""
Settings endpoints: webhooks, policies, and user management.

Security:
- Admin-only operations protected by require_role(UserRole.ADMIN)
- All queries scoped to user's org_id
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from passlib.hash import bcrypt
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from services.audit import log_action

from database import get_session
from dependencies.auth import get_current_user, require_role
from models import (
    User,
    UserRole,
    Webhook,
    Policy,
    WebhookRequest,
    WebhookResponse,
    WebhookCreatedResponse,
    PolicyRequest,
    PolicyResponse,
    UserResponse,
    RegisterRequest,
    ErrorResponse,
)

logger = logging.getLogger("flashaudit.settings")

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])


# =============================================================================
# Webhooks
# =============================================================================


@router.get("/webhooks", response_model=list[WebhookResponse], summary="List webhooks")
async def list_webhooks(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(Webhook)
        .where(Webhook.org_id == user.org_id)
        .order_by(Webhook.created_at.desc())
    )
    return [WebhookResponse.model_validate(w) for w in result.scalars().all()]


@router.post(
    "/webhooks",
    response_model=WebhookCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create webhook (returns secret once; store it securely)",
)
async def create_webhook(
    body: WebhookRequest,
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.MEMBER)),
    db: AsyncSession = Depends(get_session),
):
    webhook = Webhook(
        org_id=user.org_id,
        url=body.url,
        events=body.events,
        secret=body.secret,
        is_active=body.is_active,
    )
    db.add(webhook)
    await db.flush()

    await log_action(
        db,
        org_id=user.org_id,
        action="webhook_create",
        user_id=user.id,
        resource_type="webhook",
        resource_id=webhook.id,
        details={
            "url": body.url,
            "events": body.events,
            "has_secret": body.secret is not None,
        },
    )
    await db.commit()
    await db.refresh(webhook)

    logger.info(f"Webhook created: {webhook.url} by {user.email}")
    return WebhookCreatedResponse.model_validate(webhook)


@router.delete(
    "/webhooks/{webhook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete webhook",
)
async def delete_webhook(
    webhook_id: int,
    user: User = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(Webhook)
        .where(Webhook.id == webhook_id)
        .where(Webhook.org_id == user.org_id)
    )
    webhook = result.scalar_one_or_none()
    if webhook is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found"
        )

    await db.execute(delete(Webhook).where(Webhook.id == webhook_id))
    await db.commit()


# =============================================================================
# Policies
# =============================================================================


@router.get("/policies", response_model=list[PolicyResponse], summary="List policies")
async def list_policies(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(Policy)
        .where(Policy.org_id == user.org_id)
        .order_by(Policy.created_at.desc())
    )
    return [PolicyResponse.model_validate(p) for p in result.scalars().all()]


@router.post(
    "/policies",
    response_model=PolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create policy",
)
async def create_policy(
    body: PolicyRequest,
    user: User = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_session),
):
    policy = Policy(
        org_id=user.org_id,
        name=body.name,
        conditions=body.conditions,
        action=body.action,
        is_active=body.is_active,
    )
    db.add(policy)
    await db.flush()

    await log_action(
        db,
        org_id=user.org_id,
        action="policy_create",
        user_id=user.id,
        resource_type="policy",
        resource_id=policy.id,
        details={"name": body.name, "action": body.action.value},
    )
    await db.commit()
    await db.refresh(policy)

    logger.info(f"Policy created: {policy.name} by {user.email}")
    return PolicyResponse.model_validate(policy)


@router.delete(
    "/policies/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete policy",
)
async def delete_policy(
    policy_id: int,
    user: User = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(Policy).where(Policy.id == policy_id).where(Policy.org_id == user.org_id)
    )
    policy = result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found"
        )

    await db.execute(delete(Policy).where(Policy.id == policy_id))
    await db.commit()


# =============================================================================
# User Management (Admin only)
# =============================================================================


@router.get(
    "/users", response_model=list[UserResponse], summary="List users in organization"
)
async def list_users(
    user: User = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(User).where(User.org_id == user.org_id).order_by(User.created_at)
    )
    return [UserResponse.model_validate(u) for u in result.scalars().all()]


@router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create user (admin only)",
)
async def create_user(
    body: RegisterRequest,
    admin: User = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_session),
):
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email already registered"
        )

    user = User(
        org_id=admin.org_id,
        email=body.email,
        password_hash=bcrypt.hash(body.password),
        name=body.name,
        role=body.role,
        is_active=True,
    )
    db.add(user)
    await db.flush()

    await log_action(
        db,
        org_id=admin.org_id,
        action="user_create",
        user_id=admin.id,
        resource_type="user",
        resource_id=user.id,
        details={"email": body.email, "role": body.role.value},
    )
    await db.commit()
    await db.refresh(user)

    logger.info(f"User created: {user.email} by {admin.email}")
    return UserResponse.model_validate(user)


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deactivate user (admin only)",
)
async def deactivate_user(
    user_id: int,
    admin: User = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_session),
):
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate yourself",
        )

    result = await db.execute(
        select(User).where(User.id == user_id).where(User.org_id == admin.org_id)
    )
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    target.is_active = False
    await db.commit()

    logger.info(f"User deactivated: {target.email} by {admin.email}")
