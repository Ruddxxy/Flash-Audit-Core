"""Initial schema — all 7 tables

Revision ID: 001
Revises: None
Create Date: 2026-03-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Organizations
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("api_key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("is_active", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_org_api_key_active", "organizations", ["api_key_hash", "is_active"])

    # Repositories
    op.create_table(
        "repositories",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_unique_constraint("uq_repo_org_name", "repositories", ["org_id", "name"])
    op.create_index("ix_repo_org_id", "repositories", ["org_id"])

    # Findings
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False),
        sa.Column("secret_hash", sa.String(64), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("risk_class", sa.String(64), nullable=True),
        sa.Column("risk_impact", sa.String(64), nullable=True),
        sa.Column("status", sa.Enum("active", "fixed", "ignored", "false_positive", "rotated", name="findingstatus"), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("fixed_at", sa.DateTime(), nullable=True),
        sa.Column("rotated_at", sa.DateTime(), nullable=True),
    )
    op.create_unique_constraint("uq_finding_repo_hash", "findings", ["repo_id", "secret_hash"])
    op.create_index("ix_finding_repo_status", "findings", ["repo_id", "status"])
    op.create_index("ix_finding_hash", "findings", ["secret_hash"])

    # Users
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(256), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(128), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("role", sa.Enum("admin", "member", "viewer", name="userrole"), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_login", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_user_org_id", "users", ["org_id"])
    op.create_index("ix_user_email", "users", ["email"])

    # Sessions
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_sessions_token_hash", "sessions", ["token_hash"])

    # Webhooks
    op.create_table(
        "webhooks",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("secret_hash", sa.String(64), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_webhook_org_id", "webhooks", ["org_id"])

    # Policies
    op.create_table(
        "policies",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("conditions", sa.JSON(), nullable=False),
        sa.Column("action", sa.Enum("block", "alert", name="policyaction"), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_policy_org_id", "policies", ["org_id"])


def downgrade() -> None:
    op.drop_table("policies")
    op.drop_table("webhooks")
    op.drop_table("sessions")
    op.drop_table("users")
    op.drop_table("findings")
    op.drop_table("repositories")
    op.drop_table("organizations")
