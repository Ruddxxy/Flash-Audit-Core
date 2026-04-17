"""Rename webhooks.secret_hash to secret and expand size

Motivation:
    The column was named `secret_hash` implying a SHA256 digest,
    but the HMAC delivery code (services/webhooks.py) used it as the
    signing key — which requires plaintext so the receiver can verify.
    Rename to `secret` and expand length so real webhook secrets fit.

Revision ID: 004
Revises: 003
Create Date: 2026-04-17
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("webhooks") as batch_op:
        batch_op.alter_column(
            "secret_hash",
            new_column_name="secret",
            existing_type=sa.String(64),
            type_=sa.String(256),
            existing_nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("webhooks") as batch_op:
        batch_op.alter_column(
            "secret",
            new_column_name="secret_hash",
            existing_type=sa.String(256),
            type_=sa.String(64),
            existing_nullable=True,
        )
