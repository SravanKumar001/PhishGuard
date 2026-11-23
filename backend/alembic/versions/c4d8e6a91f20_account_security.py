"""account security

Revision ID: c4d8e6a91f20
Revises: a74c102f9b31
Create Date: 2026-11-23 19:30:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c4d8e6a91f20"
down_revision: str | Sequence[str] | None = "a74c102f9b31"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.false())
        )

    op.create_table(
        "account_tokens",
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("used_at", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "kind IN ('email_verification', 'password_reset')",
            name="ck_account_tokens_kind",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("token_hash"),
    )
    op.create_index(
        "ix_account_tokens_user_kind",
        "account_tokens",
        ["user_id", "kind"],
        unique=False,
    )
    op.create_index(
        op.f("ix_account_tokens_user_id"),
        "account_tokens",
        ["user_id"],
        unique=False,
    )

    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column("email_verified", server_default=None)


def downgrade() -> None:
    op.drop_index(op.f("ix_account_tokens_user_id"), table_name="account_tokens")
    op.drop_index("ix_account_tokens_user_kind", table_name="account_tokens")
    op.drop_table("account_tokens")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("email_verified")
