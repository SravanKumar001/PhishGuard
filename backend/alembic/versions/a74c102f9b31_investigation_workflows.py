"""investigation workflows

Revision ID: a74c102f9b31
Revises: edefcb178ae0
Create Date: 2026-11-24 10:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a74c102f9b31"
down_revision: str | Sequence[str] | None = "edefcb178ae0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_STATUS_CHECK = (
    "status IN ('new', 'investigating', 'confirmed_phishing', "
    "'benign', 'needs_review', 'closed')"
)


def upgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_constraint("ck_investigations_status", type_="check")

    op.execute("UPDATE investigations SET status = 'new' WHERE status = 'open'")

    with op.batch_alter_table("investigations") as batch_op:
        batch_op.create_check_constraint("ck_investigations_status", _STATUS_CHECK)

    op.create_table(
        "user_preferences",
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("theme", sa.String(length=16), nullable=False),
        sa.Column("compact_mode", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "theme IN ('system', 'light', 'dark')",
            name="ck_user_preferences_theme",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )


def downgrade() -> None:
    op.drop_table("user_preferences")

    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_constraint("ck_investigations_status", type_="check")

    op.execute(
        "UPDATE investigations SET status = 'open' "
        "WHERE status IN ('new', 'confirmed_phishing', 'benign', 'needs_review')"
    )

    with op.batch_alter_table("investigations") as batch_op:
        batch_op.create_check_constraint(
            "ck_investigations_status",
            "status IN ('open', 'investigating', 'closed')",
        )
