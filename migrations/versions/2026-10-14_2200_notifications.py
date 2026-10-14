"""notifications and notification settings

Revision ID: 3f8c2e6b9a14
Revises: 9e4b1d7a3c26
Create Date: 2026-10-14 22:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '3f8c2e6b9a14'
down_revision: str | Sequence[str] | None = '9e4b1d7a3c26'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "notifications",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=40), nullable=False),
        sa.Column("level", sa.String(length=8), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("body", sa.String(length=500), nullable=True),
        sa.Column("link", sa.String(length=300), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("read_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("notifications_user_id_created_at_idx", "notifications", ["user_id", "created_at"], unique=False)
    op.create_table(
        "notification_settings",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("email_deploy_success", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("email_deploy_failure", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("notification_settings")
    op.drop_index("notifications_user_id_created_at_idx", table_name="notifications")
    op.drop_table("notifications")
