"""alert channels: webhook, Slack, Telegram

Revision ID: 3a9c5e7b2d14
Revises: 8d4f2a6c1e93
Create Date: 2026-10-16 11:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '3a9c5e7b2d14'
down_revision: str | Sequence[str] | None = '8d4f2a6c1e93'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "alert_channels",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=60), nullable=False),
        sa.Column("config", sa.Text(), nullable=False),
        sa.Column("target_label", sa.String(length=120), nullable=False),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_sent_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=300), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("alert_channels")
