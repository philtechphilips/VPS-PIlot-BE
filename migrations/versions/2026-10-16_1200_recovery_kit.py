"""platform: when the recovery kit was last downloaded

Revision ID: 6b2e8d4f1a37
Revises: 3a9c5e7b2d14
Create Date: 2026-10-16 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '6b2e8d4f1a37'
down_revision: str | Sequence[str] | None = '3a9c5e7b2d14'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "platform_settings",
        sa.Column("recovery_kit_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("platform_settings", "recovery_kit_at")
