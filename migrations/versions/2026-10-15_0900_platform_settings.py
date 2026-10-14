"""platform settings (name, public URL)

Revision ID: 2c6d8e0f4a17
Revises: 7f3a1e9c5b28
Create Date: 2026-10-15 09:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '2c6d8e0f4a17'
down_revision: str | Sequence[str] | None = '7f3a1e9c5b28'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "platform_settings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=32), server_default="VPSPilot", nullable=False),
        sa.Column("public_url", sa.String(length=300), nullable=True),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("platform_settings")
