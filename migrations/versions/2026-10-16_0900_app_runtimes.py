"""app runtimes: compose file and public service

Revision ID: 5e1b7c3a9d42
Revises: 2c6d8e0f4a17
Create Date: 2026-10-16 09:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '5e1b7c3a9d42'
down_revision: str | Sequence[str] | None = '2c6d8e0f4a17'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "applications", sa.Column("compose_file", sa.String(length=200), nullable=True)
    )
    op.add_column(
        "applications", sa.Column("compose_service", sa.String(length=63), nullable=True)
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("applications", "compose_service")
    op.drop_column("applications", "compose_file")
