"""app build and start commands (for repositories without a Dockerfile)

Revision ID: 6d2a8c4e1f57
Revises: 2b7e9f4c1d83
Create Date: 2026-10-14 18:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '6d2a8c4e1f57'
down_revision: str | Sequence[str] | None = '2b7e9f4c1d83'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("applications") as batch:
        batch.add_column(sa.Column("build_command", sa.String(length=500), nullable=True))
        batch.add_column(sa.Column("start_command", sa.String(length=500), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("applications") as batch:
        batch.drop_column("start_command")
        batch.drop_column("build_command")
