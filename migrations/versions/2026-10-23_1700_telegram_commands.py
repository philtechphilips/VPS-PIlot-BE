"""telegram commands on alert channels

Revision ID: 1a7f3c9e5b28
Revises: 4e8c2a6f1d97
Create Date: 2026-10-23 17:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '1a7f3c9e5b28'
down_revision: str | Sequence[str] | None = '4e8c2a6f1d97'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("alert_channels", sa.Column("commands", sa.Boolean(), server_default=sa.false(), nullable=False))
    op.add_column("alert_channels", sa.Column("update_offset", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("alert_channels", "update_offset")
    op.drop_column("alert_channels", "commands")
