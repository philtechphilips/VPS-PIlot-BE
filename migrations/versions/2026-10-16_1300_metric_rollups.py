"""metric rollups: hourly host metrics kept for 90 days

Revision ID: 9f1d3b5c7e28
Revises: 6b2e8d4f1a37
Create Date: 2026-10-16 13:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '9f1d3b5c7e28'
down_revision: str | Sequence[str] | None = '6b2e8d4f1a37'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "metric_rollups",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("server_id", sa.String(length=32), nullable=False),
        sa.Column("hour", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("samples", sa.Integer(), nullable=False),
        sa.Column("cpu_percent", sa.Float(), nullable=False),
        sa.Column("cpu_max", sa.Float(), nullable=False),
        sa.Column("memory_percent", sa.Float(), nullable=False),
        sa.Column("memory_max", sa.Float(), nullable=False),
        sa.Column("swap_percent", sa.Float(), nullable=False),
        sa.Column("disk_percent", sa.Float(), nullable=False),
        sa.Column("load_1", sa.Float(), nullable=False),
        sa.Column("net_rx_bps", sa.Float(), nullable=False),
        sa.Column("net_tx_bps", sa.Float(), nullable=False),
        sa.ForeignKeyConstraint(["server_id"], ["servers.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "metric_rollups_server_id_hour_idx",
        "metric_rollups",
        ["server_id", "hour"],
        unique=True,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("metric_rollups_server_id_hour_idx", table_name="metric_rollups")
    op.drop_table("metric_rollups")
