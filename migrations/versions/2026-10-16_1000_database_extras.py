"""database extras: external TLS settings, metrics history

Revision ID: 8d4f2a6c1e93
Revises: 5e1b7c3a9d42
Create Date: 2026-10-16 10:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '8d4f2a6c1e93'
down_revision: str | Sequence[str] | None = '5e1b7c3a9d42'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "database_instances", sa.Column("tls_mode", sa.String(length=16), nullable=True)
    )
    op.add_column("database_instances", sa.Column("tls_ca", sa.Text(), nullable=True))
    op.add_column(
        "database_instances",
        sa.Column("sampled_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.create_table(
        "database_metrics",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("instance_id", sa.String(length=32), nullable=False),
        sa.Column("ts", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("connections", sa.Integer(), nullable=True),
        sa.Column("max_connections", sa.Integer(), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("memory_bytes", sa.BigInteger(), nullable=True),
        sa.Column("keys", sa.BigInteger(), nullable=True),
        sa.Column("ops_per_sec", sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(
            ["instance_id"], ["database_instances.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "database_metrics_instance_id_ts_idx",
        "database_metrics",
        ["instance_id", "ts"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("database_metrics_instance_id_ts_idx", table_name="database_metrics")
    op.drop_table("database_metrics")
    op.drop_column("database_instances", "sampled_at")
    op.drop_column("database_instances", "tls_ca")
    op.drop_column("database_instances", "tls_mode")
