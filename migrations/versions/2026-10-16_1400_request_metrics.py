"""request metrics: per-site requests per minute from the proxy

Revision ID: 4c8a2e6f9b13
Revises: 9f1d3b5c7e28
Create Date: 2026-10-16 14:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '4c8a2e6f9b13'
down_revision: str | Sequence[str] | None = '9f1d3b5c7e28'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "request_metrics",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("server_id", sa.String(length=32), nullable=False),
        sa.Column("host", sa.String(length=253), nullable=False),
        sa.Column("application_id", sa.String(length=32), nullable=True),
        sa.Column("minute", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("requests", sa.Integer(), nullable=False),
        sa.Column("s2xx", sa.Integer(), nullable=False),
        sa.Column("s3xx", sa.Integer(), nullable=False),
        sa.Column("s4xx", sa.Integer(), nullable=False),
        sa.Column("s5xx", sa.Integer(), nullable=False),
        sa.Column("bytes", sa.BigInteger(), nullable=False),
        sa.Column("p50_ms", sa.Float(), nullable=False),
        sa.Column("p95_ms", sa.Float(), nullable=False),
        sa.ForeignKeyConstraint(
            ["application_id"], ["applications.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "request_metrics_host_minute_idx",
        "request_metrics",
        ["host", "minute"],
        unique=True,
    )
    op.create_index(
        "request_metrics_application_id_minute_idx",
        "request_metrics",
        ["application_id", "minute"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("request_metrics_application_id_minute_idx", table_name="request_metrics")
    op.drop_index("request_metrics_host_minute_idx", table_name="request_metrics")
    op.drop_table("request_metrics")
