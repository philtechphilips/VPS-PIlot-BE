"""servers, enrollment tokens and metric samples

Revision ID: 5a91c0d2e7f4
Revises: 3e8b5f1c7a42
Create Date: 2026-10-14 10:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '5a91c0d2e7f4'
down_revision: str | Sequence[str] | None = '3e8b5f1c7a42'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "servers",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=63), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column(
            "is_control_plane", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("os_name", sa.String(length=64), nullable=True),
        sa.Column("os_version", sa.String(length=64), nullable=True),
        sa.Column("kernel", sa.String(length=128), nullable=True),
        sa.Column("arch", sa.String(length=32), nullable=True),
        sa.Column("cpu_count", sa.Integer(), nullable=True),
        sa.Column("memory_total", sa.BigInteger(), nullable=True),
        sa.Column("disk_total", sa.BigInteger(), nullable=True),
        sa.Column("ip_addresses", sa.JSON(), nullable=False),
        sa.Column("agent_version", sa.String(length=32), nullable=True),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("inventory", sa.JSON(), nullable=False),
        sa.Column("inventory_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("agent_token_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "agent_token_rotated_at", sa.TIMESTAMP(timezone=True), nullable=True
        ),
        sa.Column("enrolled_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_heartbeat_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("uptime_seconds", sa.BigInteger(), nullable=True),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("servers_pkey")),
        sa.UniqueConstraint("name", name=op.f("servers_name_key")),
        sa.UniqueConstraint(
            "agent_token_hash", name=op.f("servers_agent_token_hash_key")
        ),
    )

    op.create_table(
        "enrollment_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("server_id", sa.String(length=32), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("used_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["servers.id"],
            name=op.f("enrollment_tokens_server_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("enrollment_tokens_pkey")),
        sa.UniqueConstraint(
            "token_hash", name=op.f("enrollment_tokens_token_hash_key")
        ),
    )
    op.create_index(
        op.f("enrollment_tokens_server_id_idx"), "enrollment_tokens", ["server_id"]
    )

    op.create_table(
        "metric_samples",
        sa.Column(
            "id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), nullable=False
        ),
        sa.Column("server_id", sa.String(length=32), nullable=False),
        sa.Column("ts", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("cpu_percent", sa.Float(), nullable=False),
        sa.Column("memory_percent", sa.Float(), nullable=False),
        sa.Column("memory_used", sa.BigInteger(), nullable=False),
        sa.Column("swap_percent", sa.Float(), nullable=False),
        sa.Column("disk_percent", sa.Float(), nullable=False),
        sa.Column("disk_used", sa.BigInteger(), nullable=False),
        sa.Column("inode_percent", sa.Float(), nullable=True),
        sa.Column("load_1", sa.Float(), nullable=False),
        sa.Column("load_5", sa.Float(), nullable=False),
        sa.Column("load_15", sa.Float(), nullable=False),
        sa.Column("net_rx_bps", sa.Float(), nullable=False),
        sa.Column("net_tx_bps", sa.Float(), nullable=False),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["servers.id"],
            name=op.f("metric_samples_server_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("metric_samples_pkey")),
    )
    op.create_index(
        "metric_samples_server_id_ts_idx", "metric_samples", ["server_id", "ts"]
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("metric_samples_server_id_ts_idx", table_name="metric_samples")
    op.drop_table("metric_samples")
    op.drop_index(
        op.f("enrollment_tokens_server_id_idx"), table_name="enrollment_tokens"
    )
    op.drop_table("enrollment_tokens")
    op.drop_table("servers")
