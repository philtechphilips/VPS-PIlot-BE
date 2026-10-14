"""database instances, credentials and queries

Revision ID: 8a2d6f1c4e93
Revises: 5c1e7b3a9d48
Create Date: 2026-10-15 03:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '8a2d6f1c4e93'
down_revision: str | Sequence[str] | None = '5c1e7b3a9d48'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "database_instances",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=40), nullable=False),
        sa.Column("engine", sa.String(length=16), nullable=False),
        sa.Column("version", sa.String(length=16), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("server_id", sa.String(length=32), nullable=False),
        sa.Column("host", sa.String(length=253), nullable=True),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("admin_user", sa.String(length=63), nullable=True),
        sa.Column("admin_password", sa.Text(), nullable=True),
        sa.Column("default_database", sa.String(length=63), nullable=True),
        sa.Column("local_port", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.Column("server_version", sa.String(length=200), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["server_id"], ["servers.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name=op.f("database_instances_name_key")),
    )
    op.create_index("database_instances_server_id_idx", "database_instances", ["server_id"], unique=False)
    op.create_table(
        "database_credentials",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("instance_id", sa.String(length=32), nullable=False),
        sa.Column("username", sa.String(length=63), nullable=False),
        sa.Column("password", sa.Text(), nullable=False),
        sa.Column("pending_password", sa.Text(), nullable=True),
        sa.Column("database", sa.String(length=63), nullable=True),
        sa.Column("access", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("application_id", sa.String(length=32), nullable=True),
        sa.Column("env_key", sa.String(length=128), nullable=True),
        sa.Column("job_id", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("rotated_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["instance_id"], ["database_instances.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("database_credentials_instance_id_idx", "database_credentials", ["instance_id"], unique=False)
    op.create_table(
        "database_queries",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("instance_id", sa.String(length=32), nullable=False),
        sa.Column("job_id", sa.String(length=32), nullable=True),
        sa.Column("sql", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(length=16), nullable=False),
        sa.Column("database", sa.String(length=63), nullable=True),
        sa.Column("readonly", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["instance_id"], ["database_instances.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("database_queries_instance_id_idx", "database_queries", ["instance_id"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("database_queries_instance_id_idx", table_name="database_queries")
    op.drop_table("database_queries")
    op.drop_index("database_credentials_instance_id_idx", table_name="database_credentials")
    op.drop_table("database_credentials")
    op.drop_index("database_instances_server_id_idx", table_name="database_instances")
    op.drop_table("database_instances")
