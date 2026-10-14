"""backup settings, policies and runs; stale-backup alert rule

Revision ID: 7f3a1e9c5b28
Revises: 4b9e2c7d1a65
Create Date: 2026-10-15 07:00:00.000000

"""
import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '7f3a1e9c5b28'
down_revision: str | Sequence[str] | None = '4b9e2c7d1a65'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "backup_settings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("encryption_key", sa.Text(), nullable=False),
        sa.Column("storage_enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("endpoint", sa.String(length=300), nullable=True),
        sa.Column("region", sa.String(length=40), nullable=True),
        sa.Column("bucket", sa.String(length=63), nullable=True),
        sa.Column("prefix", sa.String(length=200), nullable=True),
        sa.Column("access_key", sa.Text(), nullable=True),
        sa.Column("secret_key", sa.Text(), nullable=True),
        sa.Column("keep_local", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "backup_policies",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("instance_id", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("every_hours", sa.Integer(), server_default="24", nullable=False),
        sa.Column("keep", sa.Integer(), server_default="7", nullable=False),
        sa.Column("databases", sa.JSON(), nullable=False),
        sa.Column("next_run_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["instance_id"], ["database_instances.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("instance_id", name=op.f("backup_policies_instance_id_key")),
    )
    op.create_table(
        "backup_runs",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("instance_id", sa.String(length=32), nullable=False),
        sa.Column("database", sa.String(length=63), nullable=False),
        sa.Column("trigger", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("job_id", sa.String(length=32), nullable=True),
        sa.Column("path", sa.String(length=500), nullable=True),
        sa.Column("remote_key", sa.String(length=500), nullable=True),
        sa.Column("size", sa.BigInteger(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.Column("verify_status", sa.String(length=16), nullable=True),
        sa.Column("verify_detail", sa.String(length=300), nullable=True),
        sa.Column("verified_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["instance_id"], ["database_instances.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("backup_runs_instance_id_idx", "backup_runs", ["instance_id"], unique=False)

    bind = op.get_bind()
    has_rules = bind.execute(sa.text("SELECT COUNT(*) FROM alert_rules")).scalar()
    has_rule = bind.execute(sa.text("SELECT COUNT(*) FROM alert_rules WHERE kind = 'backup_stale'")).scalar()
    if has_rules and not has_rule:
        bind.execute(
            sa.text(
                "INSERT INTO alert_rules (id, kind, name, threshold, duration_minutes, severity, enabled, notify_email) "
                "VALUES (:id, 'backup_stale', 'Backups stale or failing', 36, 0, 'warning', true, true)"
            ),
            {"id": uuid.uuid4().hex},
        )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DELETE FROM alert_rules WHERE kind = 'backup_stale'")
    op.drop_index("backup_runs_instance_id_idx", table_name="backup_runs")
    op.drop_table("backup_runs")
    op.drop_table("backup_policies")
    op.drop_table("backup_settings")
