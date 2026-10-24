"""release commands, per-app usage, security checks, domain protection,
status pages, weekly reports, error groups, previews

Revision ID: 7d5b2f8e3a14
Revises: 1a7f3c9e5b28
Create Date: 2026-10-24 10:00:00.000000

"""
from collections.abc import Sequence

import json

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '7d5b2f8e3a14'
down_revision: str | Sequence[str] | None = '1a7f3c9e5b28'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("applications", sa.Column("release_command", sa.String(length=500), nullable=True))
    op.add_column("applications", sa.Column("private_port", sa.Boolean(), server_default=sa.false(), nullable=False))
    op.add_column("applications", sa.Column("preview_domain", sa.String(length=200), nullable=True))
    op.add_column("applications", sa.Column("preview_env", sa.JSON(), nullable=True))
    op.execute("UPDATE applications SET preview_env = '[]'")
    op.add_column("applications", sa.Column("preview_pr", sa.Integer(), nullable=True))
    with op.batch_alter_table("applications") as batch:
        batch.alter_column("preview_env", existing_type=sa.JSON(), nullable=False)
        batch.add_column(sa.Column("preview_of", sa.String(length=32), nullable=True))
        batch.create_foreign_key(
            "applications_preview_of_fkey", "applications", ["preview_of"], ["id"], ondelete="SET NULL"
        )
    op.create_index("applications_preview_of_idx", "applications", ["preview_of"])
    op.add_column("domains", sa.Column("access", sa.JSON(), nullable=True))
    op.execute("UPDATE domains SET access = '{}'")
    with op.batch_alter_table("domains") as batch:
        batch.alter_column("access", existing_type=sa.JSON(), nullable=False)
    op.add_column("platform_settings", sa.Column("weekly_report", sa.Boolean(), server_default=sa.true(), nullable=False))
    op.add_column("platform_settings", sa.Column("report_timezone", sa.String(length=64), server_default="UTC", nullable=False))
    op.add_column("platform_settings", sa.Column("weekly_report_at", sa.TIMESTAMP(timezone=True), nullable=True))
    op.add_column("notification_settings", sa.Column("email_weekly", sa.Boolean(), server_default=sa.true(), nullable=False))
    # Channels that get alerts get the weekly report too.
    bind = op.get_bind()
    for row_id, events in bind.execute(sa.text("SELECT id, events FROM alert_channels")).all():
        events = json.loads(events) if isinstance(events, str) else (events or [])
        if "alert.firing" in events and "report.weekly" not in events:
            bind.execute(
                sa.text("UPDATE alert_channels SET events = :events WHERE id = :id"),
                {"events": json.dumps([*events, "report.weekly"]), "id": row_id},
            )
    op.create_table(
        "app_moves",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("application_id", sa.String(length=32), nullable=False),
        sa.Column("source_server_id", sa.String(length=32), nullable=False),
        sa.Column("target_server_id", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("step", sa.String(length=16), nullable=False),
        sa.Column("include_files", sa.Boolean(), nullable=False),
        sa.Column("state", sa.JSON(), nullable=False),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("app_moves_application_id_idx", "app_moves", ["application_id"])
    op.create_table(
        "error_groups",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("application_id", sa.String(length=32), nullable=False),
        sa.Column("fingerprint", sa.String(length=16), nullable=False),
        sa.Column("sample", sa.Text(), nullable=False),
        sa.Column("total", sa.BigInteger(), nullable=False),
        sa.Column("daily", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("last_seen", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("ignored", sa.Boolean(), server_default="false", nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("error_groups_application_id_fingerprint_idx", "error_groups", ["application_id", "fingerprint"], unique=True)
    op.create_table(
        "status_pages",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("slug", sa.String(length=40), nullable=False),
        sa.Column("title", sa.String(length=80), nullable=False),
        sa.Column("description", sa.String(length=300), nullable=True),
        sa.Column("components", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug", name="status_pages_slug_key"),
    )
    op.create_table(
        "app_usage_samples",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), autoincrement=True, nullable=False),
        sa.Column("application_id", sa.String(length=32), nullable=False),
        sa.Column("ts", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("cpu_percent", sa.Float(), nullable=False),
        sa.Column("memory_bytes", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("app_usage_samples_application_id_ts_idx", "app_usage_samples", ["application_id", "ts"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("app_usage_samples_application_id_ts_idx", table_name="app_usage_samples")
    op.drop_table("app_usage_samples")
    op.drop_table("status_pages")
    op.drop_index("app_moves_application_id_idx", table_name="app_moves")
    op.drop_table("app_moves")
    op.drop_index("error_groups_application_id_fingerprint_idx", table_name="error_groups")
    op.drop_table("error_groups")
    op.drop_column("notification_settings", "email_weekly")
    op.drop_column("platform_settings", "weekly_report_at")
    op.drop_column("platform_settings", "report_timezone")
    op.drop_column("platform_settings", "weekly_report")
    op.drop_column("domains", "access")
    op.drop_index("applications_preview_of_idx", table_name="applications")
    with op.batch_alter_table("applications") as batch:
        batch.drop_constraint("applications_preview_of_fkey", type_="foreignkey")
        batch.drop_column("preview_of")
    op.drop_column("applications", "preview_pr")
    op.drop_column("applications", "preview_env")
    op.drop_column("applications", "preview_domain")
    op.drop_column("applications", "private_port")
    op.drop_column("applications", "release_command")
