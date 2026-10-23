"""scheduled jobs per app

Revision ID: 4e8c2a6f1d97
Revises: 9b3d7e1a4c62
Create Date: 2026-10-23 16:00:00.000000

"""
import json
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '4e8c2a6f1d97'
down_revision: str | Sequence[str] | None = '9b3d7e1a4c62'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "app_cron_jobs",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("application_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=60), nullable=False),
        sa.Column("schedule", sa.String(length=100), nullable=False),
        sa.Column("timezone", sa.String(length=64), server_default="UTC", nullable=False),
        sa.Column("command", sa.String(length=500), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("timeout_minutes", sa.Integer(), server_default="60", nullable=False),
        sa.Column("next_run_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=16), nullable=True),
        sa.Column("last_error", sa.String(length=300), nullable=True),
        sa.Column("last_job_id", sa.String(length=32), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("app_cron_jobs_application_id_idx", "app_cron_jobs", ["application_id"])

    # Channels told about failed deploys hear about failed scheduled jobs too.
    bind = op.get_bind()
    for row_id, events in bind.execute(sa.text("SELECT id, events FROM alert_channels")).all():
        events = json.loads(events) if isinstance(events, str) else (events or [])
        if "deployment.failed" in events and "job.failed" not in events:
            bind.execute(
                sa.text("UPDATE alert_channels SET events = :events WHERE id = :id"),
                {"events": json.dumps([*events, "job.failed"]), "id": row_id},
            )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("app_cron_jobs_application_id_idx", table_name="app_cron_jobs")
    op.drop_table("app_cron_jobs")
