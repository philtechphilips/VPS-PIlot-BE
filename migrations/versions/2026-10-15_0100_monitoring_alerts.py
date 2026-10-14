"""alert rules, alerts and alert email preference

Revision ID: 5c1e7b3a9d48
Revises: 3f8c2e6b9a14
Create Date: 2026-10-15 01:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '5c1e7b3a9d48'
down_revision: str | Sequence[str] | None = '3f8c2e6b9a14'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "alert_rules",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=True),
        sa.Column("duration_minutes", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("notify_email", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("server_id", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["server_id"], ["servers.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("rule_id", sa.String(length=32), nullable=False),
        sa.Column("target_type", sa.String(length=16), nullable=False),
        sa.Column("target_id", sa.String(length=32), nullable=False),
        sa.Column("target_label", sa.String(length=120), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("detail", sa.String(length=300), nullable=True),
        sa.Column("value", sa.Float(), nullable=True),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("fired_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("acknowledged_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(length=64), nullable=True),
        sa.Column("resolved_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["rule_id"], ["alert_rules.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("alerts_rule_id_target_id_state_idx", "alerts", ["rule_id", "target_id", "state"], unique=False)
    op.create_index("alerts_state_started_at_idx", "alerts", ["state", "started_at"], unique=False)
    with op.batch_alter_table("notification_settings") as batch:
        batch.add_column(sa.Column("email_alerts", sa.Boolean(), server_default=sa.true(), nullable=False))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("notification_settings") as batch:
        batch.drop_column("email_alerts")
    op.drop_index("alerts_state_started_at_idx", table_name="alerts")
    op.drop_index("alerts_rule_id_target_id_state_idx", table_name="alerts")
    op.drop_table("alerts")
    op.drop_table("alert_rules")
