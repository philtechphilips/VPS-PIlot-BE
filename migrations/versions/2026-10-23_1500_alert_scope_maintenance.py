"""alert snooze, maintenance windows, per-app rules and error ignore lists

Revision ID: 9b3d7e1a4c62
Revises: 6c1e4a9f7d23
Create Date: 2026-10-23 15:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '9b3d7e1a4c62'
down_revision: str | Sequence[str] | None = '6c1e4a9f7d23'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("alerts", sa.Column("snoozed_until", sa.TIMESTAMP(timezone=True), nullable=True))
    with op.batch_alter_table("alert_rules") as batch:
        batch.add_column(sa.Column("application_id", sa.String(length=32), nullable=True))
        batch.create_foreign_key(
            "alert_rules_application_id_fkey", "applications",
            ["application_id"], ["id"], ondelete="CASCADE",
        )
    op.add_column("applications", sa.Column("error_ignore", sa.JSON(), nullable=True))
    op.execute("UPDATE applications SET error_ignore = '[]'")
    with op.batch_alter_table("applications") as batch:
        batch.alter_column("error_ignore", existing_type=sa.JSON(), nullable=False)
    op.create_table(
        "maintenance_windows",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("server_id", sa.String(length=32), nullable=True),
        sa.Column("application_id", sa.String(length=32), nullable=True),
        sa.Column("starts_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("ends_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("reason", sa.String(length=200), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["server_id"], ["servers.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("maintenance_windows_ends_at_idx", "maintenance_windows", ["ends_at"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("maintenance_windows_ends_at_idx", table_name="maintenance_windows")
    op.drop_table("maintenance_windows")
    op.drop_column("applications", "error_ignore")
    with op.batch_alter_table("alert_rules") as batch:
        batch.drop_constraint("alert_rules_application_id_fkey", type_="foreignkey")
        batch.drop_column("application_id")
    op.drop_column("alerts", "snoozed_until")
