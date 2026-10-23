"""app errors: error lines per app and minute, and the alert rule for them

Revision ID: 2b7f4d9e1c58
Revises: 7e3b9d1f5a26
Create Date: 2026-10-23 10:00:00.000000

"""
import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '2b7f4d9e1c58'
down_revision: str | Sequence[str] | None = '7e3b9d1f5a26'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "app_error_metrics",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("application_id", sa.String(length=32), nullable=False),
        sa.Column("minute", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("errors", sa.Integer(), nullable=False),
        sa.Column("sample", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["application_id"], ["applications.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "app_error_metrics_application_id_minute_idx",
        "app_error_metrics",
        ["application_id", "minute"],
        unique=True,
    )

    # Installs that already have their rules get the new one too.
    bind = op.get_bind()
    has_rules = bind.execute(sa.text("SELECT COUNT(*) FROM alert_rules")).scalar()
    has_rule = bind.execute(sa.text("SELECT COUNT(*) FROM alert_rules WHERE kind = 'app_errors'")).scalar()
    if has_rules and not has_rule:
        bind.execute(
            sa.text(
                "INSERT INTO alert_rules (id, kind, name, threshold, duration_minutes, severity, enabled, notify_email) "
                "VALUES (:id, 'app_errors', 'App logging errors', 1, 5, 'warning', true, true)"
            ),
            {"id": uuid.uuid4().hex},
        )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DELETE FROM alert_rules WHERE kind = 'app_errors'")
    op.drop_index("app_error_metrics_application_id_minute_idx", table_name="app_error_metrics")
    op.drop_table("app_error_metrics")
