"""uptime checks of domains, and the site down rule

Revision ID: 8a4e1f7c2b96
Revises: 5d2a8c6e3f71
Create Date: 2026-10-23 12:00:00.000000

"""
import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '8a4e1f7c2b96'
down_revision: str | Sequence[str] | None = '5d2a8c6e3f71'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "uptime_checks",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("domain_id", sa.String(length=32), nullable=False),
        sa.Column("ts", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("ms", sa.Float(), nullable=True),
        sa.Column("error", sa.String(length=200), nullable=True),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("uptime_checks_domain_id_ts_idx", "uptime_checks", ["domain_id", "ts"])

    bind = op.get_bind()
    has_rules = bind.execute(sa.text("SELECT COUNT(*) FROM alert_rules")).scalar()
    has_rule = bind.execute(sa.text("SELECT COUNT(*) FROM alert_rules WHERE kind = 'site_down'")).scalar()
    if has_rules and not has_rule:
        bind.execute(
            sa.text(
                "INSERT INTO alert_rules (id, kind, name, threshold, duration_minutes, severity, enabled, notify_email) "
                "VALUES (:id, 'site_down', 'Site down', NULL, 2, 'critical', true, true)"
            ),
            {"id": uuid.uuid4().hex},
        )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DELETE FROM alert_rules WHERE kind = 'site_down'")
    op.drop_index("uptime_checks_domain_id_ts_idx", table_name="uptime_checks")
    op.drop_table("uptime_checks")
