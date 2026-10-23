"""the security updates pending alert rule

Revision ID: 6c1e4a9f7d23
Revises: 3f6b9d2e8a15
Create Date: 2026-10-23 14:00:00.000000

"""
import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '6c1e4a9f7d23'
down_revision: str | Sequence[str] | None = '3f6b9d2e8a15'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    has_rules = bind.execute(sa.text("SELECT COUNT(*) FROM alert_rules")).scalar()
    has_rule = bind.execute(sa.text("SELECT COUNT(*) FROM alert_rules WHERE kind = 'updates_pending'")).scalar()
    if has_rules and not has_rule:
        bind.execute(
            sa.text(
                "INSERT INTO alert_rules (id, kind, name, threshold, duration_minutes, severity, enabled, notify_email) "
                "VALUES (:id, 'updates_pending', 'Security updates pending', 1, 4320, 'warning', true, true)"
            ),
            {"id": uuid.uuid4().hex},
        )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DELETE FROM alert_rules WHERE kind = 'updates_pending'")
