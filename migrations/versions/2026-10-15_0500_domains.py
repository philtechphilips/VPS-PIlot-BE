"""domains, and the certificate-expiry alert rule for existing installs

Revision ID: 4b9e2c7d1a65
Revises: 8a2d6f1c4e93
Create Date: 2026-10-15 05:00:00.000000

"""
import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '4b9e2c7d1a65'
down_revision: str | Sequence[str] | None = '8a2d6f1c4e93'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "domains",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("hostname", sa.String(length=253), nullable=False),
        sa.Column("server_id", sa.String(length=32), nullable=False),
        sa.Column("application_id", sa.String(length=32), nullable=True),
        sa.Column("redirect_to", sa.String(length=253), nullable=True),
        sa.Column("tls_mode", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.Column("apply_job_id", sa.String(length=32), nullable=True),
        sa.Column("dns_addresses", sa.JSON(), nullable=False),
        sa.Column("dns_status", sa.String(length=16), nullable=True),
        sa.Column("dns_checked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("cert_issuer", sa.String(length=120), nullable=True),
        sa.Column("cert_expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("cert_error", sa.String(length=300), nullable=True),
        sa.Column("cert_checked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["server_id"], ["servers.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("hostname", name=op.f("domains_hostname_key")),
    )
    op.create_index("domains_server_id_idx", "domains", ["server_id"], unique=False)
    op.create_index("domains_application_id_idx", "domains", ["application_id"], unique=False)

    # Installs that already have alert rules get the new one too (fresh
    # installs get it with the defaults).
    bind = op.get_bind()
    has_rules = bind.execute(sa.text("SELECT COUNT(*) FROM alert_rules")).scalar()
    has_tls = bind.execute(sa.text("SELECT COUNT(*) FROM alert_rules WHERE kind = 'tls_expiring'")).scalar()
    if has_rules and not has_tls:
        bind.execute(
            sa.text(
                "INSERT INTO alert_rules (id, kind, name, threshold, duration_minutes, severity, enabled, notify_email) "
                "VALUES (:id, 'tls_expiring', 'Certificate expiring', 14, 0, 'warning', true, true)"
            ),
            {"id": uuid.uuid4().hex},
        )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DELETE FROM alert_rules WHERE kind = 'tls_expiring'")
    op.drop_index("domains_application_id_idx", table_name="domains")
    op.drop_index("domains_server_id_idx", table_name="domains")
    op.drop_table("domains")
