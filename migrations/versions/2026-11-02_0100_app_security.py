"""app vulnerability scans and findings, security alert rules, weekly
rebuilds, the security channel event

Revision ID: 4c8e1a6d9f20
Revises: 7d5b2f8e3a14
Create Date: 2026-11-02 01:00:00.000000

"""
import json
import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '4c8e1a6d9f20'
down_revision: str | Sequence[str] | None = '7d5b2f8e3a14'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# kind, name, threshold, duration (minutes), severity: as in monitoring.KINDS
NEW_RULES = [
    ("vulnerable_deps", "Vulnerable dependencies", 1, 0, "warning"),
    ("secrets_committed", "Secrets in the repository", None, 0, "warning"),
    ("runtime_eol", "Runtime end of life", 30, 0, "warning"),
    ("agent_outdated", "Agent out of date", None, 4320, "info"),
]


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "app_scans",
        sa.Column("application_id", sa.String(length=32), nullable=False),
        sa.Column("scanned_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("checked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("check_error", sa.String(length=300), nullable=True),
        sa.Column("packages", sa.JSON(), nullable=False),
        sa.Column("lockfiles", sa.JSON(), nullable=False),
        sa.Column("os_ecosystem", sa.String(length=40), nullable=True),
        sa.Column("os_id", sa.String(length=20), nullable=True),
        sa.Column("os_version", sa.String(length=20), nullable=True),
        sa.Column("os_packages", sa.JSON(), nullable=False),
        sa.Column("secrets", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["application_id"], ["applications.id"],
            name="app_scans_application_id_fkey", ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("application_id", name="app_scans_pkey"),
    )
    op.create_table(
        "app_findings",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("application_id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=12), nullable=False),
        sa.Column("key", sa.String(length=300), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("ecosystem", sa.String(length=40), nullable=True),
        sa.Column("package", sa.String(length=214), nullable=True),
        sa.Column("version", sa.String(length=80), nullable=True),
        sa.Column("fixed", sa.String(length=80), nullable=True),
        sa.Column("advisory", sa.String(length=80), nullable=True),
        sa.Column("aliases", sa.JSON(), nullable=False),
        sa.Column("path", sa.String(length=300), nullable=True),
        sa.Column("eol_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("first_seen_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("ignored_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("ignored_by", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(
            ["application_id"], ["applications.id"],
            name="app_findings_application_id_fkey", ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="app_findings_pkey"),
    )
    op.create_index("app_findings_application_id_idx", "app_findings", ["application_id"])
    op.create_index("app_findings_application_id_key_idx", "app_findings", ["application_id", "key"])
    op.create_table(
        "security_cache",
        sa.Column("key", sa.String(length=120), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("fetched_at", sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("key", name="security_cache_pkey"),
    )
    op.add_column("applications", sa.Column("auto_rebuild", sa.Boolean(), server_default=sa.false(), nullable=False))
    op.add_column("platform_settings", sa.Column("vuln_checks", sa.Boolean(), server_default=sa.true(), nullable=False))

    bind = op.get_bind()
    # Installs that already have rules get the new ones too (fresh installs
    # create every default rule on first use).
    kinds = {row[0] for row in bind.execute(sa.text("SELECT kind FROM alert_rules"))}
    if kinds:
        rules = sa.table(
            "alert_rules",
            sa.column("id", sa.String), sa.column("kind", sa.String), sa.column("name", sa.String),
            sa.column("threshold", sa.Float), sa.column("duration_minutes", sa.Integer),
            sa.column("severity", sa.String), sa.column("enabled", sa.Boolean),
            sa.column("notify_email", sa.Boolean),
        )
        op.bulk_insert(rules, [
            {"id": uuid.uuid4().hex, "kind": kind, "name": name, "threshold": threshold,
             "duration_minutes": duration, "severity": severity, "enabled": True, "notify_email": True}
            for kind, name, threshold, duration, severity in NEW_RULES
            if kind not in kinds
        ])
    # Existing alert channels hear about security events too.
    for channel_id, events in bind.execute(sa.text("SELECT id, events FROM alert_channels")).all():
        current = json.loads(events) if isinstance(events, str) else (events or [])
        if "security" not in current:
            bind.execute(
                sa.text("UPDATE alert_channels SET events = :events WHERE id = :id"),
                {"events": json.dumps([*current, "security"]), "id": channel_id},
            )


def downgrade() -> None:
    """Downgrade schema."""
    bind = op.get_bind()
    for channel_id, events in bind.execute(sa.text("SELECT id, events FROM alert_channels")).all():
        current = json.loads(events) if isinstance(events, str) else (events or [])
        bind.execute(
            sa.text("UPDATE alert_channels SET events = :events WHERE id = :id"),
            {"events": json.dumps([e for e in current if e != "security"]), "id": channel_id},
        )
    kinds = ", ".join(f"'{kind}'" for kind, *_ in NEW_RULES)
    op.execute(f"DELETE FROM alerts WHERE rule_id IN (SELECT id FROM alert_rules WHERE kind IN ({kinds}))")
    op.execute(f"DELETE FROM alert_rules WHERE kind IN ({kinds})")
    op.drop_column("platform_settings", "vuln_checks")
    op.drop_column("applications", "auto_rebuild")
    op.drop_table("security_cache")
    op.drop_index("app_findings_application_id_key_idx", table_name="app_findings")
    op.drop_index("app_findings_application_id_idx", table_name="app_findings")
    op.drop_table("app_findings")
    op.drop_table("app_scans")
