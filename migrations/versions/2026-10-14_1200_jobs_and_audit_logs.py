"""jobs, job events and audit logs

Revision ID: 8c3f2a6d9b15
Revises: 5a91c0d2e7f4
Create Date: 2026-10-14 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '8c3f2a6d9b15'
down_revision: str | Sequence[str] | None = '5a91c0d2e7f4'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

BIGINT_PK = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "audit_logs",
        sa.Column("id", BIGINT_PK, nullable=False),
        sa.Column("actor", sa.String(length=64), nullable=False),
        sa.Column("actor_label", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=True),
        sa.Column("target_id", sa.String(length=64), nullable=True),
        sa.Column("target_label", sa.String(length=255), nullable=True),
        sa.Column("result", sa.String(length=16), nullable=False),
        sa.Column("detail", sa.String(length=500), nullable=True),
        sa.Column("correlation_id", sa.String(length=32), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("audit_logs_pkey")),
    )
    op.create_index("audit_logs_created_at_idx", "audit_logs", ["created_at"])

    op.create_table(
        "jobs",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("server_id", sa.String(length=32), nullable=False),
        sa.Column("type", sa.String(length=40), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default="queued", nullable=False
        ),
        sa.Column("idempotency_key", sa.String(length=64), nullable=True),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("correlation_id", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["servers.id"],
            name=op.f("jobs_server_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("jobs_pkey")),
        sa.UniqueConstraint(
            "server_id", "idempotency_key", name="jobs_server_id_idempotency_key_key"
        ),
    )
    op.create_index("jobs_server_id_status_idx", "jobs", ["server_id", "status"])

    op.create_table(
        "job_events",
        sa.Column("id", BIGINT_PK, nullable=False),
        sa.Column("job_id", sa.String(length=32), nullable=False),
        sa.Column("level", sa.String(length=8), nullable=False),
        sa.Column("message", sa.String(length=2000), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["jobs.id"],
            name=op.f("job_events_job_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("job_events_pkey")),
    )
    op.create_index(op.f("job_events_job_id_idx"), "job_events", ["job_id"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("job_events_job_id_idx"), table_name="job_events")
    op.drop_table("job_events")
    op.drop_index("jobs_server_id_status_idx", table_name="jobs")
    op.drop_table("jobs")
    op.drop_index("audit_logs_created_at_idx", table_name="audit_logs")
    op.drop_table("audit_logs")
