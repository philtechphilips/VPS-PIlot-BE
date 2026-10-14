"""applications, deployments and job results

Revision ID: 2b7e9f4c1d83
Revises: 8c3f2a6d9b15
Create Date: 2026-10-14 14:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '2b7e9f4c1d83'
down_revision: str | Sequence[str] | None = '8c3f2a6d9b15'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("jobs") as batch:
        batch.add_column(sa.Column("result", sa.JSON(), nullable=True))
    op.execute("UPDATE jobs SET result = '{}' WHERE result IS NULL")
    with op.batch_alter_table("jobs") as batch:
        batch.alter_column("result", existing_type=sa.JSON(), nullable=False)

    op.create_table(
        "applications",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=40), nullable=False),
        sa.Column("server_id", sa.String(length=32), nullable=False),
        sa.Column("runtime", sa.String(length=16), server_default="docker", nullable=False),
        sa.Column("source_type", sa.String(length=8), nullable=False),
        sa.Column("repo_url", sa.String(length=500), nullable=True),
        sa.Column("branch", sa.String(length=200), nullable=True),
        sa.Column("dockerfile", sa.String(length=200), server_default="Dockerfile", nullable=False),
        sa.Column("build_context", sa.String(length=200), server_default=".", nullable=False),
        sa.Column("image", sa.String(length=300), nullable=True),
        sa.Column("container_port", sa.Integer(), nullable=False),
        sa.Column("host_port", sa.Integer(), nullable=False),
        sa.Column("health_path", sa.String(length=200), server_default="/", nullable=False),
        sa.Column("health_timeout_seconds", sa.Integer(), server_default="60", nullable=False),
        sa.Column("cpu_limit", sa.String(length=16), nullable=True),
        sa.Column("memory_limit", sa.String(length=16), nullable=True),
        sa.Column("env", sa.JSON(), nullable=False),
        sa.Column("current_deployment_id", sa.String(length=32), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["servers.id"],
            name=op.f("applications_server_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("applications_pkey")),
        sa.UniqueConstraint("name", name=op.f("applications_name_key")),
    )
    op.create_index(op.f("applications_server_id_idx"), "applications", ["server_id"])

    op.create_table(
        "deployments",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("application_id", sa.String(length=32), nullable=False),
        sa.Column("server_id", sa.String(length=32), nullable=False),
        sa.Column("job_id", sa.String(length=32), nullable=True),
        sa.Column("status", sa.String(length=16), server_default="queued", nullable=False),
        sa.Column("trigger", sa.String(length=16), nullable=False),
        sa.Column("requested_ref", sa.String(length=200), nullable=True),
        sa.Column("commit_sha", sa.String(length=40), nullable=True),
        sa.Column("commit_message", sa.String(length=300), nullable=True),
        sa.Column("image_ref", sa.String(length=300), nullable=True),
        sa.Column("rollback_of", sa.String(length=32), nullable=True),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("spec", sa.JSON(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["application_id"],
            ["applications.id"],
            name=op.f("deployments_application_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("deployments_pkey")),
    )
    op.create_index(
        "deployments_application_id_created_at_idx",
        "deployments",
        ["application_id", "created_at"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("deployments_application_id_created_at_idx", table_name="deployments")
    op.drop_table("deployments")
    op.drop_index(op.f("applications_server_id_idx"), table_name="applications")
    op.drop_table("applications")
    with op.batch_alter_table("jobs") as batch:
        batch.drop_column("result")
