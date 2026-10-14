"""github app, installations and repo links on applications

Revision ID: 9e4b1d7a3c26
Revises: 6d2a8c4e1f57
Create Date: 2026-10-14 20:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '9e4b1d7a3c26'
down_revision: str | Sequence[str] | None = '6d2a8c4e1f57'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "github_apps",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("app_id", sa.BigInteger(), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("owner_login", sa.String(length=100), nullable=False),
        sa.Column("owner_type", sa.String(length=16), nullable=False),
        sa.Column("html_url", sa.String(length=300), nullable=False),
        sa.Column("client_id", sa.String(length=100), nullable=False),
        sa.Column("client_secret", sa.Text(), nullable=False),
        sa.Column("private_key", sa.Text(), nullable=False),
        sa.Column("webhook_secret", sa.Text(), nullable=True),
        sa.Column("webhook_url", sa.String(length=300), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("app_id", name=op.f("github_apps_app_id_key")),
    )
    op.create_table(
        "github_installations",
        sa.Column("id", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("github_app_id", sa.String(length=32), nullable=False),
        sa.Column("account_login", sa.String(length=100), nullable=False),
        sa.Column("account_type", sa.String(length=16), nullable=False),
        sa.Column("account_avatar_url", sa.String(length=300), nullable=True),
        sa.Column("repository_selection", sa.String(length=16), nullable=False),
        sa.Column("suspended_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["github_app_id"], ["github_apps.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("github_installations_github_app_id_idx"), "github_installations", ["github_app_id"], unique=False)

    with op.batch_alter_table("applications") as batch:
        batch.add_column(sa.Column("github_installation_id", sa.BigInteger(), nullable=True))
        batch.add_column(sa.Column("github_repo_id", sa.BigInteger(), nullable=True))
        batch.add_column(sa.Column("github_repo_full_name", sa.String(length=200), nullable=True))
        batch.add_column(sa.Column("auto_deploy", sa.Boolean(), server_default="false", nullable=False))
        batch.create_index(batch.f("applications_github_repo_id_idx"), ["github_repo_id"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("applications") as batch:
        batch.drop_index(batch.f("applications_github_repo_id_idx"))
        batch.drop_column("auto_deploy")
        batch.drop_column("github_repo_full_name")
        batch.drop_column("github_repo_id")
        batch.drop_column("github_installation_id")
    op.drop_index(op.f("github_installations_github_app_id_idx"), table_name="github_installations")
    op.drop_table("github_installations")
    op.drop_table("github_apps")
