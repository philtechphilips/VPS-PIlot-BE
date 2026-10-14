"""backup storage providers: Google Drive, and where each backup lives

Revision ID: 7e3b9d1f5a26
Revises: 4c8a2e6f9b13
Create Date: 2026-10-16 15:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '7e3b9d1f5a26'
down_revision: str | Sequence[str] | None = '4c8a2e6f9b13'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "backup_settings",
        sa.Column("provider", sa.String(length=16), server_default="s3", nullable=False),
    )
    for name, kind in (
        ("gdrive_client_id", sa.String(length=200)),
        ("gdrive_client_secret", sa.Text()),
        ("gdrive_refresh_token", sa.Text()),
        ("gdrive_account", sa.String(length=200)),
        ("gdrive_folder_id", sa.String(length=200)),
    ):
        op.add_column("backup_settings", sa.Column(name, kind, nullable=True))
    op.add_column(
        "backup_runs", sa.Column("storage", sa.String(length=16), nullable=True)
    )
    # Remote copies made so far are all in S3-compatible storage.
    op.execute("UPDATE backup_runs SET storage = 's3' WHERE remote_key IS NOT NULL")


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("backup_runs", "storage")
    for name in (
        "gdrive_folder_id",
        "gdrive_account",
        "gdrive_refresh_token",
        "gdrive_client_secret",
        "gdrive_client_id",
        "provider",
    ):
        op.drop_column("backup_settings", name)
