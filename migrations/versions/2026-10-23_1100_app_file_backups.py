"""app file backups: a data folder for Docker apps, backups of app files

Revision ID: 5d2a8c6e3f71
Revises: 2b7f4d9e1c58
Create Date: 2026-10-23 11:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '5d2a8c6e3f71'
down_revision: str | Sequence[str] | None = '2b7f4d9e1c58'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("applications", sa.Column("data_path", sa.String(length=200), nullable=True))
    with op.batch_alter_table("backup_policies") as batch:
        batch.alter_column("instance_id", existing_type=sa.String(length=32), nullable=True)
        batch.add_column(sa.Column("application_id", sa.String(length=32), nullable=True))
        batch.create_foreign_key(
            "backup_policies_application_id_fkey", "applications",
            ["application_id"], ["id"], ondelete="CASCADE",
        )
        batch.create_unique_constraint("backup_policies_application_id_key", ["application_id"])
    with op.batch_alter_table("backup_runs") as batch:
        batch.alter_column("instance_id", existing_type=sa.String(length=32), nullable=True)
        batch.add_column(sa.Column("application_id", sa.String(length=32), nullable=True))
        batch.create_foreign_key(
            "backup_runs_application_id_fkey", "applications",
            ["application_id"], ["id"], ondelete="CASCADE",
        )
    op.create_index("backup_runs_application_id_idx", "backup_runs", ["application_id"])


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DELETE FROM backup_runs WHERE application_id IS NOT NULL")
    op.execute("DELETE FROM backup_policies WHERE application_id IS NOT NULL")
    op.drop_index("backup_runs_application_id_idx", table_name="backup_runs")
    with op.batch_alter_table("backup_runs") as batch:
        batch.drop_constraint("backup_runs_application_id_fkey", type_="foreignkey")
        batch.drop_column("application_id")
        batch.alter_column("instance_id", existing_type=sa.String(length=32), nullable=False)
    with op.batch_alter_table("backup_policies") as batch:
        batch.drop_constraint("backup_policies_application_id_key", type_="unique")
        batch.drop_constraint("backup_policies_application_id_fkey", type_="foreignkey")
        batch.drop_column("application_id")
        batch.alter_column("instance_id", existing_type=sa.String(length=32), nullable=False)
    op.drop_column("applications", "data_path")
