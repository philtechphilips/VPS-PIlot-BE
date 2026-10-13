"""authenticator app (TOTP), recovery codes and onboarding

Revision ID: 3e8b5f1c7a42
Revises: 7d1c4e9a2b30
Create Date: 2026-10-14 09:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '3e8b5f1c7a42'
down_revision: str | Sequence[str] | None = '7d1c4e9a2b30'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Existing owners get onboarding_completed_at = NULL, so they are taken
    # through the remaining setup steps (authenticator, server) on next visit.
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("totp_secret", sa.String(length=255), nullable=True))
        batch.add_column(
            sa.Column("totp_enabled_at", sa.TIMESTAMP(timezone=True), nullable=True)
        )
        batch.add_column(sa.Column("totp_last_step", sa.Integer(), nullable=True))
        batch.add_column(
            sa.Column(
                "onboarding_completed_at", sa.TIMESTAMP(timezone=True), nullable=True
            )
        )

    with op.batch_alter_table("two_factor_challenges") as batch:
        batch.add_column(
            sa.Column(
                "method", sa.String(length=10), server_default="email", nullable=False
            )
        )
        batch.alter_column(
            "code_hash", existing_type=sa.String(length=64), nullable=True
        )

    op.create_table(
        "recovery_codes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("used_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("recovery_codes_user_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("recovery_codes_pkey")),
    )
    op.create_index(
        op.f("recovery_codes_user_id_idx"), "recovery_codes", ["user_id"]
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("recovery_codes_user_id_idx"), table_name="recovery_codes")
    op.drop_table("recovery_codes")
    # Rows without a code (TOTP challenges) can't satisfy NOT NULL again.
    op.execute("DELETE FROM two_factor_challenges WHERE code_hash IS NULL")
    with op.batch_alter_table("two_factor_challenges") as batch:
        batch.alter_column(
            "code_hash", existing_type=sa.String(length=64), nullable=False
        )
        batch.drop_column("method")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("onboarding_completed_at")
        batch.drop_column("totp_last_step")
        batch.drop_column("totp_enabled_at")
        batch.drop_column("totp_secret")
