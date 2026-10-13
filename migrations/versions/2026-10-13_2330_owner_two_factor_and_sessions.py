"""owner profile, email two-factor and sessions

Revision ID: 7d1c4e9a2b30
Revises: 2150c6fd6d33
Create Date: 2026-10-13 23:30:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '7d1c4e9a2b30'
down_revision: str | Sequence[str] | None = '2150c6fd6d33'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("name", sa.String(length=120), nullable=True))
        batch.add_column(
            sa.Column(
                "two_factor_enabled",
                sa.Boolean(),
                server_default=sa.true(),
                nullable=False,
            )
        )
        batch.add_column(
            sa.Column("email_verified_at", sa.TIMESTAMP(timezone=True), nullable=True)
        )
        batch.add_column(
            sa.Column(
                "failed_login_attempts",
                sa.Integer(),
                server_default="0",
                nullable=False,
            )
        )
        batch.add_column(
            sa.Column("locked_until", sa.TIMESTAMP(timezone=True), nullable=True)
        )

    op.create_table(
        "two_factor_challenges",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("purpose", sa.String(length=20), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("last_sent_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("two_factor_challenges_user_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("two_factor_challenges_pkey")),
    )
    op.create_index(
        op.f("two_factor_challenges_user_id_idx"),
        "two_factor_challenges",
        ["user_id"],
    )

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("refresh_token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "last_used_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("auth_sessions_user_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("auth_sessions_pkey")),
        sa.UniqueConstraint(
            "refresh_token_hash", name=op.f("auth_sessions_refresh_token_hash_key")
        ),
    )
    op.create_index(
        op.f("auth_sessions_user_id_idx"), "auth_sessions", ["user_id"]
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("auth_sessions_user_id_idx"), table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_index(
        op.f("two_factor_challenges_user_id_idx"), table_name="two_factor_challenges"
    )
    op.drop_table("two_factor_challenges")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("locked_until")
        batch.drop_column("failed_login_attempts")
        batch.drop_column("email_verified_at")
        batch.drop_column("two_factor_enabled")
        batch.drop_column("name")
