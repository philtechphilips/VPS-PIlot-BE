"""add roles and password reset tokens

Revision ID: 2150c6fd6d33
Revises: 685c64471cdc
Create Date: 2026-10-13 17:48:39.749191

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '2150c6fd6d33'
down_revision: str | Sequence[str] | None = '685c64471cdc'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Existing users get the default "user" role.
    op.add_column(
        "users",
        sa.Column(
            "role",
            sa.Enum("user", "admin", name="role", native_enum=False, length=20),
            server_default="user",
            nullable=False,
        ),
    )
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("password_reset_tokens_user_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("password_reset_tokens_pkey")),
        sa.UniqueConstraint(
            "token_hash", name=op.f("password_reset_tokens_token_hash_key")
        ),
    )
    op.create_index(
        op.f("password_reset_tokens_user_id_idx"),
        "password_reset_tokens",
        ["user_id"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(
        op.f("password_reset_tokens_user_id_idx"), table_name="password_reset_tokens"
    )
    op.drop_table("password_reset_tokens")
    op.drop_column("users", "role")
