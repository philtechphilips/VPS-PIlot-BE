from datetime import datetime
from enum import StrEnum

from sqlalchemy import TIMESTAMP, Enum, String, func, true
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Role(StrEnum):
    USER = "user"
    ADMIN = "admin"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(unique=True)
    name: Mapped[str | None] = mapped_column(String(120))
    password: Mapped[str]
    # Stored as a plain string (not a Postgres ENUM type) so adding a role
    # later doesn't need a type migration.
    role: Mapped[Role] = mapped_column(
        Enum(
            Role,
            native_enum=False,
            length=20,
            values_callable=lambda roles: [role.value for role in roles],
        ),
        server_default=Role.USER.value,
    )
    # Email codes are required at sign-in unless this is turned off.
    two_factor_enabled: Mapped[bool] = mapped_column(server_default=true())
    # Set when the owner proves they can read the address (first 2FA code).
    email_verified_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    # Login throttling
    failed_login_attempts: Mapped[int] = mapped_column(server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )

    @property
    def email_verified(self) -> bool:
        return self.email_verified_at is not None
