from datetime import datetime

from sqlalchemy import TIMESTAMP, ForeignKey, String, Text, func, true
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class DatabaseInstance(Base):
    """A database VPSPilot runs (managed: a vpdb-<name> container) or one
    you already had (external: reached from the server by host and port)."""

    __tablename__ = "database_instances"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(40), unique=True)
    engine: Mapped[str] = mapped_column(String(16))  # postgres|mysql|mariadb|redis
    version: Mapped[str] = mapped_column(String(16))
    mode: Mapped[str] = mapped_column(String(16))  # managed | external
    server_id: Mapped[str] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), index=True
    )
    host: Mapped[str | None] = mapped_column(String(253))  # external only
    port: Mapped[int]
    admin_user: Mapped[str | None] = mapped_column(String(63))
    admin_password: Mapped[str | None] = mapped_column(Text)  # encrypted
    default_database: Mapped[str | None] = mapped_column(String(63))
    local_port: Mapped[int | None]  # managed: published on 127.0.0.1 only
    # creating | running | stopped | error | removing | checking
    status: Mapped[str] = mapped_column(String(16))
    error: Mapped[str | None] = mapped_column(String(500))
    server_version: Mapped[str | None] = mapped_column(String(200))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )


class DatabaseCredential(Base):
    """A login VPSPilot created (for an app, or by hand). Passwords are
    encrypted; a rotation keeps the old one until the new one is applied."""

    __tablename__ = "database_credentials"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    instance_id: Mapped[str] = mapped_column(
        ForeignKey("database_instances.id", ondelete="CASCADE"), index=True
    )
    username: Mapped[str] = mapped_column(String(63))
    password: Mapped[str] = mapped_column(Text)  # encrypted
    pending_password: Mapped[str | None] = mapped_column(Text)  # encrypted
    database: Mapped[str | None] = mapped_column(String(63))
    access: Mapped[str] = mapped_column(String(16))  # owner | readwrite | readonly
    status: Mapped[str] = mapped_column(String(16))  # pending | active
    # Set when created for an app: its env var is filled in once it exists.
    application_id: Mapped[str | None] = mapped_column(String(32))
    env_key: Mapped[str | None] = mapped_column(String(128))
    job_id: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    rotated_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))


class DatabaseQuery(Base):
    """A query run from the editor. The SQL is encrypted (it can hold
    secrets); the audit log gets only a fingerprint."""

    __tablename__ = "database_queries"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    instance_id: Mapped[str] = mapped_column(
        ForeignKey("database_instances.id", ondelete="CASCADE"), index=True
    )
    job_id: Mapped[str | None] = mapped_column(String(32))
    sql: Mapped[str] = mapped_column(Text)  # encrypted
    fingerprint: Mapped[str] = mapped_column(String(16))
    database: Mapped[str | None] = mapped_column(String(63))
    readonly: Mapped[bool] = mapped_column(server_default=true())
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
