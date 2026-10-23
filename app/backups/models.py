from datetime import datetime
from typing import Any

from sqlalchemy import JSON, TIMESTAMP, BigInteger, ForeignKey, String, Text, func, true
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class BackupSettings(Base):
    """One row: the encryption key for backups and the optional off-host
    S3-compatible storage. Secrets are encrypted at rest."""

    __tablename__ = "backup_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    encryption_key: Mapped[str] = mapped_column(Text)  # encrypted
    storage_enabled: Mapped[bool] = mapped_column(server_default="false")
    endpoint: Mapped[str | None] = mapped_column(String(300))
    region: Mapped[str | None] = mapped_column(String(40))
    bucket: Mapped[str | None] = mapped_column(String(63))
    prefix: Mapped[str | None] = mapped_column(String(200))
    access_key: Mapped[str | None] = mapped_column(Text)  # encrypted
    secret_key: Mapped[str | None] = mapped_column(Text)  # encrypted
    keep_local: Mapped[bool] = mapped_column(server_default=true())
    # Where off-host copies go: "s3" (any S3-compatible service) or "gdrive".
    provider: Mapped[str] = mapped_column(String(16), server_default="s3")
    # Google Drive through the owner's OAuth client (drive.file scope).
    gdrive_client_id: Mapped[str | None] = mapped_column(String(200))
    gdrive_client_secret: Mapped[str | None] = mapped_column(Text)  # encrypted
    gdrive_refresh_token: Mapped[str | None] = mapped_column(Text)  # encrypted
    gdrive_account: Mapped[str | None] = mapped_column(String(200))
    gdrive_folder_id: Mapped[str | None] = mapped_column(String(200))
    updated_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))


class BackupPolicy(Base):
    """Scheduled backups of one database instance, or of one app's files."""

    __tablename__ = "backup_policies"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    instance_id: Mapped[str | None] = mapped_column(
        ForeignKey("database_instances.id", ondelete="CASCADE"), unique=True
    )
    application_id: Mapped[str | None] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), unique=True
    )
    enabled: Mapped[bool] = mapped_column(server_default=true())
    every_hours: Mapped[int] = mapped_column(server_default="24")
    keep: Mapped[int] = mapped_column(server_default="7")
    # Databases to back up; empty means the instance's default one(s).
    databases: Mapped[list[str]] = mapped_column(JSON, default=list)
    next_run_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )


class BackupRun(Base):
    """One backup of one database (or of a Redis instance), or of an app's
    files (application_id set, database "files")."""

    __tablename__ = "backup_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    instance_id: Mapped[str | None] = mapped_column(
        ForeignKey("database_instances.id", ondelete="CASCADE"), index=True
    )
    application_id: Mapped[str | None] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), index=True
    )
    database: Mapped[str] = mapped_column(String(63))  # "redis", "files"
    trigger: Mapped[str] = mapped_column(String(16))  # scheduled | manual
    status: Mapped[str] = mapped_column(String(16))  # queued|running|succeeded|failed
    job_id: Mapped[str | None] = mapped_column(String(32))
    path: Mapped[str | None] = mapped_column(String(500))
    remote_key: Mapped[str | None] = mapped_column(String(500))
    # Which storage holds remote_key (runs before this existed: S3).
    storage: Mapped[str | None] = mapped_column(String(16))
    size: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))
    error: Mapped[str | None] = mapped_column(String(500))
    verify_status: Mapped[str | None] = mapped_column(
        String(16)
    )  # passed | failed | running
    verify_detail: Mapped[str | None] = mapped_column(String(300))
    verified_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
