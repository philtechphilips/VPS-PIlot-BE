from datetime import datetime
from typing import Any

from sqlalchemy import JSON, TIMESTAMP, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AppScan(Base):
    """What an app was last found to be made of (see agent audit.py)."""

    __tablename__ = "app_scans"

    application_id: Mapped[str] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True
    )
    scanned_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    # Last lookup against OSV.dev and end-of-life data (None: not yet).
    checked_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    check_error: Mapped[str | None] = mapped_column(String(300))
    # [[ecosystem, name, version]] from the lockfiles, and the files read.
    packages: Mapped[list[Any]] = mapped_column(JSON, default=list)
    lockfiles: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # The container's distro (Debian:12, Alpine:v3.20...) and its packages
    # as [[source package, version]].
    os_ecosystem: Mapped[str | None] = mapped_column(String(40))
    os_id: Mapped[str | None] = mapped_column(String(20))
    os_version: Mapped[str | None] = mapped_column(String(20))
    os_packages: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # [{"path", "line", "rule"}]: committed files that look like secrets.
    secrets: Mapped[list[Any]] = mapped_column(JSON, default=list)


class AppFinding(Base):
    """One problem found in an app. Rebuilt on every check; `key` carries
    first_seen_at and an ignore across checks."""

    __tablename__ = "app_findings"
    __table_args__ = (
        Index("app_findings_application_id_key_idx", "application_id", "key"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    application_id: Mapped[str] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), index=True
    )
    # dependency | os | secret | eol
    kind: Mapped[str] = mapped_column(String(12))
    key: Mapped[str] = mapped_column(String(300))
    # critical | high | medium | low | unknown
    severity: Mapped[str] = mapped_column(String(10))
    title: Mapped[str] = mapped_column(String(300))
    ecosystem: Mapped[str | None] = mapped_column(String(40))
    package: Mapped[str | None] = mapped_column(String(214))
    version: Mapped[str | None] = mapped_column(String(80))
    # The first release with the fix, when there is one.
    fixed: Mapped[str | None] = mapped_column(String(80))
    advisory: Mapped[str | None] = mapped_column(String(80))  # GHSA-..., CVE-...
    aliases: Mapped[list[Any]] = mapped_column(JSON, default=list)
    path: Mapped[str | None] = mapped_column(String(300))  # secrets
    # End-of-life findings: when security fixes stop(ped).
    eol_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    first_seen_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    ignored_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    ignored_by: Mapped[str | None] = mapped_column(String(64))


class SecurityCache(Base):
    """Advisories from OSV.dev (osv:<id>) and end-of-life tables
    (eol:<product>), so each is fetched once a day at most."""

    __tablename__ = "security_cache"

    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
