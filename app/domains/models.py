from datetime import datetime
from typing import Any

from sqlalchemy import JSON, TIMESTAMP, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Domain(Base):
    """A hostname served by the server's VPSPilot proxy: proxied to an app,
    or redirected to another of your domains."""

    __tablename__ = "domains"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(253), unique=True)
    server_id: Mapped[str] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), index=True
    )
    application_id: Mapped[str | None] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), index=True
    )
    redirect_to: Mapped[str | None] = mapped_column(String(253))
    tls_mode: Mapped[str] = mapped_column(String(16))  # auto | internal | off
    # pending (being applied) | active | error
    status: Mapped[str] = mapped_column(String(16))
    error: Mapped[str | None] = mapped_column(String(500))
    apply_job_id: Mapped[str | None] = mapped_column(String(32))
    # DNS as seen by the control plane
    dns_addresses: Mapped[list[str]] = mapped_column(JSON, default=list)
    dns_status: Mapped[str | None] = mapped_column(
        String(16)
    )  # ok | elsewhere | missing
    dns_checked_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    # Certificate as presented by the proxy
    cert_issuer: Mapped[str | None] = mapped_column(String(120))
    cert_expires_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    cert_error: Mapped[str | None] = mapped_column(String(300))
    cert_checked_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
