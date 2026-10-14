from datetime import datetime
from typing import Any

from sqlalchemy import JSON, TIMESTAMP, BigInteger, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AuditLog(Base):
    """Who did what to which target, and how it ended. Never holds secrets:
    metadata is limited to identifiers and safe descriptive fields."""

    __tablename__ = "audit_logs"
    __table_args__ = (Index("audit_logs_created_at_idx", "created_at"),)

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True
    )
    # "user:<id>", "agent:<server id>" or "system"
    actor: Mapped[str] = mapped_column(String(64))
    actor_label: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[str | None] = mapped_column(String(64))
    target_label: Mapped[str | None] = mapped_column(String(255))
    # "success", "failure", "accepted", "rejected"
    result: Mapped[str] = mapped_column(String(16))
    detail: Mapped[str | None] = mapped_column(String(500))
    correlation_id: Mapped[str] = mapped_column(String(32))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
