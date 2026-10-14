from datetime import datetime

from sqlalchemy import TIMESTAMP, Float, ForeignKey, Index, String, func, true
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AlertRule(Base):
    """A condition watched on every server (or one server, or every app)."""

    __tablename__ = "alert_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    # agent_offline | cpu_high | memory_high | disk_high | inode_high |
    # swap_high | app_down (see monitoring.service.KINDS)
    kind: Mapped[str] = mapped_column(String(24))
    name: Mapped[str] = mapped_column(String(100))
    threshold: Mapped[float | None] = mapped_column(Float)  # percent
    duration_minutes: Mapped[int]
    severity: Mapped[str] = mapped_column(String(10))  # critical | warning | info
    enabled: Mapped[bool] = mapped_column(server_default=true())
    notify_email: Mapped[bool] = mapped_column(server_default=true())
    # Limit to one server; None means every server.
    server_id: Mapped[str | None] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE")
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )


class Alert(Base):
    """An incident: one per rule and target while it lasts (deduplicated)."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("alerts_rule_id_target_id_state_idx", "rule_id", "target_id", "state"),
        Index("alerts_state_started_at_idx", "state", "started_at"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    rule_id: Mapped[str] = mapped_column(
        ForeignKey("alert_rules.id", ondelete="CASCADE")
    )
    target_type: Mapped[str] = mapped_column(String(16))  # server | application
    target_id: Mapped[str] = mapped_column(String(32))
    target_label: Mapped[str] = mapped_column(String(120))
    severity: Mapped[str] = mapped_column(String(10))
    title: Mapped[str] = mapped_column(String(200))
    detail: Mapped[str | None] = mapped_column(String(300))
    value: Mapped[float | None] = mapped_column(Float)
    # pending (condition seen, waiting out the duration) | firing |
    # acknowledged | resolved
    state: Mapped[str] = mapped_column(String(16))
    started_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    fired_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    acknowledged_by: Mapped[str | None] = mapped_column(String(64))
    resolved_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
