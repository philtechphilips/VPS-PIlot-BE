from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    TIMESTAMP,
    BigInteger,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    false,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Server(Base):
    """A managed VPS. Created as "pending" when an enrollment token is issued;
    the agent fills in the host details when it enrolls."""

    __tablename__ = "servers"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(63), unique=True)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    is_control_plane: Mapped[bool] = mapped_column(server_default=false())

    # Reported by the agent
    hostname: Mapped[str | None] = mapped_column(String(255))
    os_name: Mapped[str | None] = mapped_column(String(64))
    os_version: Mapped[str | None] = mapped_column(String(64))
    kernel: Mapped[str | None] = mapped_column(String(128))
    arch: Mapped[str | None] = mapped_column(String(32))
    cpu_count: Mapped[int | None]
    memory_total: Mapped[int | None] = mapped_column(BigInteger)
    disk_total: Mapped[int | None] = mapped_column(BigInteger)
    ip_addresses: Mapped[list[str]] = mapped_column(JSON, default=list)
    agent_version: Mapped[str | None] = mapped_column(String(32))
    capabilities: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Latest service/container/runtime snapshot from the agent
    inventory: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    inventory_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))

    # Agent identity: sha256 of the per-agent token issued at enrollment
    agent_token_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    agent_token_rotated_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True)
    )

    enrolled_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    uptime_seconds: Mapped[int | None] = mapped_column(BigInteger)
    revoked_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )


class EnrollmentToken(Base):
    """Single-use, short-lived token that lets one agent enroll one server."""

    __tablename__ = "enrollment_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[str] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )


class MetricSample(Base):
    """One host metrics sample. Kept for settings.metrics_retention_days."""

    __tablename__ = "metric_samples"
    __table_args__ = (Index("metric_samples_server_id_ts_idx", "server_id", "ts"),)

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True
    )
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    cpu_percent: Mapped[float] = mapped_column(Float)
    memory_percent: Mapped[float] = mapped_column(Float)
    memory_used: Mapped[int] = mapped_column(BigInteger)
    swap_percent: Mapped[float] = mapped_column(Float)
    disk_percent: Mapped[float] = mapped_column(Float)
    disk_used: Mapped[int] = mapped_column(BigInteger)
    inode_percent: Mapped[float | None] = mapped_column(Float)
    load_1: Mapped[float] = mapped_column(Float)
    load_5: Mapped[float] = mapped_column(Float)
    load_15: Mapped[float] = mapped_column(Float)
    net_rx_bps: Mapped[float] = mapped_column(Float)
    net_tx_bps: Mapped[float] = mapped_column(Float)
