from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    TIMESTAMP,
    BigInteger,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Job(Base):
    """A typed operation for one server's agent to run.

    Lifecycle: queued → running → succeeded | failed, or queued → expired /
    canceled. Jobs are bound to their server: an agent can only claim its own.
    """

    __tablename__ = "jobs"
    __table_args__ = (
        Index("jobs_server_id_status_idx", "server_id", "status"),
        UniqueConstraint(
            "server_id", "idempotency_key", name="jobs_server_id_idempotency_key_key"
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String(40))
    # Validated against the job type's schema before it is stored.
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Protocol version, so agents can refuse job formats they don't know.
    version: Mapped[int] = mapped_column(server_default="1")
    status: Mapped[str] = mapped_column(String(16), server_default="queued")
    idempotency_key: Mapped[str | None] = mapped_column(String(64))
    attempts: Mapped[int] = mapped_column(server_default="0")
    created_by: Mapped[str] = mapped_column(String(64))
    correlation_id: Mapped[str] = mapped_column(String(32))
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    claimed_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    exit_code: Mapped[int | None]
    # Bounded command output (see MAX_OUTPUT in the service)
    output: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )


class JobEvent(Base):
    """Progress messages streamed by the agent while a job runs."""

    __tablename__ = "job_events"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True
    )
    job_id: Mapped[str] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"), index=True
    )
    level: Mapped[str] = mapped_column(String(8))
    message: Mapped[str] = mapped_column(String(2000))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
