from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    TIMESTAMP,
    BigInteger,
    Boolean,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Application(Base):
    """An app deployed to one server as a Docker container."""

    __tablename__ = "applications"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    # Also the container and image name on the server, so it's a strict slug.
    name: Mapped[str] = mapped_column(String(40), unique=True)
    server_id: Mapped[str] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), index=True
    )
    # docker | systemd (native Node.js/Python releases) | compose
    runtime: Mapped[str] = mapped_column(String(16), server_default="docker")

    # Source: a Git repository built with a Dockerfile, or a prebuilt image.
    source_type: Mapped[str] = mapped_column(String(8))  # "git" | "image"
    repo_url: Mapped[str | None] = mapped_column(String(500))
    branch: Mapped[str | None] = mapped_column(String(200))
    dockerfile: Mapped[str] = mapped_column(String(200), server_default="Dockerfile")
    build_context: Mapped[str] = mapped_column(String(200), server_default=".")
    image: Mapped[str | None] = mapped_column(String(300))
    # Only used when the repository has no Dockerfile (detected builds).
    build_command: Mapped[str | None] = mapped_column(String(500))
    start_command: Mapped[str | None] = mapped_column(String(500))
    # Compose apps: the file (found automatically when empty) and the service
    # that receives traffic (needed when there's more than one).
    compose_file: Mapped[str | None] = mapped_column(String(200))
    compose_service: Mapped[str | None] = mapped_column(String(63))
    # Linked GitHub repository (via the GitHub App), for private clones and
    # deploy-on-push.
    github_installation_id: Mapped[int | None] = mapped_column(BigInteger)
    github_repo_id: Mapped[int | None] = mapped_column(BigInteger, index=True)
    github_repo_full_name: Mapped[str | None] = mapped_column(String(200))
    auto_deploy: Mapped[bool] = mapped_column(Boolean, server_default="false")

    container_port: Mapped[int]
    host_port: Mapped[int]
    health_path: Mapped[str] = mapped_column(String(200), server_default="/")
    health_timeout_seconds: Mapped[int] = mapped_column(server_default="60")
    cpu_limit: Mapped[str | None] = mapped_column(String(16))  # e.g. "1.0"
    memory_limit: Mapped[str | None] = mapped_column(String(16))  # e.g. "512m"

    # [{"key": ..., "value": <encrypted>, "secret": bool}], see apps.service
    env: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    current_deployment_id: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )


class Deployment(Base):
    """One release attempt. Successful ones keep their image for rollback."""

    __tablename__ = "deployments"
    __table_args__ = (
        Index(
            "deployments_application_id_created_at_idx", "application_id", "created_at"
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    application_id: Mapped[str] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE")
    )
    server_id: Mapped[str] = mapped_column(String(32))
    job_id: Mapped[str | None] = mapped_column(String(32))
    # queued | running | succeeded | failed | canceled
    status: Mapped[str] = mapped_column(String(16), server_default="queued")
    trigger: Mapped[str] = mapped_column(String(16))  # create | manual | rollback
    # What was requested and what was actually deployed
    requested_ref: Mapped[str | None] = mapped_column(String(200))
    commit_sha: Mapped[str | None] = mapped_column(String(40))
    commit_message: Mapped[str | None] = mapped_column(String(300))
    image_ref: Mapped[str | None] = mapped_column(String(300))
    rollback_of: Mapped[str | None] = mapped_column(String(32))
    error: Mapped[str | None] = mapped_column(String(500))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    # Snapshot of how it was run (ports, health check) for the record
    spec: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    notes: Mapped[str | None] = mapped_column(Text)


class RequestMetric(Base):
    """Requests to one site in one minute, from the proxy's access log."""

    __tablename__ = "request_metrics"
    __table_args__ = (
        Index("request_metrics_host_minute_idx", "host", "minute", unique=True),
        Index("request_metrics_application_id_minute_idx", "application_id", "minute"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True
    )
    server_id: Mapped[str] = mapped_column(String(32))
    host: Mapped[str] = mapped_column(String(253))
    application_id: Mapped[str | None] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE")
    )
    minute: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    requests: Mapped[int]
    s2xx: Mapped[int]
    s3xx: Mapped[int]
    s4xx: Mapped[int]
    s5xx: Mapped[int]
    bytes: Mapped[int] = mapped_column(BigInteger)
    p50_ms: Mapped[float] = mapped_column(Float)
    p95_ms: Mapped[float] = mapped_column(Float)


class AppErrorMetric(Base):
    """Error lines one app logged in one minute, with the latest one."""

    __tablename__ = "app_error_metrics"
    __table_args__ = (
        Index(
            "app_error_metrics_application_id_minute_idx",
            "application_id",
            "minute",
            unique=True,
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True
    )
    application_id: Mapped[str] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE")
    )
    minute: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    errors: Mapped[int]
    # The latest error line, secrets masked by the agent; encrypted at rest.
    sample: Mapped[str | None] = mapped_column(Text)
