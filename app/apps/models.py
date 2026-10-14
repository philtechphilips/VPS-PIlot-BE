from datetime import datetime
from typing import Any

from sqlalchemy import JSON, TIMESTAMP, ForeignKey, Index, String, Text, func
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
    runtime: Mapped[str] = mapped_column(String(16), server_default="docker")

    # Source: a Git repository built with a Dockerfile, or a prebuilt image.
    source_type: Mapped[str] = mapped_column(String(8))  # "git" | "image"
    repo_url: Mapped[str | None] = mapped_column(String(500))
    branch: Mapped[str | None] = mapped_column(String(200))
    dockerfile: Mapped[str] = mapped_column(String(200), server_default="Dockerfile")
    build_context: Mapped[str] = mapped_column(String(200), server_default=".")
    image: Mapped[str | None] = mapped_column(String(300))

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
