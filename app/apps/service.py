"""Applications and deployments. A deployment is one `app.deploy` job on the
app's server; the job's outcome updates the deployment and, on success,
promotes it to the app's current release."""

import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.apps.models import Application, Deployment
from app.core.security import decrypt_secret, encrypt_secret, new_id
from app.jobs import service as jobs
from app.jobs.models import Job
from app.servers.models import Server

NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
FIRST_HOST_PORT = 20000
ENV_PURPOSE = "app-env"
RESERVED_ENV = {"PORT"}  # set by VPSPilot from container_port


class AppError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Environment variables (encrypted at rest)
# ---------------------------------------------------------------------------


def encode_env(
    items: list[dict[str, Any]], existing: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Validate and encrypt env vars. A secret sent without a value keeps
    its stored value, since the browser never receives secret values."""
    previous = {e["key"]: e for e in existing}
    seen: set[str] = set()
    out = []
    for item in items:
        key = item["key"]
        if not ENV_KEY_RE.match(key):
            raise AppError(422, f"Invalid variable name: {key}")
        if key in RESERVED_ENV:
            raise AppError(422, f"{key} is set by VPSPilot")
        if key in seen:
            raise AppError(422, f"Duplicate variable: {key}")
        seen.add(key)
        value = item.get("value")
        if value is None:
            if key not in previous:
                raise AppError(422, f"{key} needs a value")
            encrypted = previous[key]["value"]
        else:
            if "\n" in value or len(value) > 8192:
                raise AppError(422, f"{key}: values must be one line, up to 8 KB")
            encrypted = encrypt_secret(value, ENV_PURPOSE)
        out.append({"key": key, "value": encrypted, "secret": bool(item.get("secret"))})
    return out


def env_for_display(app: Application) -> list[dict[str, Any]]:
    return [
        {
            "key": e["key"],
            "secret": e["secret"],
            "value": None if e["secret"] else decrypt_secret(e["value"], ENV_PURPOSE),
        }
        for e in app.env or []
    ]


def secret_keys(app: Application) -> list[str]:
    return [e["key"] for e in app.env or [] if e["secret"]]


def env_values(app: Application) -> dict[str, str]:
    """Plain values, only for handing to the agent running a deploy."""
    values = {e["key"]: decrypt_secret(e["value"], ENV_PURPOSE) for e in app.env or []}
    values["PORT"] = str(app.container_port)
    return values


# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------


def list_apps(db: Session) -> list[Application]:
    return list(db.scalars(select(Application).order_by(Application.created_at)))


def get_app(db: Session, app_id: str) -> Application | None:
    return db.get(Application, app_id)


def _next_host_port(db: Session, server_id: str) -> int:
    used = set(
        db.scalars(
            select(Application.host_port).where(Application.server_id == server_id)
        )
    )
    port = FIRST_HOST_PORT
    while port in used:
        port += 1
    return port


def create_app(db: Session, server: Server, data: dict[str, Any]) -> Application:
    name = data["name"]
    if not NAME_RE.match(name):
        raise AppError(
            422, "Use lowercase letters, numbers and dashes, up to 40 characters."
        )
    if db.scalar(select(Application).where(Application.name == name)):
        raise AppError(409, f"An application named {name} already exists")
    if server.enrolled_at is None or server.revoked_at is not None:
        raise AppError(409, "Pick a server with an active agent")
    host_port = data.get("host_port") or _next_host_port(db, server.id)
    clash = db.scalar(
        select(Application).where(
            Application.server_id == server.id, Application.host_port == host_port
        )
    )
    if clash:
        raise AppError(409, f"Port {host_port} is already used by {clash.name}")

    source = data["source"]
    app = Application(
        id=new_id(),
        name=name,
        server_id=server.id,
        source_type=source["type"],
        repo_url=source.get("url"),
        branch=source.get("branch"),
        image=source.get("image"),
        dockerfile=data.get("dockerfile") or "Dockerfile",
        build_context=data.get("build_context") or ".",
        container_port=data["container_port"],
        host_port=host_port,
        health_path=data.get("health_path") or "/",
        health_timeout_seconds=data.get("health_timeout_seconds") or 60,
        cpu_limit=data.get("cpu_limit"),
        memory_limit=data.get("memory_limit"),
        env=encode_env(data.get("env") or [], []),
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def update_settings(db: Session, app: Application, data: dict[str, Any]) -> Application:
    """Change how the next deployment runs. Nothing restarts until then."""
    for field in (
        "branch",
        "image",
        "dockerfile",
        "build_context",
        "container_port",
        "health_path",
        "health_timeout_seconds",
        "cpu_limit",
        "memory_limit",
    ):
        if field in data:
            setattr(app, field, data[field])
    if "env" in data and data["env"] is not None:
        app.env = encode_env(data["env"], app.env or [])
    db.commit()
    db.refresh(app)
    return app


# ---------------------------------------------------------------------------
# Deployments
# ---------------------------------------------------------------------------


def _payload(
    app: Application, deployment: Deployment, source: dict[str, Any]
) -> dict[str, Any]:
    return {
        "app": app.name,
        "deployment_id": deployment.id,
        "source": source,
        "dockerfile": app.dockerfile,
        "context": app.build_context,
        "container_port": app.container_port,
        "host_port": app.host_port,
        "health_path": app.health_path,
        "health_timeout": app.health_timeout_seconds,
        "cpus": app.cpu_limit,
        "memory": app.memory_limit,
        "has_env": True,
    }


def _queue(
    db: Session,
    app: Application,
    deployment: Deployment,
    source: dict[str, Any],
    actor: str,
    label: str,
    request=None,
) -> Deployment:
    server = db.get(Server, app.server_id)
    try:
        job, _ = jobs.create(
            db,
            server,
            "app.deploy",
            _payload(app, deployment, source),
            actor,
            label,
            request=request,
        )
    except jobs.JobError as error:
        db.delete(deployment)
        db.commit()
        raise AppError(error.status_code, error.detail) from None
    deployment.job_id = job.id
    deployment.spec = {k: v for k, v in job.payload.items() if k not in ("source",)}
    db.commit()
    db.refresh(deployment)
    return deployment


def deploy(
    db: Session,
    app: Application,
    actor: str,
    label: str,
    trigger: str = "manual",
    ref: str | None = None,
    request=None,
) -> Deployment:
    """Build and release the app's branch (or a specific commit/tag)."""
    if app.source_type == "git":
        requested = ref or app.branch or "main"
        source = {"type": "git", "url": app.repo_url, "ref": requested}
    else:
        requested = ref or app.image
        source = {"type": "image", "image": requested, "pull": True}
    deployment = Deployment(
        id=new_id(),
        application_id=app.id,
        server_id=app.server_id,
        status="queued",
        trigger=trigger,
        requested_ref=requested,
        created_by=label[:64],
        spec={},
        created_at=_now(),
    )
    db.add(deployment)
    db.flush()
    return _queue(db, app, deployment, source, actor, label, request)


def rollback(
    db: Session,
    app: Application,
    target: Deployment,
    actor: str,
    label: str,
    request=None,
) -> Deployment:
    """Release a previous successful deployment's image again (no rebuild)."""
    if (
        target.application_id != app.id
        or target.status != "succeeded"
        or not target.image_ref
    ):
        raise AppError(
            409, "Only successful deployments with an image can be rolled back to"
        )
    if app.current_deployment_id == target.id:
        raise AppError(409, "That deployment is already live")
    deployment = Deployment(
        id=new_id(),
        application_id=app.id,
        server_id=app.server_id,
        status="queued",
        trigger="rollback",
        requested_ref=target.image_ref,
        commit_sha=target.commit_sha,
        commit_message=target.commit_message,
        rollback_of=target.id,
        created_by=label[:64],
        spec={},
        created_at=_now(),
    )
    db.add(deployment)
    db.flush()
    # Images built here are local; images from a registry may be pulled again.
    pull = app.source_type == "image"
    source = {"type": "image", "image": target.image_ref, "pull": pull}
    return _queue(db, app, deployment, source, actor, label, request)


def list_deployments(
    db: Session, app_id: str | None = None, limit: int = 30
) -> list[Deployment]:
    jobs.reap(db)
    query = (
        select(Deployment)
        .order_by(Deployment.created_at.desc(), Deployment.id)
        .limit(limit)
    )
    if app_id:
        query = query.where(Deployment.application_id == app_id)
    return list(db.scalars(query))


def get_deployment(db: Session, deployment_id: str) -> Deployment | None:
    return db.get(Deployment, deployment_id)


def remove_app(
    db: Session, app: Application, actor: str, label: str, request=None
) -> None:
    """Ask the agent to remove the container, then forget the app."""
    server = db.get(Server, app.server_id)
    if server and server.enrolled_at and not server.revoked_at:
        try:
            jobs.create(
                db,
                server,
                "app.remove",
                {"app": app.name},
                actor,
                label,
                request=request,
            )
        except jobs.JobError:
            pass  # The record is removed regardless; the container may linger.
    db.delete(app)
    db.commit()


# ---------------------------------------------------------------------------
# Job outcome → deployment
# ---------------------------------------------------------------------------


def on_job_finished(db: Session, job: Job) -> None:
    if job.type != "app.deploy":
        return
    deployment = db.scalar(select(Deployment).where(Deployment.job_id == job.id))
    if deployment is None:
        return
    deployment.finished_at = job.finished_at or _now()
    result = job.result or {}
    if job.status == "succeeded":
        deployment.status = "succeeded"
        deployment.commit_sha = result.get("commit_sha") or deployment.commit_sha
        deployment.commit_message = (
            result.get("commit_message") or deployment.commit_message or ""
        )[:300] or None
        deployment.image_ref = result.get("image_ref") or deployment.requested_ref
        app = db.get(Application, deployment.application_id)
        if app:
            app.current_deployment_id = deployment.id
    else:
        deployment.status = "canceled" if job.status == "canceled" else "failed"
        deployment.error = job.error or f"Job {job.status}"


jobs.on_finished.append(on_job_finished)


def job_for(db: Session, deployment: Deployment) -> Job | None:
    return db.get(Job, deployment.job_id) if deployment.job_id else None
