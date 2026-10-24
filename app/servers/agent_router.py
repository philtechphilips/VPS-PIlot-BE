"""Endpoints the agent calls. Agents only ever connect out to the control
plane; nothing here requires an inbound port on the managed server."""

import io
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse, Response, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import select

from app.apps import service as apps
from app.apps.models import Application
from app.audit import service as audit
from app.backups import service as backups
from app.core import artifacts
from app.core.config import settings
from app.core.database import DbSession
from app.databases import service as databases
from app.jobs import service as jobs
from app.jobs.schemas import (
    AgentJob,
    ClaimResponse,
    JobCompleteRequest,
    JobEventsRequest,
)
from app.platform import service as platform
from app.servers import service
from app.servers.models import Server
from app.servers.schemas import (
    AgentConfig,
    EnrollRequest,
    EnrollResponse,
    HeartbeatRequest,
    InventoryRequest,
    MetricsRequest,
)

router = APIRouter(prefix="/agent", tags=["Agent"])

AGENT_DIR = Path(__file__).resolve().parents[2] / "agent"
bearer = HTTPBearer(auto_error=False)


def current_agent(
    db: DbSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Server:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing agent token")
    server = service.authenticate_agent(db, credentials.credentials)
    if server is None:
        # Revoked or unknown: the agent should stop and ask to be re-enrolled.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent is not enrolled")
    return server


Agent = Annotated[Server, Depends(current_agent)]


def _config(
    jobs_pending: int = 0, error_ignore: dict[str, list[str]] | None = None
) -> AgentConfig:
    return AgentConfig(
        heartbeat_seconds=settings.agent_heartbeat_seconds,
        metrics_seconds=settings.agent_metrics_seconds,
        server_time=datetime.now(UTC),
        jobs_pending=jobs_pending,
        error_ignore=error_ignore or {},
    )


@router.post("/v1/enroll", response_model=EnrollResponse)
def enroll(body: EnrollRequest, request: Request, db: DbSession):
    """Redeem a single-use enrollment token for a per-agent credential."""
    try:
        server, agent_token = service.enroll(
            db, body.token, body.facts.model_dump(exclude_none=True)
        )
    except service.ServerError as error:
        audit.record(
            db,
            action="agent.enroll",
            result="rejected",
            detail=error.detail,
            request=request,
        )
        raise HTTPException(error.status_code, error.detail) from None
    audit.record(
        db,
        action="agent.enroll",
        result="success",
        actor=f"agent:{server.id}",
        actor_label=server.name,
        target_type="server",
        target_id=server.id,
        target_label=server.name,
        detail=f"{server.os_name or ''} {server.os_version or ''}".strip() or None,
        request=request,
    )
    return EnrollResponse(
        server_id=server.id,
        server_name=server.name,
        agent_token=agent_token,
        heartbeat_seconds=settings.agent_heartbeat_seconds,
        metrics_seconds=settings.agent_metrics_seconds,
    )


@router.post("/v1/heartbeat", response_model=AgentConfig)
def heartbeat(body: HeartbeatRequest, agent: Agent, db: DbSession):
    service.heartbeat(db, agent, body.facts.model_dump(exclude_none=True))
    apps_here = list(
        db.scalars(select(Application).where(Application.server_id == agent.id))
    )
    groups = apps.ignored_fingerprints(db, [a.id for a in apps_here])
    ignore = {
        a.name: [*(a.error_ignore or []), *groups.get(a.id, [])]
        for a in apps_here
        if a.error_ignore or a.id in groups
    }
    return _config(jobs.pending_count(db, agent), ignore)


@router.post("/v1/metrics", status_code=status.HTTP_202_ACCEPTED)
def metrics(body: MetricsRequest, agent: Agent, db: DbSession):
    stored = service.store_metrics(db, agent, [s.model_dump() for s in body.samples])
    return {"stored": stored}


@router.post("/v1/inventory", status_code=status.HTTP_202_ACCEPTED)
def inventory(body: InventoryRequest, agent: Agent, db: DbSession):
    service.store_inventory(db, agent, body.model_dump())
    return {"ok": True}


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


def _job_error(error: jobs.JobError) -> HTTPException:
    return HTTPException(error.status_code, error.detail)


@router.post("/v1/jobs/claim", response_model=ClaimResponse)
def claim_job(agent: Agent, db: DbSession):
    """Hand this agent its oldest queued job, if any."""
    job = jobs.claim(db, agent)
    if job is None:
        return ClaimResponse(job=None)
    return ClaimResponse(
        job=AgentJob(id=job.id, type=job.type, version=job.version, payload=job.payload)
    )


@router.get("/v1/jobs/{job_id}/secrets")
def job_secrets(job_id: str, agent: Agent, db: DbSession):
    """Secrets for a job (deploy env values, database passwords and SQL),
    only to the agent running it, only while it runs. They are never stored
    in the job itself."""
    job = jobs.get(db, job_id)
    if job is None or job.server_id != agent.id or job.status != "running":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No secrets for this job")
    if job.type.startswith("db."):
        return {"secrets": databases.job_secrets(db, job)}
    if job.type.startswith("backup."):
        return {"secrets": backups.job_secrets(db, job)}
    if job.type != "app.deploy":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No secrets for this job")
    app = db.scalar(select(Application).where(Application.name == job.payload["app"]))
    if app is None or app.server_id != agent.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No secrets for this job")
    # secret_keys tells the agent which values to mask in build output.
    reply = {"env": apps.env_values(app), "secret_keys": apps.secret_keys(app)}
    source = job.payload.get("source") or {}
    if source.get("type") == "git" and source.get("auth"):
        token = apps.git_token(db, app)
        if token:
            reply["git_token"] = token
    return reply


class RequestRow(BaseModel):
    host: Annotated[str, StringConstraints(max_length=253)]
    minute: Annotated[int, Field(ge=0)]
    requests: Annotated[int, Field(ge=0)]
    s2xx: Annotated[int, Field(ge=0)]
    s3xx: Annotated[int, Field(ge=0)]
    s4xx: Annotated[int, Field(ge=0)]
    s5xx: Annotated[int, Field(ge=0)]
    bytes: Annotated[int, Field(ge=0)]
    p50_ms: Annotated[float, Field(ge=0)]
    p95_ms: Annotated[float, Field(ge=0)]


class RequestsReport(BaseModel):
    rows: Annotated[list[RequestRow], Field(max_length=2000)]


@router.post("/v1/requests", status_code=status.HTTP_202_ACCEPTED)
def report_requests(body: RequestsReport, agent: Agent, db: DbSession):
    """Per-site request counts from the proxy's access log."""
    stored = apps.store_requests(db, agent, [r.model_dump() for r in body.rows])
    return {"stored": stored}


@router.put("/v1/jobs/{job_id}/artifact", status_code=status.HTTP_202_ACCEPTED)
async def upload_artifact(job_id: str, request: Request, agent: Agent, db: DbSession):
    """A database export, streamed up by the agent running the job."""
    job = jobs.get(db, job_id)
    if (
        job is None
        or job.server_id != agent.id
        or job.status != "running"
        or job.type != "db.export"
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No upload for this job")
    try:
        size = await artifacts.write(
            f"{job.id}.out",
            request.stream(),
            settings.max_transfer_mb * 1024 * 1024,
        )
    except artifacts.TooLarge as error:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, str(error)) from None
    return {"size": size}


@router.get("/v1/jobs/{job_id}/artifact")
def download_artifact(job_id: str, agent: Agent, db: DbSession):
    """The uploaded file a database import job loads."""
    job = jobs.get(db, job_id)
    if (
        job is None
        or job.server_id != agent.id
        or job.status != "running"
        or job.type != "db.import"
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No file for this job")
    name = f"{job.payload['upload_id']}.in"
    if not artifacts.exists(name):
        raise HTTPException(status.HTTP_410_GONE, "The upload expired")
    return StreamingResponse(
        artifacts.read(name), media_type="application/octet-stream"
    )


@router.post("/v1/jobs/{job_id}/events", status_code=status.HTTP_202_ACCEPTED)
def job_events(job_id: str, body: JobEventsRequest, agent: Agent, db: DbSession):
    try:
        stored = jobs.add_events(
            db, agent, job_id, [e.model_dump() for e in body.events]
        )
    except jobs.JobError as error:
        raise _job_error(error) from None
    return {"stored": stored}


@router.post("/v1/jobs/{job_id}/complete", status_code=status.HTTP_202_ACCEPTED)
def job_complete(job_id: str, body: JobCompleteRequest, agent: Agent, db: DbSession):
    try:
        job = jobs.complete(
            db,
            agent,
            job_id,
            body.status == "succeeded",
            body.exit_code,
            body.output,
            body.error,
            body.result,
        )
    except jobs.JobError as error:
        raise _job_error(error) from None
    return {"status": job.status}


class ErrorGroupRow(BaseModel):
    fp: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{16}$")]
    count: Annotated[int, Field(ge=0)]
    sample: Annotated[str, StringConstraints(max_length=500)] = ""


class AppErrorRow(BaseModel):
    app: Annotated[str, StringConstraints(max_length=40)]
    minute: Annotated[int, Field(ge=0)]
    errors: Annotated[int, Field(ge=0)]
    sample: Annotated[str, StringConstraints(max_length=500)] = ""
    groups: Annotated[list[ErrorGroupRow], Field(max_length=20)] = []


class AppErrorsReport(BaseModel):
    rows: Annotated[list[AppErrorRow], Field(max_length=2000)]


@router.post("/v1/app-errors", status_code=status.HTTP_202_ACCEPTED)
def report_app_errors(body: AppErrorsReport, agent: Agent, db: DbSession):
    """Error lines per app and minute from the apps' logs."""
    stored = apps.store_app_errors(db, agent, [r.model_dump() for r in body.rows])
    return {"stored": stored}


class UsageRow(BaseModel):
    app: Annotated[str, StringConstraints(max_length=40)]
    cpu_percent: Annotated[float, Field(ge=0, le=100_000)]
    memory_bytes: Annotated[int, Field(ge=0)]


class UsageReport(BaseModel):
    rows: Annotated[list[UsageRow], Field(max_length=500)]


@router.post("/v1/app-usage", status_code=status.HTTP_202_ACCEPTED)
def report_usage(body: UsageReport, agent: Agent, db: DbSession):
    """CPU and memory per app, once a minute."""
    stored = apps.store_usage(db, agent, [r.model_dump() for r in body.rows])
    return {"stored": stored}


# ---------------------------------------------------------------------------
# Installer
# ---------------------------------------------------------------------------

# The installer lives next to this file so it can be read and linted as shell.
INSTALL_SCRIPT = (Path(__file__).parent / "install.sh").read_text()


@router.get("/install.sh", response_class=PlainTextResponse)
def install_script(db: DbSession):
    """The one-line installer referenced by enrollment commands."""
    return PlainTextResponse(
        INSTALL_SCRIPT.replace("__API_URL__", platform.agent_url(db)),
        media_type="text/x-shellscript",
    )


def build_agent_package() -> bytes:
    """tar.gz of the agent's Python package (no compiled files)."""
    buffer = io.BytesIO()
    package = AGENT_DIR / "vpspilot_agent"
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path in sorted(package.rglob("*.py")):
            tar.add(path, arcname=str(path.relative_to(AGENT_DIR)))
    return buffer.getvalue()


@router.get("/package.tar.gz")
def agent_package():
    return Response(
        build_agent_package(),
        media_type="application/gzip",
        headers={"Content-Disposition": 'attachment; filename="vpspilot-agent.tar.gz"'},
    )
