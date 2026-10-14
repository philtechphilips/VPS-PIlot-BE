"""Durable jobs: created by the owner, claimed and run by the target agent."""

from datetime import UTC, datetime, timedelta

from pydantic import ValidationError
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.audit import service as audit
from app.core.security import new_id
from app.jobs import types
from app.jobs.models import Job, JobEvent
from app.servers.models import Server

QUEUE_TTL = timedelta(minutes=10)  # unclaimed jobs expire
RUN_TIMEOUT = timedelta(minutes=5)  # claimed jobs must finish in time
MAX_OUTPUT = 64 * 1024
MAX_EVENTS_PER_JOB = 500


class JobError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> datetime:
    return datetime.now(UTC)


def reap(db: Session) -> None:
    """Expire unclaimed jobs past their deadline and fail stuck ones."""
    now = _now()
    db.execute(
        update(Job)
        .where(Job.status == "queued", Job.expires_at < now)
        .values(status="expired", finished_at=now, error="Not picked up in time")
    )
    db.execute(
        update(Job)
        .where(Job.status == "running", Job.claimed_at < now - RUN_TIMEOUT)
        .values(status="failed", finished_at=now, error="Timed out on the server")
    )
    db.commit()


def create(
    db: Session,
    server: Server,
    job_type: str,
    payload: dict,
    actor: str,
    actor_label: str,
    idempotency_key: str | None = None,
    request=None,
) -> tuple[Job, bool]:
    """Queue a job. Returns (job, created); an existing job is returned when
    the idempotency key was already used for this server."""
    if server.revoked_at is not None or server.enrolled_at is None:
        raise JobError(409, "This server has no active agent")
    try:
        clean = types.validate(job_type, payload)
    except types.PolicyError as error:
        audit.record(
            db,
            action=f"job.{job_type}",
            result="rejected",
            actor=actor,
            actor_label=actor_label,
            target_type="server",
            target_id=server.id,
            target_label=server.name,
            detail=str(error),
            request=request,
        )
        raise JobError(403, str(error)) from None
    except ValidationError as error:
        raise JobError(422, error.errors()[0]["msg"]) from None

    if idempotency_key:
        existing = db.scalar(
            select(Job).where(
                Job.server_id == server.id, Job.idempotency_key == idempotency_key
            )
        )
        if existing:
            return existing, False

    job = Job(
        id=new_id(),
        server_id=server.id,
        type=job_type,
        payload=clean,
        status="queued",
        idempotency_key=idempotency_key,
        created_by=actor,
        correlation_id=new_id(),
        expires_at=_now() + QUEUE_TTL,
    )
    db.add(job)
    audit.record(
        db,
        action=f"job.{job_type}",
        result="accepted",
        actor=actor,
        actor_label=actor_label,
        target_type="server",
        target_id=server.id,
        target_label=server.name,
        detail=_describe(job_type, clean),
        correlation_id=job.correlation_id,
        request=request,
        meta={"job_id": job.id},
        commit=False,
    )
    db.commit()
    db.refresh(job)
    return job, True


def _describe(job_type: str, payload: dict) -> str:
    target = payload.get("unit") or payload.get("container") or ""
    return f"{job_type} {target}".strip()


def get(db: Session, job_id: str) -> Job | None:
    return db.get(Job, job_id)


def list_jobs(db: Session, server_id: str | None = None, limit: int = 30) -> list[Job]:
    reap(db)
    query = select(Job).order_by(Job.created_at.desc(), Job.id).limit(limit)
    if server_id:
        query = query.where(Job.server_id == server_id)
    return list(db.scalars(query))


def events(db: Session, job_id: str) -> list[JobEvent]:
    return list(
        db.scalars(
            select(JobEvent).where(JobEvent.job_id == job_id).order_by(JobEvent.id)
        )
    )


def cancel(db: Session, job: Job) -> Job:
    if job.status != "queued":
        raise JobError(
            409, f"Only queued jobs can be canceled (this one is {job.status})"
        )
    job.status = "canceled"
    job.finished_at = _now()
    db.commit()
    db.refresh(job)
    return job


# ---------------------------------------------------------------------------
# Agent side
# ---------------------------------------------------------------------------


def claim(db: Session, server: Server) -> Job | None:
    """Hand the oldest queued job for this server to its agent."""
    reap(db)
    job = db.scalar(
        select(Job)
        .where(Job.server_id == server.id, Job.status == "queued")
        .order_by(Job.created_at, Job.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if job is None:
        return None
    job.status = "running"
    job.claimed_at = _now()
    job.attempts += 1
    db.commit()
    db.refresh(job)
    return job


def pending_count(db: Session, server: Server) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(Job)
            .where(Job.server_id == server.id, Job.status == "queued")
        )
        or 0
    )


def _owned_running(db: Session, server: Server, job_id: str) -> Job:
    job = db.get(Job, job_id)
    # Jobs are bound to their server: another agent can't touch them.
    if job is None or job.server_id != server.id:
        raise JobError(404, "Job not found")
    if job.status != "running":
        raise JobError(409, f"Job is {job.status}")
    return job


def add_events(db: Session, server: Server, job_id: str, items: list[dict]) -> int:
    job = _owned_running(db, server, job_id)
    existing = (
        db.scalar(
            select(func.count()).select_from(JobEvent).where(JobEvent.job_id == job.id)
        )
        or 0
    )
    room = max(0, MAX_EVENTS_PER_JOB - existing)
    for item in items[:room]:
        db.add(JobEvent(job_id=job.id, level=item["level"], message=item["message"]))
    db.commit()
    return min(len(items), room)


def complete(
    db: Session,
    server: Server,
    job_id: str,
    succeeded: bool,
    exit_code: int | None,
    output: str,
    error: str | None,
) -> Job:
    job = _owned_running(db, server, job_id)
    job.status = "succeeded" if succeeded else "failed"
    job.finished_at = _now()
    job.exit_code = exit_code
    job.output = output[-MAX_OUTPUT:] if output else None
    job.error = (error or "")[:500] or None
    audit.record(
        db,
        action=f"job.{job.type}",
        result="success" if succeeded else "failure",
        actor=f"agent:{server.id}",
        actor_label=server.name,
        target_type="server",
        target_id=server.id,
        target_label=server.name,
        detail=_describe(job.type, job.payload)
        + ("" if succeeded else f": {job.error or 'failed'}"),
        correlation_id=job.correlation_id,
        meta={"job_id": job.id, "exit_code": exit_code},
        commit=False,
    )
    db.commit()
    db.refresh(job)
    return job
