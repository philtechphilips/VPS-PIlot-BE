"""Scheduled jobs: commands run inside an app on a cron schedule.

The background loop starts the ones that are due; each run is an app.exec
job on the app's server, so it shows up with its output like any other job.
A run is skipped while the previous one is still going, and a failed run
notifies the inbox and alert channels (event job.failed).
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.apps.models import AppCronJob, Application
from app.core import cron
from app.core.security import new_id
from app.jobs import service as jobs
from app.jobs.models import Job
from app.servers.models import Server

MAX_PER_APP = 20


class CronJobError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _next(job: AppCronJob, after: datetime | None = None) -> datetime:
    return cron.parse(job.schedule).next_after(after or _now(), job.timezone)


def _validate(schedule: str, timezone: str) -> None:
    try:
        cron.parse(schedule).next_after(_now(), timezone)
    except cron.CronError as error:
        raise CronJobError(422, str(error)) from None


def list_for(db: Session, app: Application) -> list[AppCronJob]:
    return list(
        db.scalars(
            select(AppCronJob)
            .where(AppCronJob.application_id == app.id)
            .order_by(AppCronJob.created_at)
        )
    )


def create(
    db: Session, app: Application, data: dict[str, Any], label: str
) -> AppCronJob:
    if len(list_for(db, app)) >= MAX_PER_APP:
        raise CronJobError(409, f"An app can have up to {MAX_PER_APP} scheduled jobs")
    _validate(data["schedule"], data.get("timezone") or "UTC")
    job = AppCronJob(
        id=new_id(),
        application_id=app.id,
        name=data["name"],
        schedule=data["schedule"].strip(),
        timezone=data.get("timezone") or "UTC",
        command=data["command"],
        enabled=data.get("enabled", True),
        timeout_minutes=data.get("timeout_minutes") or 60,
        created_by=label[:64],
        created_at=_now(),
    )
    job.next_run_at = _next(job) if job.enabled else None
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def update(db: Session, job: AppCronJob, data: dict[str, Any]) -> AppCronJob:
    schedule = data.get("schedule") or job.schedule
    timezone = data.get("timezone") or job.timezone
    _validate(schedule, timezone)
    for field in (
        "name",
        "schedule",
        "timezone",
        "command",
        "enabled",
        "timeout_minutes",
    ):
        if data.get(field) is not None:
            setattr(job, field, data[field])
    job.next_run_at = _next(job) if job.enabled else None
    db.commit()
    db.refresh(job)
    return job


def _running(db: Session, job: AppCronJob) -> bool:
    if not job.last_job_id:
        return False
    last = db.get(Job, job.last_job_id)
    return last is not None and last.status in ("queued", "running")


def run(db: Session, job: AppCronJob, actor: str, label: str, request=None) -> Job:
    """Start a run now (the schedule or the Run now button)."""
    app = db.get(Application, job.application_id)
    if app is None or app.current_deployment_id is None:
        raise CronJobError(
            409, "Deploy the app first: jobs run inside its live release"
        )
    if _running(db, job):
        raise CronJobError(409, "The previous run is still going")
    payload = {
        "app": app.name,
        "runtime": app.runtime,
        "command": job.command,
        "timeout": job.timeout_minutes * 60,
        "cron_id": job.id,
    }
    if app.runtime == "compose":
        payload["service"] = app.compose_service or ""
    try:
        queued, _ = jobs.create(
            db,
            db.get(Server, app.server_id),
            "app.exec",
            payload,
            actor,
            label,
            request=request,
            audited=actor != "system",
        )
    except jobs.JobError as error:
        raise CronJobError(error.status_code, error.detail) from None
    job.last_run_at, job.last_status, job.last_job_id = _now(), "running", queued.id
    job.last_error = None
    db.commit()
    return queued


def run_due(db: Session, now: datetime | None = None) -> int:
    """Called by the background loop."""
    now = now or _now()
    started = 0
    for job in db.scalars(
        select(AppCronJob).where(
            AppCronJob.enabled.is_(True), AppCronJob.next_run_at <= now
        )
    ):
        job.next_run_at = _next(job, now)
        db.commit()
        try:
            run(db, job, "system", f"Schedule: {job.name}"[:64])
            started += 1
        except CronJobError as error:
            job.last_status, job.last_error = "skipped", error.detail[:300]
            job.last_run_at = now
            db.commit()
    return started


def on_job_finished(db: Session, job: Job) -> None:
    if job.type != "app.exec":
        return
    cron_id = (job.payload or {}).get("cron_id")
    entry = db.get(AppCronJob, cron_id) if cron_id else None
    if entry is None or entry.last_job_id != job.id:
        return
    ok = job.status == "succeeded"
    entry.last_status = "succeeded" if ok else "failed"
    entry.last_error = None if ok else (job.error or f"Job {job.status}")[:300]
    db.flush()
    if not ok:
        from app.core.config import settings
        from app.notifications import channels
        from app.notifications import service as notifications

        app = db.get(Application, entry.application_id)
        title = f"Scheduled job {entry.name} failed on {app.name if app else 'an app'}"
        link = f"/dashboard/applications/{entry.application_id}"
        notifications.notify(db, "job.failed", "err", title, entry.last_error, link)
        channels.dispatch(
            db,
            "job.failed",
            {
                "title": title,
                "detail": entry.last_error,
                "app": app.name if app else None,
                "url": f"{settings.frontend_url.rstrip('/')}{link}",
            },
        )


jobs.on_finished.append(on_job_finished)
