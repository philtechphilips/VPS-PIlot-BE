"""Scheduled jobs of an app."""

from datetime import datetime
from typing import Annotated, NoReturn

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field, StringConstraints

from app.apps import crons, service
from app.apps.models import AppCronJob, Application
from app.audit import service as audit
from app.auth.dependencies import AdminUser
from app.core.database import DbSession
from app.jobs.types import Command

router = APIRouter(prefix="/api/v1/applications", tags=["Applications"])

Name = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=60)
]
ScheduleText = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=5, max_length=100)
]
Zone = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_]+(/[A-Za-z0-9_+-]+){0,2}$")]
Minutes = Annotated[int, Field(ge=1, le=360)]


class CronIn(BaseModel):
    name: Name
    schedule: ScheduleText
    timezone: Zone = "UTC"
    command: Command
    enabled: bool = True
    timeout_minutes: Minutes = 60


class CronUpdate(BaseModel):
    name: Name | None = None
    schedule: ScheduleText | None = None
    timezone: Zone | None = None
    command: Command | None = None
    enabled: bool | None = None
    timeout_minutes: Minutes | None = None


class CronOut(BaseModel):
    id: str
    name: str
    schedule: str
    timezone: str
    command: str
    enabled: bool
    timeout_minutes: int
    next_run_at: datetime | None
    last_run_at: datetime | None
    last_status: str | None
    last_error: str | None
    last_job_id: str | None
    created_at: datetime


def _raise(error: crons.CronJobError) -> NoReturn:
    raise HTTPException(status_code=error.status_code, detail=error.detail)


def _app(db, app_id: str) -> Application:
    app = service.get_app(db, app_id)
    if app is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Application not found")
    return app


def _job(db, app: Application, cron_id: str) -> AppCronJob:
    job = db.get(AppCronJob, cron_id)
    if job is None or job.application_id != app.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scheduled job not found")
    return job


def _out(job: AppCronJob) -> CronOut:
    return CronOut.model_validate(job, from_attributes=True)


def _audit(db, user, request, action: str, app: Application, job: AppCronJob) -> None:
    actor, label = audit.user_actor(user)
    audit.record(
        db,
        action=action,
        result="success",
        actor=actor,
        actor_label=label,
        target_type="application",
        target_id=app.id,
        target_label=app.name,
        detail=f"{job.name}: {job.schedule} ({job.timezone})",
        request=request,
    )


class RunIn(BaseModel):
    command: Command
    timeout_minutes: Minutes = 30


@router.post("/{app_id}/run", status_code=202)
def run_command(
    app_id: str, body: RunIn, request: Request, db: DbSession, user: AdminUser
):
    """Run a one-off command inside the app; poll the returned job for output."""
    app = _app(db, app_id)
    actor, label = audit.user_actor(user)
    try:
        job = crons.run_once(
            db, app, body.command, body.timeout_minutes, actor, label, request
        )
    except crons.CronJobError as error:
        _raise(error)
    return {"job_id": job.id}


@router.get("/{app_id}/cron", response_model=list[CronOut])
def list_jobs(app_id: str, db: DbSession, _: AdminUser):
    return [_out(j) for j in crons.list_for(db, _app(db, app_id))]


@router.post("/{app_id}/cron", response_model=CronOut, status_code=201)
def create_job(
    app_id: str, body: CronIn, request: Request, db: DbSession, user: AdminUser
):
    app = _app(db, app_id)
    _, label = audit.user_actor(user)
    try:
        job = crons.create(db, app, body.model_dump(), label)
    except crons.CronJobError as error:
        _raise(error)
    _audit(db, user, request, "cron.create", app, job)
    return _out(job)


@router.patch("/{app_id}/cron/{cron_id}", response_model=CronOut)
def update_job(
    app_id: str,
    cron_id: str,
    body: CronUpdate,
    request: Request,
    db: DbSession,
    user: AdminUser,
):
    app = _app(db, app_id)
    try:
        job = crons.update(
            db, _job(db, app, cron_id), body.model_dump(exclude_unset=True)
        )
    except crons.CronJobError as error:
        _raise(error)
    _audit(db, user, request, "cron.update", app, job)
    return _out(job)


@router.delete("/{app_id}/cron/{cron_id}", status_code=204)
def delete_job(
    app_id: str, cron_id: str, request: Request, db: DbSession, user: AdminUser
):
    app = _app(db, app_id)
    job = _job(db, app, cron_id)
    _audit(db, user, request, "cron.delete", app, job)
    db.delete(job)
    db.commit()


@router.post("/{app_id}/cron/{cron_id}/run", status_code=202)
def run_job(
    app_id: str, cron_id: str, request: Request, db: DbSession, user: AdminUser
):
    app = _app(db, app_id)
    job = _job(db, app, cron_id)
    actor, label = audit.user_actor(user)
    try:
        queued = crons.run(db, job, actor, label, request)
    except crons.CronJobError as error:
        _raise(error)
    return {"job_id": queued.id}
