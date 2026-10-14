from datetime import datetime
from typing import Annotated, Literal, NoReturn

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import func, select

from app.audit import service as audit
from app.auth.dependencies import AdminUser
from app.backups import service
from app.backups.models import BackupRun
from app.core.database import DbSession
from app.databases import service as databases
from app.databases.models import DatabaseInstance
from app.jobs import service as jobs
from app.jobs.models import Job
from app.jobs.types import DbIdent

router = APIRouter(prefix="/api/v1/backups", tags=["Backups"])


def _raise(error: service.BackupError) -> NoReturn:
    raise HTTPException(status_code=error.status_code, detail=error.detail)


class PolicyIn(BaseModel):
    enabled: bool | None = None
    every_hours: Annotated[int, Field(ge=1, le=24 * 30)] | None = None
    keep: Annotated[int, Field(ge=1, le=365)] | None = None
    databases: Annotated[list[DbIdent], Field(max_length=50)] | None = None


class RunIn(BaseModel):
    instance_id: Annotated[str, StringConstraints(max_length=32)]
    database: DbIdent | None = None


class RestoreIn(BaseModel):
    mode: Literal["replace", "new"]
    into: DbIdent | None = None


class SettingsIn(BaseModel):
    storage_enabled: bool | None = None
    endpoint: (
        Annotated[
            str, StringConstraints(pattern=r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?/?$")
        ]
        | None
    ) = None
    region: Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]{1,40}$")] | None = (
        None
    )
    bucket: (
        Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")]
        | None
    ) = None
    prefix: (
        Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._/-]{0,200}$")] | None
    ) = None
    access_key: Annotated[str, StringConstraints(max_length=200)] | None = None
    secret_key: Annotated[str, StringConstraints(max_length=200)] | None = None
    keep_local: bool | None = None


def _run_out(db, run: BackupRun) -> dict:
    instance = db.get(DatabaseInstance, run.instance_id)
    return {
        "id": run.id,
        "instance_id": run.instance_id,
        "instance_name": instance.name if instance else None,
        "engine": instance.engine if instance else None,
        "database": run.database,
        "trigger": run.trigger,
        "status": run.status,
        "size": run.size,
        "sha256": run.sha256,
        "local": bool(run.path),
        "remote": bool(run.remote_key),
        "error": run.error,
        "verify_status": run.verify_status,
        "verify_detail": run.verify_detail,
        "verified_at": run.verified_at,
        "created_by": run.created_by,
        "created_at": run.created_at,
        "finished_at": run.finished_at,
    }


def _settings_out(row) -> dict:
    return {
        "storage_enabled": row.storage_enabled,
        "endpoint": row.endpoint,
        "region": row.region,
        "bucket": row.bucket,
        "prefix": row.prefix,
        "has_credentials": bool(row.access_key and row.secret_key),
        "keep_local": row.keep_local,
        "updated_at": row.updated_at,
    }


def _audit(
    db,
    user,
    request,
    action: str,
    label: str | None,
    detail: str | None = None,
    result: str = "accepted",
) -> None:
    actor, actor_label = audit.user_actor(user)
    audit.record(
        db,
        action=action,
        result=result,
        actor=actor,
        actor_label=actor_label,
        target_type="backup",
        target_id=label,
        target_label=label,
        detail=detail,
        request=request,
    )


def _get_run(db, run_id: str) -> BackupRun:
    run = db.get(BackupRun, run_id)
    if run is None or run.deleted_at:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Backup not found")
    return run


@router.get("")
def list_runs(
    db: DbSession,
    _: AdminUser,
    instance_id: Annotated[str, Query(max_length=32)] | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    before: Annotated[str, Query(max_length=32)] | None = None,
):
    jobs.reap(db)
    return [_run_out(db, r) for r in service.list_runs(db, instance_id, limit, before)]


@router.get("/summary")
def summary(db: DbSession, _: AdminUser):
    live = select(BackupRun).where(
        BackupRun.deleted_at.is_(None), BackupRun.status == "succeeded"
    )
    size = db.scalar(
        select(func.coalesce(func.sum(BackupRun.size), 0)).where(
            BackupRun.deleted_at.is_(None), BackupRun.status == "succeeded"
        )
    )
    since = datetime.now().astimezone() - service.timedelta(days=1)
    failed = db.scalar(
        select(func.count())
        .select_from(BackupRun)
        .where(BackupRun.status == "failed", BackupRun.created_at >= since)
    )
    verified = db.scalar(
        select(func.count())
        .select_from(BackupRun)
        .where(BackupRun.verify_status == "passed", BackupRun.deleted_at.is_(None))
    )
    count = db.scalar(select(func.count()).select_from(live.subquery()))
    return {
        "size": int(size or 0),
        "count": count,
        "failed_24h": failed,
        "verified": verified,
    }


@router.get("/policies")
def policies(db: DbSession, _: AdminUser):
    out = []
    for instance in databases.list_instances(db):
        policy = service.get_policy(db, instance.id)
        out.append(
            {
                "instance_id": instance.id,
                "instance_name": instance.name,
                "engine": instance.engine,
                "status": instance.status,
                "enabled": bool(policy and policy.enabled),
                "every_hours": policy.every_hours if policy else 24,
                "keep": policy.keep if policy else 7,
                "databases": (
                    policy.databases
                    if policy and policy.databases
                    else service.default_databases(db, instance)
                ),
                "next_run_at": policy.next_run_at
                if policy and policy.enabled
                else None,
            }
        )
    return out


@router.put("/policies/{instance_id}")
def set_policy(
    instance_id: str, body: PolicyIn, request: Request, db: DbSession, user: AdminUser
):
    instance = databases.get(db, instance_id)
    if instance is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Database not found")
    policy = service.set_policy(db, instance, body.model_dump(exclude_unset=True))
    _audit(
        db,
        user,
        request,
        "backup.policy",
        instance.name,
        f"{'on' if policy.enabled else 'off'}, every {policy.every_hours}h, "
        f"keep {policy.keep}",
        result="success",
    )
    return {
        "enabled": policy.enabled,
        "every_hours": policy.every_hours,
        "keep": policy.keep,
        "databases": policy.databases,
        "next_run_at": policy.next_run_at,
    }


@router.post("/run", status_code=status.HTTP_202_ACCEPTED)
def run_now(body: RunIn, request: Request, db: DbSession, user: AdminUser):
    instance = databases.get(db, body.instance_id)
    if instance is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Database not found")
    actor, label = audit.user_actor(user)
    try:
        runs = service.run_backup(
            db, instance, body.database, "manual", actor, label, request
        )
    except service.BackupError as error:
        _raise(error)
    return [_run_out(db, r) for r in runs]


@router.post("/{run_id}/verify", status_code=status.HTTP_202_ACCEPTED)
def verify(run_id: str, request: Request, db: DbSession, user: AdminUser):
    run = _get_run(db, run_id)
    actor, label = audit.user_actor(user)
    try:
        job = service.verify(db, run, actor, label, request)
    except service.BackupError as error:
        _raise(error)
    return {"job_id": job.id}


@router.post("/{run_id}/restore", status_code=status.HTTP_202_ACCEPTED)
def restore(
    run_id: str, body: RestoreIn, request: Request, db: DbSession, user: AdminUser
):
    run = _get_run(db, run_id)
    if body.mode == "new" and not body.into:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Name the new database"
        )
    actor, label = audit.user_actor(user)
    try:
        job = service.restore(db, run, body.mode, body.into, actor, label, request)
    except service.BackupError as error:
        _raise(error)
    _audit(
        db,
        user,
        request,
        "backup.restore",
        run.database,
        f"{body.mode}{' into ' + body.into if body.into else ''} from {run.id[:10]}",
    )
    return {"job_id": job.id}


@router.delete("/{run_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete(run_id: str, request: Request, db: DbSession, user: AdminUser):
    run = _get_run(db, run_id)
    actor, label = audit.user_actor(user)
    service.delete_runs(db, [run], actor, label)
    _audit(
        db, user, request, "backup.delete", run.database, run.id[:10], result="success"
    )


@router.get("/jobs/{job_id}")
def job_status(job_id: str, db: DbSession, _: AdminUser):
    jobs.reap(db)
    job = db.get(Job, job_id)
    if job is None or not job.type.startswith("backup."):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return {"status": job.status, "error": job.error, "result": job.result or {}}


@router.get("/settings")
def get_settings(db: DbSession, _: AdminUser):
    return _settings_out(service.get_settings(db))


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, db: DbSession, user: AdminUser):
    try:
        row = service.update_settings(db, body.model_dump(exclude_unset=True))
    except service.BackupError as error:
        _raise(error)
    _audit(
        db,
        user,
        request,
        "backup.settings",
        "storage",
        "off-host on" if row.storage_enabled else "off-host off",
        result="success",
    )
    return _settings_out(row)


@router.post("/settings/test", status_code=status.HTTP_202_ACCEPTED)
def test_settings(
    db: DbSession, user: AdminUser, server_id: Annotated[str, Query(max_length=32)]
):
    actor, label = audit.user_actor(user)
    try:
        job = service.test_storage(db, server_id, actor, label)
    except service.BackupError as error:
        _raise(error)
    return {"job_id": job.id}
