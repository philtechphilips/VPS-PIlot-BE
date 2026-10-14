"""Backups of databases: scheduling, runs, retention, verify and restore.

The agent dumps, encrypts (AES-256, key held here, encrypted at rest) and
optionally uploads to S3-compatible storage; this module decides what runs
when, keeps the records and prunes old backups.
"""

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.backups.models import BackupPolicy, BackupRun, BackupSettings
from app.core.security import decrypt_secret, encrypt_secret, new_id
from app.databases import service as databases
from app.databases.models import DatabaseCredential, DatabaseInstance
from app.jobs import service as jobs
from app.jobs.models import Job
from app.servers.models import Server

PURPOSE = "backup"


class BackupError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    return value if value is None or value.tzinfo else value.replace(tzinfo=UTC)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def get_settings(db: Session) -> BackupSettings:
    row = db.get(BackupSettings, 1)
    if row is None:
        # The key that encrypts every backup; generated once, never shown.
        row = BackupSettings(
            id=1,
            encryption_key=encrypt_secret(secrets.token_hex(32), PURPOSE),
            storage_enabled=False,
            keep_local=True,
        )
        db.add(row)
        db.commit()
    return row


def update_settings(db: Session, data: dict[str, Any]) -> BackupSettings:
    row = get_settings(db)
    for field in (
        "storage_enabled",
        "provider",
        "endpoint",
        "region",
        "bucket",
        "prefix",
        "keep_local",
        "gdrive_client_id",
    ):
        if field in data and data[field] is not None:
            setattr(row, field, data[field])
    for field in ("access_key", "secret_key", "gdrive_client_secret"):
        if data.get(field):
            setattr(row, field, encrypt_secret(data[field], PURPOSE))
    if row.storage_enabled and _config(row, row.provider) is None:
        db.rollback()
        raise BackupError(
            422,
            "Connect Google Drive first"
            if row.provider == "gdrive"
            else "Fill in the endpoint, bucket and both keys to turn on off-host "
            "storage",
        )
    row.updated_at = _now()
    db.commit()
    return row


def _config(row: BackupSettings, provider: str) -> dict[str, Any] | None:
    """Storage for jobs, when that provider is set up."""
    if provider == "gdrive":
        if not (row.gdrive_refresh_token and row.gdrive_folder_id):
            return None
        return {"provider": "gdrive", "folder_id": row.gdrive_folder_id}
    if not (row.endpoint and row.bucket and row.access_key and row.secret_key):
        return None
    return {
        "provider": "s3",
        "endpoint": row.endpoint.rstrip("/"),
        "region": row.region or "auto",
        "bucket": row.bucket,
        "prefix": row.prefix or "",
    }


def _storage(row: BackupSettings) -> dict[str, Any] | None:
    """Where new backups are copied (None: kept on the server only)."""
    return _config(row, row.provider) if row.storage_enabled else None


def _storage_of(row: BackupSettings, run: BackupRun) -> dict[str, Any] | None:
    """Where an existing backup's remote copy lives."""
    if not run.remote_key:
        return None
    return _config(row, run.storage or "s3")


def job_secrets(db: Session, job: Job) -> dict[str, Any]:
    row = get_settings(db)
    out: dict[str, Any] = {"backup_key": decrypt_secret(row.encryption_key, PURPOSE)}
    storage = job.payload.get("storage") or {}
    if storage.get("provider") == "gdrive":
        from app.backups import gdrive

        try:
            out["gdrive_token"] = gdrive.access_token(row)
        except gdrive.DriveError:
            pass  # the agent reports the missing access
    elif storage and row.access_key and row.secret_key:
        out["s3_access_key"] = decrypt_secret(row.access_key, PURPOSE)
        out["s3_secret_key"] = decrypt_secret(row.secret_key, PURPOSE)
    instance = db.get(DatabaseInstance, job.payload.get("instance_id") or "")
    if instance is not None and instance.admin_password:
        out["password"] = decrypt_secret(instance.admin_password, databases.PURPOSE)
    if instance is not None and instance.tls_ca:
        out["ca"] = instance.tls_ca
    return out


def test_storage(db: Session, server_id: str, actor: str, label: str) -> Job:
    row = get_settings(db)
    storage = _storage(row)
    if storage is None:
        raise BackupError(422, "Turn on off-host storage first")
    server = db.get(Server, server_id)
    if server is None:
        raise BackupError(404, "Server not found")
    try:
        job, _ = jobs.create(
            db,
            server,
            "backup.storage_test",
            {"storage": storage, "has_secrets": True},
            actor,
            label,
        )
    except jobs.JobError as error:
        raise BackupError(error.status_code, error.detail) from None
    return job


# ---------------------------------------------------------------------------
# Policies and runs
# ---------------------------------------------------------------------------


def get_policy(db: Session, instance_id: str) -> BackupPolicy | None:
    return db.scalar(
        select(BackupPolicy).where(BackupPolicy.instance_id == instance_id)
    )


def set_policy(
    db: Session, instance: DatabaseInstance, data: dict[str, Any]
) -> BackupPolicy:
    policy = get_policy(db, instance.id)
    if policy is None:
        policy = BackupPolicy(
            id=new_id(), instance_id=instance.id, databases=[], created_at=_now()
        )
        db.add(policy)
    for field in ("enabled", "every_hours", "keep"):
        if data.get(field) is not None:
            setattr(policy, field, data[field])
    if data.get("databases") is not None:
        policy.databases = (
            [] if instance.engine == "redis" else list(dict.fromkeys(data["databases"]))
        )
    if policy.enabled:
        # Next run: soon if never run, else after the interval.
        last = db.scalar(
            select(BackupRun.created_at)
            .where(BackupRun.instance_id == instance.id)
            .order_by(BackupRun.created_at.desc())
            .limit(1)
        )
        policy.next_run_at = (
            (_aware(last) + timedelta(hours=policy.every_hours))
            if last
            else _now() + timedelta(minutes=1)
        )
    db.commit()
    return policy


def default_databases(db: Session, instance: DatabaseInstance) -> list[str]:
    if instance.engine == "redis":
        return ["redis"]
    names = [instance.default_database] if instance.default_database else []
    names += [
        c.database
        for c in db.scalars(
            select(DatabaseCredential).where(
                DatabaseCredential.instance_id == instance.id
            )
        )
        if c.database
    ]
    return list(dict.fromkeys(names))


def _target_and_storage(
    db: Session, instance: DatabaseInstance
) -> tuple[dict[str, Any], dict[str, Any] | None, bool]:
    row = get_settings(db)
    return databases.target(instance), _storage(row), row.keep_local


def run_backup(
    db: Session,
    instance: DatabaseInstance,
    database: str | None,
    trigger: str,
    actor: str,
    label: str,
    request=None,
) -> list[BackupRun]:
    if instance.status not in ("running", "stopped"):
        raise BackupError(409, "The database isn't ready")
    if database:
        names = [database]
    else:
        policy = get_policy(db, instance.id)
        names = (
            policy.databases if policy and policy.databases else None
        ) or default_databases(db, instance)
    if not names:
        raise BackupError(422, "Pick a database to back up")
    server = db.get(Server, instance.server_id)
    target, storage, keep_local = _target_and_storage(db, instance)
    runs = []
    for name in names:
        run = BackupRun(
            id=new_id(),
            instance_id=instance.id,
            database=name,
            trigger=trigger,
            status="queued",
            created_by=label[:64],
            created_at=_now(),
            meta={},
        )
        db.add(run)
        db.flush()
        payload: dict[str, Any] = {
            "target": target,
            "instance_id": instance.id,
            "backup_id": run.id,
            "database": None if instance.engine == "redis" else name,
            "keep_local": keep_local,
            "has_secrets": True,
        }
        if storage:
            payload["storage"] = storage
        try:
            job, _ = jobs.create(
                db, server, "backup.create", payload, actor, label, request=request
            )
        except jobs.JobError as error:
            db.delete(run)
            db.commit()
            raise BackupError(error.status_code, error.detail) from None
        run.job_id = job.id
        runs.append(run)
    db.commit()
    return runs


def _restore_job(
    db: Session,
    run: BackupRun,
    mode: str,
    into: str | None,
    actor: str,
    label: str,
    request=None,
) -> Job:
    if run.status != "succeeded" or run.deleted_at:
        raise BackupError(
            409, "Only finished, kept backups can be restored or verified"
        )
    instance = db.get(DatabaseInstance, run.instance_id)
    if instance is None or instance.status != "running":
        raise BackupError(409, "The database must be running")
    if instance.engine == "redis" and mode == "new":
        raise BackupError(409, "Redis snapshots restore into the same instance")
    if instance.engine == "redis" and mode == "replace" and instance.mode != "managed":
        raise BackupError(
            409, "Restore external Redis by hand; VPSPilot replaces data it runs"
        )
    target = databases.target(instance)
    storage = _storage_of(get_settings(db), run)
    payload: dict[str, Any] = {
        "target": target,
        "instance_id": instance.id,
        "backup_id": run.id,
        "database": None if instance.engine == "redis" else run.database,
        "mode": mode,
        "path": run.path,
        "remote_key": run.remote_key,
        "sha256": run.sha256,
        "has_secrets": True,
    }
    if into:
        payload["into"] = into
    if storage and run.remote_key:
        payload["storage"] = storage
    try:
        job, _ = jobs.create(
            db,
            db.get(Server, instance.server_id),
            "backup.restore",
            payload,
            actor,
            label,
            request=request,
        )
    except jobs.JobError as error:
        raise BackupError(error.status_code, error.detail) from None
    return job


def verify(db: Session, run: BackupRun, actor: str, label: str, request=None) -> Job:
    job = _restore_job(db, run, "verify", None, actor, label, request)
    run.verify_status, run.verify_detail = "running", None
    db.commit()
    return job


def restore(
    db: Session,
    run: BackupRun,
    mode: str,
    into: str | None,
    actor: str,
    label: str,
    request=None,
) -> Job:
    return _restore_job(db, run, mode, into, actor, label, request)


def delete_runs(db: Session, runs: list[BackupRun], actor: str, label: str) -> None:
    """Remove backup files (local and remote) and mark the runs deleted."""
    by_instance: dict[str, list[BackupRun]] = {}
    for run in runs:
        by_instance.setdefault(run.instance_id, []).append(run)
    for instance_id, items in by_instance.items():
        instance = db.get(DatabaseInstance, instance_id)
        server = db.get(Server, instance.server_id) if instance else None
        row = get_settings(db)
        # One job per place the remote copies live (local files go with any).
        groups: dict[str, list[BackupRun]] = {}
        for r in items:
            if r.path or r.remote_key:
                groups.setdefault(r.storage or "s3", []).append(r)
        for provider, group in groups.items() if server else ():
            payload: dict[str, Any] = {
                "items": [{"path": r.path, "remote_key": r.remote_key} for r in group],
                "has_secrets": True,
            }
            storage = _config(row, provider)
            if storage:
                payload["storage"] = storage
            try:
                jobs.create(
                    db, server, "backup.delete", payload, actor, label, audited=False
                )
            except jobs.JobError:
                pass
        for run in items:
            run.deleted_at = _now()
    db.commit()


def _prune(db: Session, instance_id: str, database: str) -> None:
    policy = get_policy(db, instance_id)
    keep = policy.keep if policy else 7
    kept = list(
        db.scalars(
            select(BackupRun)
            .where(
                BackupRun.instance_id == instance_id,
                BackupRun.database == database,
                BackupRun.status == "succeeded",
                BackupRun.deleted_at.is_(None),
            )
            .order_by(BackupRun.created_at.desc())
        )
    )
    if len(kept) > keep:
        delete_runs(db, kept[keep:], "system", "Retention")


def run_due(db: Session) -> int:
    """Called by the background loop: start scheduled backups that are due."""
    started = 0
    for policy in db.scalars(
        select(BackupPolicy).where(BackupPolicy.enabled.is_(True))
    ):
        if policy.next_run_at is None or _aware(policy.next_run_at) > _now():
            continue
        instance = db.get(DatabaseInstance, policy.instance_id)
        policy.next_run_at = _now() + timedelta(hours=policy.every_hours)
        db.commit()
        if instance is None or instance.status != "running":
            continue
        try:
            started += len(
                run_backup(db, instance, None, "scheduled", "system", "Schedule")
            )
        except BackupError:
            continue
    return started


def list_runs(
    db: Session,
    instance_id: str | None = None,
    limit: int = 50,
    before: str | None = None,
) -> list[BackupRun]:
    query = (
        select(BackupRun)
        .where(BackupRun.deleted_at.is_(None))
        .order_by(BackupRun.created_at.desc(), BackupRun.id)
        .limit(limit)
    )
    if instance_id:
        query = query.where(BackupRun.instance_id == instance_id)
    if before:
        cursor = db.get(BackupRun, before)
        if cursor is not None:
            query = query.where(
                (BackupRun.created_at < cursor.created_at)
                | (
                    (BackupRun.created_at == cursor.created_at)
                    & (BackupRun.id > cursor.id)
                )
            )
    return list(db.scalars(query))


# ---------------------------------------------------------------------------
# Job outcomes
# ---------------------------------------------------------------------------


def on_job_finished(db: Session, job: Job) -> None:
    if not job.type.startswith("backup."):
        return
    run = db.get(BackupRun, job.payload.get("backup_id") or "")
    if run is None:
        return
    ok = job.status == "succeeded"
    result = job.result or {}
    if job.type == "backup.create":
        run.finished_at = _now()
        if ok:
            run.status = "succeeded"
            run.path, run.remote_key = result.get("path"), result.get("remote_key")
            run.storage = (
                (result.get("storage") or "s3")[:16] if run.remote_key else None
            )
            run.size, run.sha256 = result.get("size"), result.get("sha256")
            db.flush()
            _prune(db, run.instance_id, run.database)
        else:
            run.status = "failed"
            run.error = (job.error or f"Job {job.status}")[:500]
    elif job.type == "backup.restore" and job.payload.get("mode") == "verify":
        run.verified_at = _now()
        run.verify_status = "passed" if ok else "failed"
        run.verify_detail = (
            f"Restored {result.get('tables', 0)} tables into a throwaway database"
            if ok and job.payload.get("database")
            else "Snapshot decrypted and valid"
            if ok
            else (job.error or "Verification failed")
        )[:300]


jobs.on_finished.append(on_job_finished)
