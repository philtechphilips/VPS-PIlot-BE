"""Moving an app to another server.

Steps, each one a job (or a few) that this module starts and then waits for:

1. files      back up the app's files to off-server storage
2. databases  for each managed database attached to the app: a new instance
              on the target server, the app's data exported from the old one
              and imported into a new login and database there (Redis data
              isn't copied); the app's variable points at the new one
3. deploy     the app is deployed on the target server
4. restore    the files are put back there
5. domains    the target's proxy serves the app's domains too

Then it waits for DNS: the old copy keeps serving until you point the
domains at the new server and finish the move, which removes the old copy
(databases on the old server are kept; delete them when you're sure).
"""

import shutil
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.apps import service as apps
from app.apps.models import Application, AppMove, Deployment
from app.core import artifacts
from app.core.security import new_id
from app.jobs import service as jobs
from app.jobs.models import Job
from app.servers.models import Server

ACTIVE = ("running", "waiting_dns")


class MoveError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class _Wait(Exception):
    """The current step is waiting for a job."""


class _Fail(Exception):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


def active_for(db: Session, app_id: str) -> AppMove | None:
    return db.scalar(
        select(AppMove).where(
            AppMove.application_id == app_id, AppMove.status.in_(ACTIVE)
        )
    )


def latest_for(db: Session, app_id: str) -> AppMove | None:
    return db.scalar(
        select(AppMove)
        .where(AppMove.application_id == app_id)
        .order_by(AppMove.created_at.desc())
        .limit(1)
    )


def _attached(db: Session, app: Application) -> list[dict[str, Any]]:
    """Managed databases on the app's server that it has a login for."""
    from app.databases.models import DatabaseCredential, DatabaseInstance

    out = []
    for cred in db.scalars(
        select(DatabaseCredential).where(DatabaseCredential.application_id == app.id)
    ):
        instance = db.get(DatabaseInstance, cred.instance_id)
        if (
            instance is None
            or instance.mode != "managed"
            or instance.server_id != app.server_id
            or not cred.env_key
        ):
            continue
        out.append(
            {
                "source_id": instance.id,
                "source_name": instance.name,
                "engine": instance.engine,
                "version": instance.version,
                "database": cred.database,
                "env_key": cred.env_key,
                "stage": "create",
            }
        )
    return out


def plan(db: Session, app: Application) -> dict[str, Any]:
    """What a move would copy, for the dialog."""
    from app.backups import service as backups

    settings = backups.get_settings(db)
    has_files = app.runtime != "docker" or bool(app.data_path)
    return {
        "databases": [
            {"name": d["source_name"], "engine": d["engine"]}
            for d in _attached(db, app)
        ],
        "files": has_files,
        "storage": bool(settings.storage_enabled),
    }


def start(
    db: Session,
    app: Application,
    target: Server,
    include_files: bool,
    actor: str,
    label: str,
) -> AppMove:
    if target.id == app.server_id:
        raise MoveError(422, "The app already runs there")
    if target.enrolled_at is None or target.revoked_at is not None:
        raise MoveError(409, f"{target.name} has no active agent")
    if app.current_deployment_id is None:
        raise MoveError(409, "Deploy the app first; there's nothing to move yet")
    if active_for(db, app.id):
        raise MoveError(409, "This app is already being moved")
    details = plan(db, app)
    include_files = include_files and details["files"]
    if include_files and not details["storage"]:
        raise MoveError(
            409,
            "Moving files goes through your off-server backup storage: turn it on in "
            "Settings → Backup Storage, or move without the files",
        )
    move = AppMove(
        id=new_id(),
        application_id=app.id,
        source_server_id=app.server_id,
        target_server_id=target.id,
        status="running",
        step="files",
        include_files=include_files,
        state={
            "actor": actor,
            "databases": _attached(db, app),
            "host_port": app.host_port,
        },
        created_by=label[:64],
        created_at=_now(),
    )
    db.add(move)
    db.commit()
    advance(db, move)
    return move


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


def _job_done(db: Session, job_id: str | None, what: str) -> None:
    """Returns when the job succeeded; raises _Wait or _Fail otherwise."""
    job = db.get(Job, job_id) if job_id else None
    if job is None:
        raise _Fail(f"{what}: the job is gone")
    if job.status in ("queued", "running"):
        raise _Wait()
    if job.status != "succeeded":
        raise _Fail(f"{what} failed: {job.error or job.status}")


def _files(db: Session, move: AppMove, app: Application) -> None:
    from app.backups import service as backups

    state = move.state
    if not move.include_files:
        return
    if "backup_run" not in state:
        run = backups.run_app_backup(db, app, "manual", state["actor"], move.created_by)
        state["backup_run"], state["backup_job"] = run.id, run.job_id
        raise _Wait()
    _job_done(db, state["backup_job"], "Backing up the app's files")


def _database(
    db: Session, move: AppMove, app: Application, entry: dict[str, Any]
) -> None:
    from app.databases import service as databases
    from app.databases.models import DatabaseCredential, DatabaseInstance

    actor, label = move.state["actor"], move.created_by
    sql = entry["engine"] != "redis"
    if entry["stage"] == "create":
        name = entry["source_name"]
        taken = {i.name for i in db.scalars(select(DatabaseInstance))}
        n = 2
        while f"{name}-{n}" in taken:
            n += 1
        instance, job = databases.create_managed(
            db,
            {
                "name": f"{name}-{n}"[:40],
                "server_id": move.target_server_id,
                "engine": entry["engine"],
                "version": entry["version"],
            },
            actor,
            label,
        )
        entry.update(
            target_id=instance.id,
            target_name=instance.name,
            job=job.id,
            stage="creating",
        )
        raise _Wait()
    if entry["stage"] == "creating":
        _job_done(db, entry["job"], f"Creating {entry['target_name']}")
        entry["stage"] = "export" if sql and entry["database"] else "attach"
    if entry["stage"] == "export":
        source = db.get(DatabaseInstance, entry["source_id"])
        if source is None:
            raise _Fail(f"{entry['source_name']} was removed")
        job = databases.export(db, source, entry["database"], actor, label)
        entry.update(job=job.id, export_job=job.id, stage="exporting")
        raise _Wait()
    if entry["stage"] == "exporting":
        _job_done(db, entry["job"], f"Exporting {entry['source_name']}")
        entry["stage"] = "attach"
    if entry["stage"] == "attach":
        target = db.get(DatabaseInstance, entry["target_id"])
        # Point the variable at the new database: drop it, keeping the old
        # value to put back if the move is canceled.
        kept = [e for e in app.env or [] if e["key"] != entry["env_key"]]
        old = next((e for e in app.env or [] if e["key"] == entry["env_key"]), None)
        entry["old_env"] = old
        app.env = kept
        username = databases._unique_username(db, target, app.name)
        if sql:
            databases.create_database(db, target, username, None, actor, label)
        cred, job = databases.create_user(
            db,
            target,
            username,
            username if sql else None,
            "owner" if entry["engine"] == "postgres" else "readwrite",
            actor,
            label,
            application=app,
            env_key=entry["env_key"],
        )
        entry.update(
            job=job.id, credential_id=cred.id, new_database=username, stage="attaching"
        )
        raise _Wait()
    if entry["stage"] == "attaching":
        _job_done(
            db, entry["job"], f"Creating {app.name}'s login on {entry['target_name']}"
        )
        cred = db.get(DatabaseCredential, entry["credential_id"])
        if cred is None or cred.status != "active":
            raise _Wait()
        entry["stage"] = "import" if entry.get("export_job") else "done"
    if entry["stage"] == "import":
        upload = new_id()
        source_file = artifacts.path_for(f"{entry['export_job']}.out")
        shutil.copyfile(source_file, artifacts.path_for(f"{upload}.in"))
        target = db.get(DatabaseInstance, entry["target_id"])
        job = databases.queue_import(
            db,
            target,
            entry["new_database"],
            upload,
            artifacts.size(f"{upload}.in"),
            actor,
            move.created_by,
        )
        entry.update(job=job.id, stage="importing")
        raise _Wait()
    if entry["stage"] == "importing":
        _job_done(db, entry["job"], f"Importing into {entry['target_name']}")
        entry["stage"] = "done"


def _deploy(db: Session, move: AppMove, app: Application) -> None:
    state = move.state
    if "deployment" not in state:
        target = db.get(Server, move.target_server_id)
        app.server_id = target.id
        if apps._port_conflict(db, target, app.host_port, app):
            app.host_port = apps._next_host_port(db, target)
        deployment = apps.deploy(db, app, state["actor"], move.created_by)
        state["deployment"] = deployment.id
        raise _Wait()
    deployment = db.get(Deployment, state["deployment"])
    if deployment is None or deployment.status in ("queued", "running"):
        raise _Wait()
    if deployment.status != "succeeded":
        reason = deployment.error or deployment.status
        raise _Fail(f"The deploy on the new server failed: {reason}")


def _restore(db: Session, move: AppMove, app: Application) -> None:
    from app.backups import service as backups
    from app.backups.models import BackupRun

    state = move.state
    if not move.include_files:
        return
    if "restore_job" not in state:
        run = db.get(BackupRun, state["backup_run"])
        job = backups.restore(db, run, "replace", None, state["actor"], move.created_by)
        state["restore_job"] = job.id
        raise _Wait()
    _job_done(db, state["restore_job"], "Restoring the files")


STEPS = ("files", "databases", "deploy", "restore", "domains")


def advance(db: Session, move: AppMove) -> None:
    """Do whatever the move can do now; it picks up where it left off."""
    if move.status != "running":
        return
    app = db.get(Application, move.application_id)
    if app is None:
        move.status, move.error = "failed", "The app was removed"
        db.commit()
        return
    state = dict(move.state)
    move.state = state
    try:
        while True:
            if move.step == "files":
                _files(db, move, app)
                move.step = "databases"
            elif move.step == "databases":
                entries = [dict(e) for e in state["databases"]]
                state["databases"] = entries
                for entry in entries:
                    if entry["stage"] != "done":
                        _database(db, move, app, entry)
                move.step = "deploy"
            elif move.step == "deploy":
                _deploy(db, move, app)
                move.step = "restore"
            elif move.step == "restore":
                _restore(db, move, app)
                move.step = "domains"
            elif move.step == "domains":
                _apply_proxy(db, move.target_server_id, move)
                move.step, move.status = "dns", "waiting_dns"
                break
            else:
                break
    except _Wait:
        pass
    except (_Fail, MoveError) as error:
        move.status, move.error = "failed", str(error)[:500]
        _undo(db, move, app)
    except Exception as error:  # noqa: BLE001 - a step's own error (e.g. DbError)
        move.status = "failed"
        move.error = str(getattr(error, "detail", error))[:500]
        _undo(db, move, app)
    move.state = {**state}
    db.commit()


def _apply_proxy(db: Session, server_id: str, move: AppMove) -> None:
    from app.domains import service as domains

    try:
        domains.apply(db, server_id, move.state["actor"], move.created_by)
    except domains.DomainError:
        pass


def _undo(db: Session, move: AppMove, app: Application) -> None:
    """Back to the old server: the app record, its variables and the proxy.
    New databases on the target are kept for you to look at or delete."""
    state = move.state
    if app.server_id != move.source_server_id:
        target = db.get(Server, move.target_server_id)
        app.server_id = move.source_server_id
        app.host_port = state.get("host_port", app.host_port)
        if target is not None:
            try:
                jobs.create(
                    db,
                    target,
                    "app.remove",
                    {"app": app.name},
                    state["actor"],
                    move.created_by,
                )
            except jobs.JobError:
                pass
    env = [e for e in app.env or []]
    for entry in state.get("databases", []):
        old = entry.get("old_env")
        if old:
            env = [e for e in env if e["key"] != entry["env_key"]] + [old]
    app.env = env
    old_deploy = db.scalar(
        select(Deployment)
        .where(
            Deployment.application_id == app.id,
            Deployment.server_id == move.source_server_id,
            Deployment.status == "succeeded",
        )
        .order_by(Deployment.created_at.desc())
        .limit(1)
    )
    if old_deploy is not None:
        app.current_deployment_id = old_deploy.id
    move.finished_at = _now()
    db.flush()
    _apply_proxy(db, move.target_server_id, move)


def finish(db: Session, move: AppMove, actor: str, label: str) -> AppMove:
    """DNS points at the new server: take the domains over, remove the old copy."""
    from app.domains.models import Domain

    if move.status != "waiting_dns":
        raise MoveError(409, "The move isn't ready to finish")
    app = db.get(Application, move.application_id)
    for domain in db.scalars(select(Domain).where(Domain.application_id == app.id)):
        domain.server_id = move.target_server_id
    move.status, move.step, move.finished_at = "done", "finished", _now()
    db.flush()
    source = db.get(Server, move.source_server_id)
    _apply_proxy(db, move.source_server_id, move)
    _apply_proxy(db, move.target_server_id, move)
    if source is not None and source.enrolled_at and not source.revoked_at:
        try:
            jobs.create(db, source, "app.remove", {"app": app.name}, actor, label)
        except jobs.JobError:
            pass
    db.commit()
    return move


def cancel(db: Session, move: AppMove) -> AppMove:
    if move.status not in ACTIVE:
        raise MoveError(409, "The move is over")
    app = db.get(Application, move.application_id)
    move.status, move.error = "canceled", None
    if app is not None:
        _undo(db, move, app)
    db.commit()
    return move


def moving_domains(db: Session, server_id: str) -> list[Any]:
    """Domains a target server serves while it waits for DNS."""
    from app.domains.models import Domain

    out = []
    for move in db.scalars(
        select(AppMove).where(
            AppMove.status == "waiting_dns", AppMove.target_server_id == server_id
        )
    ):
        out += list(
            db.scalars(
                select(Domain).where(Domain.application_id == move.application_id)
            )
        )
    return out


def on_job_finished(db: Session, job: Job) -> None:
    for move in db.scalars(select(AppMove).where(AppMove.status == "running")):
        advance(db, move)


def advance_all(db: Session) -> None:
    for move in db.scalars(select(AppMove).where(AppMove.status == "running")):
        advance(db, move)


jobs.after_finished.append(on_job_finished)
