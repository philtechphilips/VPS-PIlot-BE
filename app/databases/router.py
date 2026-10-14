from datetime import datetime
from typing import Annotated, Literal, NoReturn

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, StringConstraints

from app.apps.models import Application
from app.audit import service as audit
from app.auth.dependencies import AdminUser
from app.core import artifacts
from app.core.config import settings
from app.core.database import DbSession
from app.core.security import new_id
from app.databases import service
from app.databases.models import DatabaseCredential, DatabaseInstance
from app.jobs import service as jobs
from app.jobs.types import DbHost, DbIdent, DbObject, HostPort, Port
from app.servers.models import Server

router = APIRouter(prefix="/api/v1/databases", tags=["Databases"])

Engine = Literal["postgres", "mysql", "mariadb", "redis"]
Name = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=40)
]
EnvKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")]


def _raise(error: service.DbError) -> NoReturn:
    raise HTTPException(status_code=error.status_code, detail=error.detail)


class ManagedCreate(BaseModel):
    name: Name
    server_id: Annotated[str, StringConstraints(max_length=32)]
    engine: Engine
    version: Annotated[str, StringConstraints(max_length=8)] | None = None
    database: DbIdent | None = None
    local_port: HostPort | None = None


# disable: no TLS; require: encrypted, certificate not checked;
# verify: encrypted and the certificate must match the host.
TlsMode = Literal["disable", "require", "verify"]
CaPem = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        max_length=65536,
        pattern=r"^(-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+"
        r"-----END CERTIFICATE-----\s*)+$",
    ),
]


class ExternalCreate(BaseModel):
    name: Name
    server_id: Annotated[str, StringConstraints(max_length=32)]
    engine: Engine
    host: DbHost
    port: Port | None = None
    user: (
        Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.@-]{1,63}$")] | None
    ) = None
    password: Annotated[str, StringConstraints(max_length=512)] | None = None
    database: DbIdent | None = None
    tls_mode: TlsMode = "verify"
    ca: CaPem | None = None


class TlsIn(BaseModel):
    tls_mode: TlsMode
    # None keeps the stored CA; "" removes it (system CAs are used).
    ca: CaPem | Literal[""] | None = None


class ControlIn(BaseModel):
    action: Literal["start", "stop", "restart"]


class QueryIn(BaseModel):
    sql: Annotated[str, StringConstraints(min_length=1, max_length=100_000)]
    database: DbIdent | None = None
    readonly: bool = True
    max_rows: Annotated[int, Field(ge=1, le=1000)] = 500


class ExploreIn(BaseModel):
    what: Literal["databases", "users", "stats", "tables", "columns"]
    database: DbIdent | None = None
    namespace: DbObject | None = None
    table: DbObject | None = None


class RedisIn(BaseModel):
    action: Literal["info", "scan", "get", "delete", "acl_list"]
    pattern: Annotated[str, StringConstraints(max_length=200)] | None = None
    cursor: Annotated[int, Field(ge=0)] = 0
    count: Annotated[int, Field(ge=1, le=1000)] = 100
    key: Annotated[str, StringConstraints(max_length=512)] | None = None


class DatabaseIn(BaseModel):
    name: DbIdent
    owner: DbIdent | None = None


class UserIn(BaseModel):
    username: DbIdent
    database: DbIdent | None = None
    access: Literal["owner", "readwrite", "readonly"] = "readwrite"
    # Redis: the keys this login may use, e.g. "cache:*" (default: all).
    key_pattern: (
        Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:*{}\[\]-]{1,63}$")]
        | None
    ) = None


class AttachIn(BaseModel):
    application_id: Annotated[str, StringConstraints(max_length=32)]
    env_key: EnvKey = "DATABASE_URL"


class InstanceOut(BaseModel):
    id: str
    name: str
    engine: str
    engine_label: str
    version: str
    mode: str
    server_id: str
    server_name: str | None
    host: str
    port: int
    admin_user: str | None
    default_database: str | None
    local_port: int | None
    status: str
    error: str | None
    server_version: str | None
    tls_mode: str | None
    has_ca: bool
    created_by: str
    created_at: datetime
    users: int


def _out(db, instance: DatabaseInstance) -> InstanceOut:
    server = db.get(Server, instance.server_id)
    return InstanceOut(
        id=instance.id,
        name=instance.name,
        engine=instance.engine,
        engine_label=service.ENGINES[instance.engine]["label"],
        version=instance.version,
        mode=instance.mode,
        server_id=instance.server_id,
        server_name=server.name if server else None,
        host=f"vpdb-{instance.name}"
        if instance.mode == "managed"
        else (instance.host or ""),
        port=instance.port,
        admin_user=instance.admin_user,
        default_database=instance.default_database,
        local_port=instance.local_port,
        status=service.live_status(db, instance),
        error=instance.error,
        server_version=instance.server_version,
        tls_mode=instance.tls_mode,
        has_ca=bool(instance.tls_ca),
        created_by=instance.created_by,
        created_at=instance.created_at,
        users=len(service.credentials(db, instance)),
    )


def _get(db, instance_id: str) -> DatabaseInstance:
    instance = service.get(db, instance_id)
    if instance is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Database not found")
    return instance


def _audit(
    db,
    user,
    request,
    action: str,
    instance: DatabaseInstance,
    detail: str | None = None,
    result: str = "accepted",
) -> None:
    actor, label = audit.user_actor(user)
    audit.record(
        db,
        action=action,
        result=result,
        actor=actor,
        actor_label=label,
        target_type="database",
        target_id=instance.id,
        target_label=instance.name,
        detail=detail,
        request=request,
    )


def _job(job) -> dict:
    return {"job_id": job.id}


@router.get("/engines")
def engines(_: AdminUser):
    return service.engines()


@router.get("", response_model=list[InstanceOut])
def list_databases(db: DbSession, _: AdminUser):
    jobs.reap(db)
    return [_out(db, i) for i in service.list_instances(db)]


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def create_managed(
    body: ManagedCreate, request: Request, db: DbSession, user: AdminUser
):
    """Run a new database container on the server. Poll the job/instance."""
    actor, label = audit.user_actor(user)
    try:
        instance, job = service.create_managed(
            db, body.model_dump(), actor, label, request
        )
    except service.DbError as error:
        _raise(error)
    _audit(
        db,
        user,
        request,
        "database.create",
        instance,
        f"{instance.engine} {instance.version} on {body.server_id}",
    )
    return {"database": _out(db, instance), "job_id": job.id}


@router.post("/external", status_code=status.HTTP_202_ACCEPTED)
def connect_external(
    body: ExternalCreate, request: Request, db: DbSession, user: AdminUser
):
    """Register a database you already run; the agent tests the connection."""
    actor, label = audit.user_actor(user)
    try:
        instance, job = service.connect_external(
            db, body.model_dump(), actor, label, request
        )
    except service.DbError as error:
        _raise(error)
    _audit(
        db,
        user,
        request,
        "database.connect",
        instance,
        f"{instance.engine} at {instance.host}:{instance.port}",
    )
    return {"database": _out(db, instance), "job_id": job.id}


@router.get("/{instance_id}", response_model=InstanceOut)
def get_database(instance_id: str, db: DbSession, _: AdminUser):
    jobs.reap(db)
    return _out(db, _get(db, instance_id))


class ExportIn(BaseModel):
    database: DbIdent


@router.post("/{instance_id}/export", status_code=status.HTTP_202_ACCEPTED)
def export_database(
    instance_id: str, body: ExportIn, request: Request, db: DbSession, user: AdminUser
):
    """Dump one database as SQL (gzip). Download it when the job succeeds."""
    instance = _get(db, instance_id)
    actor, label = audit.user_actor(user)
    try:
        job = service.export(db, instance, body.database, actor, label, request)
    except service.DbError as error:
        _raise(error)
    _audit(db, user, request, "database.export", instance, body.database)
    return _job(job)


@router.get("/{instance_id}/exports/{job_id}")
def download_export(
    instance_id: str, job_id: str, request: Request, db: DbSession, user: AdminUser
):
    instance = _get(db, instance_id)
    try:
        name, filename = service.export_file(db, instance, job_id)
    except service.DbError as error:
        _raise(error)
    _audit(db, user, request, "database.export.download", instance, filename)
    return StreamingResponse(
        artifacts.read(name),
        media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/{instance_id}/import", status_code=status.HTTP_202_ACCEPTED)
async def import_database(
    instance_id: str,
    request: Request,
    db: DbSession,
    user: AdminUser,
    database: Annotated[str, Query(pattern=r"^[a-z_][a-z0-9_]{0,62}$")],
):
    """Upload a .sql, .sql.gz or pg_dump file as the request body; the agent
    loads it into `database` (one transaction on PostgreSQL)."""
    instance = _get(db, instance_id)
    if instance.engine == "redis":
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Use backups for Redis"
        )
    upload_id = new_id()
    try:
        size = await artifacts.write(
            f"{upload_id}.in",
            request.stream(),
            settings.max_transfer_mb * 1024 * 1024,
        )
    except artifacts.TooLarge as error:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, str(error)) from None
    if size == 0:
        artifacts.delete(f"{upload_id}.in")
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "The file is empty")
    actor, label = audit.user_actor(user)
    try:
        job = service.queue_import(
            db, instance, database, upload_id, size, actor, label, request
        )
    except service.DbError as error:
        artifacts.delete(f"{upload_id}.in")
        _raise(error)
    _audit(db, user, request, "database.import", instance, f"{database} ({size} bytes)")
    return _job(job)


@router.get("/{instance_id}/metrics")
def database_metrics(
    instance_id: str,
    db: DbSession,
    _: AdminUser,
    hours: Annotated[int, Query(ge=1, le=24 * 30)] = 24,
):
    """Samples every 5 minutes: connections, size (SQL), memory/keys/ops (Redis)."""
    instance = _get(db, instance_id)
    return [
        {
            "ts": m.ts,
            "connections": m.connections,
            "max_connections": m.max_connections,
            "size_bytes": m.size_bytes,
            "memory_bytes": m.memory_bytes,
            "keys": m.keys,
            "ops_per_sec": m.ops_per_sec,
        }
        for m in service.metrics(db, instance, hours)
    ]


@router.put("/{instance_id}/tls", status_code=status.HTTP_202_ACCEPTED)
def update_tls(
    instance_id: str, body: TlsIn, request: Request, db: DbSession, user: AdminUser
):
    """Change how an external database is reached; the agent re-checks."""
    instance = _get(db, instance_id)
    actor, label = audit.user_actor(user)
    try:
        job = service.update_tls(db, instance, body.tls_mode, body.ca, actor, label)
    except service.DbError as error:
        _raise(error)
    _audit(db, user, request, "database.tls", instance, body.tls_mode)
    return {"database": _out(db, instance), "job_id": job.id}


@router.delete("/{instance_id}", status_code=status.HTTP_202_ACCEPTED)
def remove_database(
    instance_id: str,
    request: Request,
    db: DbSession,
    user: AdminUser,
    delete_data: bool = False,
):
    instance = _get(db, instance_id)
    actor, label = audit.user_actor(user)
    _audit(
        db,
        user,
        request,
        "database.remove",
        instance,
        "with data" if delete_data else "data kept",
    )
    job = service.remove(db, instance, delete_data, actor, label, request)
    return {"job_id": job.id if job else None}


@router.post("/{instance_id}/control", status_code=status.HTTP_202_ACCEPTED)
def control(
    instance_id: str, body: ControlIn, request: Request, db: DbSession, user: AdminUser
):
    instance = _get(db, instance_id)
    actor, label = audit.user_actor(user)
    try:
        return _job(service.control(db, instance, body.action, actor, label, request))
    except service.DbError as error:
        _raise(error)


@router.get("/{instance_id}/connection")
def connection(instance_id: str, request: Request, db: DbSession, user: AdminUser):
    """Logins with passwords and ready-made URLs. Viewing is audited."""
    instance = _get(db, instance_id)
    _audit(db, user, request, "database.credentials.view", instance, result="success")
    return service.connection_details(db, instance)


@router.post("/{instance_id}/query", status_code=status.HTTP_202_ACCEPTED)
def query(
    instance_id: str, body: QueryIn, request: Request, db: DbSession, user: AdminUser
):
    instance = _get(db, instance_id)
    actor, label = audit.user_actor(user)
    try:
        job, q = service.run_query(
            db,
            instance,
            body.sql,
            body.database,
            body.readonly,
            body.max_rows,
            actor,
            label,
            request,
        )
    except service.DbError as error:
        _raise(error)
    # The SQL itself can hold secrets: the audit log gets its fingerprint.
    _audit(
        db,
        user,
        request,
        "database.query",
        instance,
        f"{'read-only' if body.readonly else 'read-write'} query {q.fingerprint}"
        + (f" on {body.database}" if body.database else ""),
    )
    return _job(job)


@router.post("/{instance_id}/explore", status_code=status.HTTP_202_ACCEPTED)
def explore(instance_id: str, body: ExploreIn, db: DbSession, user: AdminUser):
    instance = _get(db, instance_id)
    if instance.engine == "redis":
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Use the key browser for Redis"
        )
    actor, label = audit.user_actor(user)
    try:
        return _job(service.explore(db, instance, body.model_dump(), actor, label))
    except service.DbError as error:
        _raise(error)


@router.post("/{instance_id}/redis", status_code=status.HTTP_202_ACCEPTED)
def redis(
    instance_id: str, body: RedisIn, request: Request, db: DbSession, user: AdminUser
):
    instance = _get(db, instance_id)
    actor, label = audit.user_actor(user)
    try:
        return _job(
            service.redis_op(db, instance, body.model_dump(), actor, label, request)
        )
    except service.DbError as error:
        _raise(error)


@router.get("/{instance_id}/jobs/{job_id}")
def job_result(instance_id: str, job_id: str, db: DbSession, _: AdminUser):
    """Poll an operation: {status, error, data}."""
    jobs.reap(db)
    instance = _get(db, instance_id)
    try:
        return service.job_result(db, instance, job_id)
    except service.DbError as error:
        _raise(error)


@router.post("/{instance_id}/databases", status_code=status.HTTP_202_ACCEPTED)
def create_database(
    instance_id: str, body: DatabaseIn, request: Request, db: DbSession, user: AdminUser
):
    instance = _get(db, instance_id)
    actor, label = audit.user_actor(user)
    try:
        job = service.create_database(
            db, instance, body.name, body.owner, actor, label, request
        )
    except service.DbError as error:
        _raise(error)
    return _job(job)


@router.delete("/{instance_id}/databases/{name}", status_code=status.HTTP_202_ACCEPTED)
def drop_database(
    instance_id: str, name: str, request: Request, db: DbSession, user: AdminUser
):
    instance = _get(db, instance_id)
    if not service.IDENT_RE.fullmatch(name):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid database name"
        )
    actor, label = audit.user_actor(user)
    try:
        return _job(service.drop_database(db, instance, name, actor, label, request))
    except service.DbError as error:
        _raise(error)


@router.post("/{instance_id}/users", status_code=status.HTTP_202_ACCEPTED)
def create_user(
    instance_id: str, body: UserIn, request: Request, db: DbSession, user: AdminUser
):
    instance = _get(db, instance_id)
    actor, label = audit.user_actor(user)
    try:
        credential, job = service.create_user(
            db,
            instance,
            body.username,
            body.key_pattern if instance.engine == "redis" else body.database,
            body.access,
            actor,
            label,
            request,
        )
    except service.DbError as error:
        _raise(error)
    return {"job_id": job.id, "credential_id": credential.id}


def _credential(
    db, instance: DatabaseInstance, credential_id: str
) -> DatabaseCredential:
    credential = db.get(DatabaseCredential, credential_id)
    if credential is None or credential.instance_id != instance.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Login not found")
    return credential


@router.post(
    "/{instance_id}/users/{credential_id}/rotate", status_code=status.HTTP_202_ACCEPTED
)
def rotate(
    instance_id: str,
    credential_id: str,
    request: Request,
    db: DbSession,
    user: AdminUser,
):
    instance = _get(db, instance_id)
    credential = _credential(db, instance, credential_id)
    actor, label = audit.user_actor(user)
    try:
        return _job(
            service.rotate_password(db, instance, credential, actor, label, request)
        )
    except service.DbError as error:
        _raise(error)


@router.delete("/{instance_id}/users/{username}", status_code=status.HTTP_202_ACCEPTED)
def drop_user(
    instance_id: str, username: str, request: Request, db: DbSession, user: AdminUser
):
    instance = _get(db, instance_id)
    if not service.IDENT_RE.fullmatch(username):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid user name")
    actor, label = audit.user_actor(user)
    try:
        return _job(service.drop_user(db, instance, username, actor, label, request))
    except service.DbError as error:
        _raise(error)


@router.post("/{instance_id}/attach", status_code=status.HTTP_202_ACCEPTED)
def attach(
    instance_id: str, body: AttachIn, request: Request, db: DbSession, user: AdminUser
):
    """Create a login for an app and add its URL to the app's env (secret)."""
    instance = _get(db, instance_id)
    application = db.get(Application, body.application_id)
    if application is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Application not found")
    actor, label = audit.user_actor(user)
    try:
        credential, job = service.attach_to_app(
            db, instance, application, body.env_key, actor, label, request
        )
    except service.DbError as error:
        _raise(error)
    _audit(
        db,
        user,
        request,
        "database.attach",
        instance,
        f"{body.env_key} for {application.name}",
        result="success" if job is None else "accepted",
    )
    return {
        "job_id": job.id if job else None,
        "credential_id": credential.id if credential else None,
    }
