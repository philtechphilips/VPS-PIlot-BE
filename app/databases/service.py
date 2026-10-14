"""Database Management Center.

Managed databases run as vpdb-<name> containers on the server's private
`vpspilot` Docker network; apps on that server join the network and reach
them by name. External databases are ones you already run; the agent reaches
them from the server. Every operation is a typed job; passwords and SQL are
handed to the agent through the job-secrets channel, never stored in jobs.
"""

import hashlib
import ipaddress
import json
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.apps.models import Application
from app.core import artifacts
from app.core.config import settings
from app.core.security import decrypt_secret, encrypt_secret, new_id
from app.databases.models import (
    DatabaseCredential,
    DatabaseInstance,
    DatabaseMetric,
    DatabaseQuery,
)
from app.jobs import service as jobs
from app.jobs.models import Job
from app.servers.models import Server

PURPOSE = "database"
NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?")
IDENT_RE = re.compile(r"[a-z_][a-z0-9_]{0,62}")

ENGINES: dict[str, dict[str, Any]] = {
    "postgres": {
        "label": "PostgreSQL",
        "versions": ["17", "16"],
        "port": 5432,
        "admin": "postgres",
        "scheme": "postgresql",
    },
    "mysql": {
        "label": "MySQL",
        "versions": ["8.4"],
        "port": 3306,
        "admin": "root",
        "scheme": "mysql",
    },
    "mariadb": {
        "label": "MariaDB",
        "versions": ["11"],
        "port": 3306,
        "admin": "root",
        "scheme": "mysql",
    },
    "redis": {
        "label": "Redis",
        "versions": ["7"],
        "port": 6379,
        "admin": None,
        "scheme": "redis",
    },
}


class DbError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> datetime:
    return datetime.now(UTC)


def generate_password() -> str:
    # Letters and digits only: safe in URLs, SQL literals and shells.
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(32))


def _enc(value: str) -> str:
    return encrypt_secret(value, PURPOSE)


def _dec(value: str | None) -> str | None:
    return decrypt_secret(value, PURPOSE) if value else None


# ---------------------------------------------------------------------------
# Instances
# ---------------------------------------------------------------------------


def get(db: Session, instance_id: str) -> DatabaseInstance | None:
    return db.get(DatabaseInstance, instance_id)


def list_instances(db: Session) -> list[DatabaseInstance]:
    return list(
        db.scalars(select(DatabaseInstance).order_by(DatabaseInstance.created_at))
    )


def _active_server(db: Session, server_id: str) -> Server:
    server = db.get(Server, server_id)
    if server is None:
        raise DbError(404, "Server not found")
    if server.enrolled_at is None or server.revoked_at is not None:
        raise DbError(409, "Pick a server with an active agent")
    return server


def _check_name(db: Session, name: str) -> None:
    if not NAME_RE.fullmatch(name):
        raise DbError(
            422, "Use lowercase letters, numbers and dashes, up to 40 characters."
        )
    if db.scalar(select(DatabaseInstance).where(DatabaseInstance.name == name)):
        raise DbError(409, f"A database named {name} already exists")


def live_status(db: Session, instance: DatabaseInstance) -> str:
    """For managed databases, the container state the agent last reported."""
    if instance.mode != "managed" or instance.status in (
        "creating",
        "removing",
        "error",
    ):
        return instance.status
    server = db.get(Server, instance.server_id)
    containers = ((server.inventory if server else None) or {}).get("containers") or []
    container = next(
        (c for c in containers if c.get("name") == f"vpdb-{instance.name}"), None
    )
    if container is None:
        return instance.status
    return "running" if container.get("state") == "running" else "stopped"


def _queue(
    db: Session,
    instance: DatabaseInstance,
    job_type: str,
    payload: dict[str, Any],
    actor: str,
    label: str,
    request=None,
    audited: bool = True,
) -> Job:
    server = db.get(Server, instance.server_id)
    try:
        job, _ = jobs.create(
            db,
            server,
            job_type,
            {"instance_id": instance.id, **payload},
            actor,
            label,
            request=request,
            audited=audited,
        )
    except jobs.JobError as error:
        raise DbError(error.status_code, error.detail) from None
    return job


def create_managed(
    db: Session, data: dict[str, Any], actor: str, label: str, request=None
) -> tuple[DatabaseInstance, Job]:
    server = _active_server(db, data["server_id"])
    name = data["name"]
    _check_name(db, name)
    engine = data["engine"]
    spec = ENGINES[engine]
    version = data.get("version") or spec["versions"][0]
    if version not in spec["versions"]:
        raise DbError(422, f"{spec['label']} {version} isn't available")
    database = None
    if engine != "redis":
        database = data.get("database") or name.replace("-", "_")
        if not IDENT_RE.fullmatch(database):
            raise DbError(422, "Database names use lowercase letters, numbers and _")
    local_port = data.get("local_port")
    if local_port and db.scalar(
        select(DatabaseInstance).where(
            DatabaseInstance.server_id == server.id,
            DatabaseInstance.local_port == local_port,
        )
    ):
        raise DbError(409, f"Port {local_port} is already used by another database")
    instance = DatabaseInstance(
        id=new_id(),
        name=name,
        engine=engine,
        version=version,
        mode="managed",
        server_id=server.id,
        port=spec["port"],
        admin_user=spec["admin"],
        admin_password=_enc(generate_password()),
        default_database=database,
        local_port=local_port,
        status="creating",
        created_by=label[:64],
    )
    db.add(instance)
    db.flush()
    payload = {"name": name, "engine": engine, "version": version}
    if engine == "postgres":
        payload["user"] = spec["admin"]
    if database:
        payload["database"] = database
    if local_port:
        payload["local_port"] = local_port
    job = _queue(db, instance, "db.create", payload, actor, label, request)
    return instance, job


# Hosts that reach the server itself or cloud metadata. The agent resolves
# names and checks the addresses too; this catches the obvious ones early.
_BLOCKED_HOSTS = ("localhost", "metadata", "metadata.google.internal")


def check_external_host(host: str) -> None:
    name = host.strip("[]").lower().rstrip(".")
    if name in _BLOCKED_HOSTS or name.endswith(".localhost"):
        raise DbError(
            422, f"{host} points at the server itself; use a managed database"
        )
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
    ):
        raise DbError(
            422,
            f"{host} isn't allowed: it reaches the server itself or cloud metadata",
        )


def connect_external(
    db: Session, data: dict[str, Any], actor: str, label: str, request=None
) -> tuple[DatabaseInstance, Job]:
    check_external_host(data["host"])
    server = _active_server(db, data["server_id"])
    _check_name(db, data["name"])
    engine = data["engine"]
    spec = ENGINES[engine]
    instance = DatabaseInstance(
        id=new_id(),
        name=data["name"],
        engine=engine,
        version="external",
        mode="external",
        server_id=server.id,
        host=data["host"],
        port=data.get("port") or spec["port"],
        admin_user=data.get("user") if engine != "redis" else None,
        admin_password=_enc(data["password"]) if data.get("password") else None,
        default_database=data.get("database"),
        tls_mode=data.get("tls_mode") or "verify",
        tls_ca=(data.get("ca") or "").strip() or None,
        status="checking",
        created_by=label[:64],
    )
    db.add(instance)
    db.flush()
    return instance, _check_connection(db, instance, actor, label, request)


def _check_connection(
    db: Session, instance: DatabaseInstance, actor: str, label: str, request=None
) -> Job:
    """Prove the connection by reading the server's stats (or Redis INFO)."""
    if instance.engine == "redis":
        payload = {"target": target(instance), "action": "info"}
        return _queue(db, instance, "db.redis", payload, actor, label, request)
    payload = {"target": target(instance), "what": "stats"}
    return _queue(db, instance, "db.explore", payload, actor, label, request)


def update_tls(
    db: Session,
    instance: DatabaseInstance,
    mode: str,
    ca: str | None,
    actor: str,
    label: str,
) -> Job:
    if instance.mode != "external":
        raise DbError(409, "Managed databases are reached over the private network")
    instance.tls_mode = mode
    if ca is not None:
        instance.tls_ca = ca or None
    instance.status = "checking"
    instance.error = None
    db.commit()
    return _check_connection(db, instance, actor, label)


def target(instance: DatabaseInstance) -> dict[str, Any]:
    if instance.mode == "managed":
        out: dict[str, Any] = {
            "mode": "managed",
            "engine": instance.engine,
            "name": instance.name,
        }
        if instance.engine != "redis":
            out["user"] = instance.admin_user
        return out
    out = {
        "mode": "external",
        "engine": instance.engine,
        "host": instance.host,
        "port": instance.port,
        "tls": instance.tls_mode or "prefer",
    }
    if instance.admin_user:
        out["user"] = instance.admin_user
    return out


def control(
    db: Session,
    instance: DatabaseInstance,
    action: str,
    actor: str,
    label: str,
    request=None,
) -> Job:
    if instance.mode != "managed":
        raise DbError(
            409, "Only databases VPSPilot runs can be started or stopped here"
        )
    return _queue(
        db,
        instance,
        "db.control",
        {"name": instance.name, "action": action},
        actor,
        label,
        request,
    )


def remove(
    db: Session,
    instance: DatabaseInstance,
    delete_data: bool,
    actor: str,
    label: str,
    request=None,
) -> Job | None:
    """External: just forget it. Managed: remove the container (and data)."""
    if instance.mode != "managed":
        db.delete(instance)
        db.commit()
        return None
    instance.status = "removing"
    return _queue(
        db,
        instance,
        "db.remove",
        {"name": instance.name, "delete_data": delete_data},
        actor,
        label,
        request,
    )


# ---------------------------------------------------------------------------
# Queries, browsing, Redis
# ---------------------------------------------------------------------------


def fingerprint(sql: str) -> str:
    normal = (
        re.sub(r"\s+", " ", re.sub(r"'(?:[^']|'')*'|\b\d+\b", "?", sql)).strip().lower()
    )
    return hashlib.sha256(normal.encode()).hexdigest()[:16]


def run_query(
    db: Session,
    instance: DatabaseInstance,
    sql: str,
    database: str | None,
    readonly: bool,
    max_rows: int,
    actor: str,
    label: str,
    request=None,
) -> tuple[Job, DatabaseQuery]:
    if instance.engine == "redis":
        raise DbError(422, "Use the key browser for Redis")
    query = DatabaseQuery(
        id=new_id(),
        instance_id=instance.id,
        sql=_enc(sql),
        fingerprint=fingerprint(sql),
        database=database,
        readonly=readonly,
        created_by=label[:64],
        created_at=_now(),
    )
    db.add(query)
    db.flush()
    payload: dict[str, Any] = {
        "target": target(instance),
        "query_id": query.id,
        "readonly": readonly,
        "max_rows": max_rows,
    }
    if database:
        payload["database"] = database
    job = _queue(
        db, instance, "db.query", payload, actor, label, request, audited=False
    )
    query.job_id = job.id
    db.commit()
    return job, query


def explore(
    db: Session,
    instance: DatabaseInstance,
    data: dict[str, Any],
    actor: str,
    label: str,
) -> Job:
    payload = {
        "target": target(instance),
        **{k: v for k, v in data.items() if v is not None},
    }
    return _queue(db, instance, "db.explore", payload, actor, label, audited=False)


def redis_op(
    db: Session,
    instance: DatabaseInstance,
    data: dict[str, Any],
    actor: str,
    label: str,
    request=None,
) -> Job:
    if instance.engine != "redis":
        raise DbError(422, "Not a Redis database")
    payload = {
        "target": target(instance),
        **{k: v for k, v in data.items() if v is not None},
    }
    # Reading is not audited per request; deleting is.
    return _queue(
        db,
        instance,
        "db.redis",
        payload,
        actor,
        label,
        request,
        audited=data.get("action") == "delete",
    )


def job_result(db: Session, instance: DatabaseInstance, job_id: str) -> dict[str, Any]:
    job = db.get(Job, job_id)
    if job is None or job.payload.get("instance_id") != instance.id:
        raise DbError(404, "Request not found")
    out: dict[str, Any] = {
        "status": job.status,
        "error": job.error,
        "data": None,
        "result": job.result or None,
    }
    if job.status == "succeeded" and job.type not in ("db.export", "db.import"):
        text = jobs.job_output(job)
        try:
            out["data"] = json.loads(text) if text else None
        except ValueError:
            out["data"] = None
    return out


# ---------------------------------------------------------------------------
# Users, databases, credentials
# ---------------------------------------------------------------------------


def _sql_only(instance: DatabaseInstance) -> None:
    if instance.engine == "redis":
        raise DbError(422, "Redis has no databases to manage here")


def _redis_acl_ready(db: Session, instance: DatabaseInstance) -> bool:
    """ACL users need agent 1.1.0."""
    server = db.get(Server, instance.server_id)
    try:
        version = tuple(int(p) for p in (server.agent_version or "0").split(".")[:3])
    except (AttributeError, ValueError):
        return False
    return version >= (1, 1, 0)


def _acl_payload(
    instance: DatabaseInstance, credential: DatabaseCredential
) -> dict[str, Any]:
    return {
        "target": target(instance),
        "action": "acl_setuser",
        "user": credential.username,
        "access": credential.access,
        # For Redis logins, `database` holds the key pattern they may use.
        "pattern": credential.database or "*",
        "credential_id": credential.id,
    }


def create_database(
    db: Session,
    instance: DatabaseInstance,
    name: str,
    owner: str | None,
    actor: str,
    label: str,
    request=None,
) -> Job:
    _sql_only(instance)
    return _queue(
        db,
        instance,
        "db.admin",
        {
            "target": target(instance),
            "action": "create_database",
            "database": name,
            "user": owner,
        },
        actor,
        label,
        request,
    )


def drop_database(
    db: Session,
    instance: DatabaseInstance,
    name: str,
    actor: str,
    label: str,
    request=None,
) -> Job:
    _sql_only(instance)
    if name == instance.default_database:
        raise DbError(409, "That's this instance's default database")
    return _queue(
        db,
        instance,
        "db.admin",
        {"target": target(instance), "action": "drop_database", "database": name},
        actor,
        label,
        request,
    )


def create_user(
    db: Session,
    instance: DatabaseInstance,
    username: str,
    database: str | None,
    access: str,
    actor: str,
    label: str,
    request=None,
    application: Application | None = None,
    env_key: str | None = None,
) -> tuple[DatabaseCredential, Job]:
    if instance.engine == "redis":
        if access not in ("readwrite", "readonly"):
            raise DbError(422, "Redis logins are read-write or read-only")
        if username == "default":
            raise DbError(409, "default is the admin login")
        if not _redis_acl_ready(db, instance):
            raise DbError(
                409, "Upgrade this server's agent to 1.1.0 to add Redis logins"
            )
    if db.scalar(
        select(DatabaseCredential).where(
            DatabaseCredential.instance_id == instance.id,
            DatabaseCredential.username == username,
        )
    ):
        raise DbError(409, f"VPSPilot already manages a user named {username}")
    credential = DatabaseCredential(
        id=new_id(),
        instance_id=instance.id,
        username=username,
        password=_enc(generate_password()),
        database=database,
        access=access,
        status="pending",
        application_id=application.id if application else None,
        env_key=env_key,
        created_at=_now(),
    )
    db.add(credential)
    db.flush()
    if instance.engine == "redis":
        job = _queue(
            db,
            instance,
            "db.redis",
            _acl_payload(instance, credential),
            actor,
            label,
            request,
        )
        credential.job_id = job.id
        db.commit()
        return credential, job
    payload = {
        "target": target(instance),
        "action": "create_user",
        "user": username,
        "access": access,
        "credential_id": credential.id,
    }
    if database:
        payload["database"] = database
    job = _queue(db, instance, "db.admin", payload, actor, label, request)
    credential.job_id = job.id
    db.commit()
    return credential, job


def rotate_password(
    db: Session,
    instance: DatabaseInstance,
    credential: DatabaseCredential,
    actor: str,
    label: str,
    request=None,
) -> Job:
    credential.pending_password = _enc(generate_password())
    db.flush()
    if instance.engine == "redis":
        job = _queue(
            db,
            instance,
            "db.redis",
            _acl_payload(instance, credential),
            actor,
            label,
            request,
        )
        credential.job_id = job.id
        db.commit()
        return job
    job = _queue(
        db,
        instance,
        "db.admin",
        {
            "target": target(instance),
            "action": "set_password",
            "user": credential.username,
            "credential_id": credential.id,
        },
        actor,
        label,
        request,
    )
    credential.job_id = job.id
    db.commit()
    return job


def drop_user(
    db: Session,
    instance: DatabaseInstance,
    username: str,
    actor: str,
    label: str,
    request=None,
) -> Job:
    if instance.engine == "redis":
        if username == "default":
            raise DbError(409, "VPSPilot needs the admin login")
        return _queue(
            db,
            instance,
            "db.redis",
            {"target": target(instance), "action": "acl_deluser", "user": username},
            actor,
            label,
            request,
        )
    if username == instance.admin_user:
        raise DbError(409, "VPSPilot needs the admin user")
    return _queue(
        db,
        instance,
        "db.admin",
        {"target": target(instance), "action": "drop_user", "user": username},
        actor,
        label,
        request,
    )


def credentials(db: Session, instance: DatabaseInstance) -> list[DatabaseCredential]:
    return list(
        db.scalars(
            select(DatabaseCredential)
            .where(DatabaseCredential.instance_id == instance.id)
            .order_by(DatabaseCredential.created_at)
        )
    )


def connection_url(
    instance: DatabaseInstance,
    username: str | None,
    password: str | None,
    database: str | None,
    host: str | None = None,
    port: int | None = None,
) -> str:
    scheme = ENGINES[instance.engine]["scheme"]
    host = host or (
        f"vpdb-{instance.name}" if instance.mode == "managed" else instance.host
    )
    port = port or instance.port
    if instance.engine == "redis":
        user = quote(username, safe="") if username else ""
        auth = f"{user}:{quote(password, safe='')}@" if password else ""
        return f"redis://{auth}{host}:{port}/0"
    auth = f"{quote(username or '', safe='')}:{quote(password or '', safe='')}@"
    return f"{scheme}://{auth}{host}:{port}/{database or ''}"


def connection_details(db: Session, instance: DatabaseInstance) -> dict[str, Any]:
    """Every login VPSPilot knows, with ready-to-paste URLs (secrets!)."""
    admin_password = _dec(instance.admin_password)
    logins = [
        {
            "id": None,
            "username": instance.admin_user,
            "password": admin_password,
            "database": instance.default_database,
            "access": "admin",
            "status": "active",
            "application_id": None,
            "url": connection_url(
                instance, instance.admin_user, admin_password, instance.default_database
            ),
        }
    ]
    for credential in credentials(db, instance):
        password = _dec(credential.password)
        logins.append(
            {
                "id": credential.id,
                "username": credential.username,
                "password": password,
                "database": credential.database,
                "access": credential.access,
                "status": credential.status,
                "application_id": credential.application_id,
                "url": connection_url(
                    instance, credential.username, password, credential.database
                ),
            }
        )
    local = None
    if instance.mode == "managed" and instance.local_port:
        local = connection_url(
            instance,
            instance.admin_user,
            admin_password,
            instance.default_database,
            "127.0.0.1",
            instance.local_port,
        )
    return {"logins": logins, "local_url": local}


def _unique_username(db: Session, instance: DatabaseInstance, name: str) -> str:
    base = re.sub(r"[^a-z0-9_]", "_", name.lower())[:40]
    username = base
    n = 1
    while db.scalar(
        select(DatabaseCredential).where(
            DatabaseCredential.instance_id == instance.id,
            DatabaseCredential.username == username,
        )
    ):
        n += 1
        username = f"{base}_{n}"
    return username


def attach_to_app(
    db: Session,
    instance: DatabaseInstance,
    application: Application,
    env_key: str,
    actor: str,
    label: str,
    request=None,
) -> tuple[DatabaseCredential | None, Job | None]:
    """Give an app its own login (and database) and put the URL in its env."""
    if instance.mode == "managed" and application.server_id != instance.server_id:
        raise DbError(
            409,
            "The app runs on another server; managed databases are only "
            "reachable from their own server",
        )
    if any(e["key"] == env_key for e in application.env or []):
        raise DbError(409, f"{application.name} already has {env_key}")
    if instance.engine == "redis" and _redis_acl_ready(db, instance):
        # Its own login: no admin or dangerous commands.
        username = _unique_username(db, instance, application.name)
        return create_user(
            db,
            instance,
            username,
            None,
            "readwrite",
            actor,
            label,
            request,
            application,
            env_key,
        )
    if instance.engine == "redis":
        from app.apps import service as apps

        url = connection_url(instance, None, _dec(instance.admin_password), None)
        existing = [
            {"key": e["key"], "value": None, "secret": e["secret"]}
            for e in application.env or []
        ]
        application.env = apps.encode_env(
            [*existing, {"key": env_key, "value": url, "secret": True}],
            application.env or [],
        )
        db.commit()
        return None, None
    username = _unique_username(db, instance, application.name)
    # The app gets its own database, then a user that can do everything in
    # it (so migrations work) and nothing elsewhere. Jobs run in order.
    create_database(db, instance, username, None, actor, label, request)
    access = "owner" if instance.engine == "postgres" else "readwrite"
    return create_user(
        db,
        instance,
        username,
        username,
        access,
        actor,
        label,
        request,
        application,
        env_key,
    )


# ---------------------------------------------------------------------------
# Agent side: secrets for a running job, and outcomes
# ---------------------------------------------------------------------------


def job_secrets(db: Session, job: Job) -> dict[str, Any]:
    instance = db.get(DatabaseInstance, job.payload.get("instance_id"))
    if instance is None:
        return {}
    out: dict[str, Any] = {}
    if instance.admin_password:
        out["password"] = _dec(instance.admin_password)
    if instance.tls_ca:
        out["ca"] = instance.tls_ca
    if job.type == "db.query":
        query = db.get(DatabaseQuery, job.payload.get("query_id"))
        if query is not None and query.instance_id == instance.id:
            out["sql"] = _dec(query.sql)
    credential_id = job.payload.get("credential_id")
    if job.type in ("db.admin", "db.redis") and credential_id:
        credential = db.get(DatabaseCredential, credential_id)
        if credential is not None and credential.instance_id == instance.id:
            out["new_password"] = _dec(
                credential.pending_password or credential.password
            )
    return out


# ---------------------------------------------------------------------------
# Export and import (through encrypted, temporary artifacts)
# ---------------------------------------------------------------------------


def export(
    db: Session,
    instance: DatabaseInstance,
    database: str,
    actor: str,
    label: str,
    request=None,
) -> Job:
    _sql_only(instance)
    payload = {"target": target(instance), "database": database}
    return _queue(db, instance, "db.export", payload, actor, label, request)


def export_file(
    db: Session, instance: DatabaseInstance, job_id: str
) -> tuple[str, str]:
    """(artifact name, download file name) of a finished export."""
    job = db.get(Job, job_id)
    if (
        job is None
        or job.type != "db.export"
        or job.payload.get("instance_id") != instance.id
    ):
        raise DbError(404, "Export not found")
    if job.status != "succeeded":
        raise DbError(409, "The export isn't ready")
    name = f"{job.id}.out"
    if not artifacts.exists(name):
        raise DbError(410, "This export expired (exports are kept for a day)")
    stamp = (job.finished_at or _now()).strftime("%Y%m%d-%H%M")
    return name, f"{instance.name}-{job.payload['database']}-{stamp}.sql.gz"


def sniff_format(instance: DatabaseInstance, head: bytes) -> str:
    if head.startswith(b"\x1f\x8b"):
        return "sql.gz"
    if head.startswith(b"PGDMP"):
        if instance.engine != "postgres":
            raise DbError(422, "That's a PostgreSQL archive (pg_dump -Fc)")
        return "pgdump"
    try:
        head[:4096].decode("utf-8")
    except UnicodeDecodeError as error:
        if error.start < 4090:  # not just a cut multi-byte character
            raise DbError(
                422, "Upload a .sql file, a .sql.gz file or a pg_dump archive"
            ) from None
    return "sql"


def queue_import(
    db: Session,
    instance: DatabaseInstance,
    database: str,
    upload_id: str,
    size: int,
    actor: str,
    label: str,
    request=None,
) -> Job:
    _sql_only(instance)
    name = f"{upload_id}.in"
    head = next(iter(artifacts.read(name)), b"")
    try:
        fmt = sniff_format(instance, head)
    except DbError:
        artifacts.delete(name)
        raise
    payload = {
        "target": target(instance),
        "database": database,
        "format": fmt,
        "upload_id": upload_id,
        "size": size,
    }
    return _queue(db, instance, "db.import", payload, actor, label, request)


# ---------------------------------------------------------------------------
# Metrics history
# ---------------------------------------------------------------------------

SAMPLE_EVERY = timedelta(minutes=5)


def sample_due(db: Session) -> int:
    """Queue a stats read for each running database not sampled lately.
    Called by the monitoring worker; samples land in on_job_finished."""
    from app.servers import service as servers

    now = _now()
    cutoff = now - timedelta(days=settings.metrics_retention_days)
    db.execute(delete(DatabaseMetric).where(DatabaseMetric.ts < cutoff))
    queued = 0
    for instance in db.scalars(
        select(DatabaseInstance).where(DatabaseInstance.status == "running")
    ):
        last = instance.sampled_at
        if last is not None and now - _aware(last) < SAMPLE_EVERY:
            continue
        server = db.get(Server, instance.server_id)
        if server is None or servers.status_of(server, now) != "online":
            continue
        instance.sampled_at = now
        try:
            if instance.engine == "redis":
                payload = {"target": target(instance), "action": "info", "sample": True}
                _queue(
                    db, instance, "db.redis", payload, "system", "VPSPilot", None, False
                )
            else:
                payload = {"target": target(instance), "what": "stats", "sample": True}
                _queue(
                    db,
                    instance,
                    "db.explore",
                    payload,
                    "system",
                    "VPSPilot",
                    None,
                    False,
                )
            queued += 1
        except DbError:
            continue
    db.commit()
    return queued


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _store_sample(db: Session, instance: DatabaseInstance, job: Job) -> None:
    try:
        data = json.loads(jobs.job_output(job) or "{}")
    except ValueError:
        return
    metric = DatabaseMetric(instance_id=instance.id, ts=job.finished_at or _now())
    if instance.engine == "redis":
        info = data.get("info") or {}
        for field, key in (
            ("connections", "connected_clients"),
            ("max_connections", "maxclients"),
            ("memory_bytes", "used_memory"),
        ):
            value = _number(info.get(key))
            setattr(metric, field, int(value) if value is not None else None)
        metric.ops_per_sec = _number(info.get("instantaneous_ops_per_sec"))
        metric.keys = int(data.get("keys") or 0)
    else:
        try:
            row = dict(zip(data["columns"], data["rows"][0], strict=False))
        except (KeyError, IndexError, TypeError):
            return
        for field, key in (
            ("connections", "connections"),
            ("max_connections", "max_connections"),
            ("size_bytes", "size"),
        ):
            value = _number(row.get(key))
            setattr(metric, field, int(value) if value is not None else None)
    db.add(metric)


def metrics(
    db: Session, instance: DatabaseInstance, hours: int
) -> list[DatabaseMetric]:
    since = _now() - timedelta(hours=hours)
    return list(
        db.scalars(
            select(DatabaseMetric)
            .where(
                DatabaseMetric.instance_id == instance.id, DatabaseMetric.ts >= since
            )
            .order_by(DatabaseMetric.ts)
        )
    )


def on_job_finished(db: Session, job: Job) -> None:
    if not job.type.startswith("db."):
        return
    instance = db.get(DatabaseInstance, job.payload.get("instance_id"))
    if instance is None:
        return
    ok = job.status == "succeeded"
    if job.type == "db.import":
        artifacts.delete(f"{job.payload.get('upload_id')}.in")
    if job.type == "db.export" and not ok:
        artifacts.delete(f"{job.id}.out")
    if job.payload.get("sample"):
        if ok:
            _store_sample(db, instance, job)
        return
    if job.type == "db.create":
        instance.status = "running" if ok else "error"
        instance.error = None if ok else (job.error or f"Job {job.status}")[:500]
    elif job.type == "db.remove":
        if ok:
            db.delete(instance)
        else:
            instance.status = "error"
            instance.error = (job.error or "Couldn't remove the database")[:500]
    elif job.type == "db.control":
        if ok:
            instance.status = (
                "stopped" if job.payload.get("action") == "stop" else "running"
            )
    elif instance.status == "checking":
        # External connection test.
        instance.status = "running" if ok else "error"
        instance.error = None if ok else (job.error or "Couldn't connect")[:500]
        if ok and job.type == "db.explore":
            try:
                stats = json.loads(jobs.job_output(job) or "{}")
                instance.server_version = str(stats["rows"][0][0])[:200]
            except (ValueError, KeyError, IndexError, TypeError):
                pass
    if job.type == "db.admin":
        _admin_finished(db, instance, job, ok)
    if job.type == "db.redis" and job.payload.get("action") in (
        "acl_setuser",
        "acl_deluser",
    ):
        # Same bookkeeping as SQL logins: first set creates, later ones rotate.
        credential = db.get(DatabaseCredential, job.payload.get("credential_id") or "")
        if job.payload["action"] == "acl_deluser":
            action = "drop_user"
        elif credential is not None and credential.status == "pending":
            action = "create_user"
        else:
            action = "set_password"
        _admin_finished(db, instance, job, ok, action)


def _admin_finished(
    db: Session,
    instance: DatabaseInstance,
    job: Job,
    ok: bool,
    action: str | None = None,
) -> None:
    credential = db.get(DatabaseCredential, job.payload.get("credential_id") or "")
    action = action or job.payload.get("action")
    if action == "create_user" and credential is not None:
        if not ok:
            db.delete(credential)
            return
        credential.status = "active"
        if credential.application_id and credential.env_key:
            app = db.get(Application, credential.application_id)
            if app is not None:
                from app.apps import service as apps

                url = connection_url(
                    instance,
                    credential.username,
                    _dec(credential.password),
                    credential.database,
                )
                existing = [
                    {"key": e["key"], "value": None, "secret": e["secret"]}
                    for e in app.env or []
                ]
                if not any(e["key"] == credential.env_key for e in existing):
                    app.env = apps.encode_env(
                        [
                            *existing,
                            {"key": credential.env_key, "value": url, "secret": True},
                        ],
                        app.env or [],
                    )
    elif action == "set_password" and credential is not None:
        if ok and credential.pending_password:
            credential.password = credential.pending_password
            credential.rotated_at = _now()
        credential.pending_password = None
    elif action == "drop_user" and ok:
        for stale in db.scalars(
            select(DatabaseCredential).where(
                DatabaseCredential.instance_id == instance.id,
                DatabaseCredential.username == job.payload.get("user"),
            )
        ):
            db.delete(stale)


jobs.on_finished.append(on_job_finished)


def engines() -> list[dict[str, Any]]:
    return [
        {"engine": k, "label": v["label"], "versions": v["versions"], "port": v["port"]}
        for k, v in ENGINES.items()
    ]
