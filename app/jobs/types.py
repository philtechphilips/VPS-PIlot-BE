"""The fixed set of operations an agent may be asked to run.

Every job type has a strict payload schema. The same allowlist is enforced
again by the agent and by the privileged helper on the server, so a bad
payload is rejected three times before anything executes.
"""

from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

Unit = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9@._:-]{1,200}\.service$")]
Container = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
]
Lines = Annotated[int, Field(ge=1, le=500)]

# Stopping or restarting these could cut VPSPilot (or you) off the server.
PROTECTED_UNITS = {"vpspilot-agent.service", "vpspilot-helper.service"}
NO_STOP_UNITS = {"ssh.service", "sshd.service"}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServicePayload(Strict):
    unit: Unit


class ServiceLogsPayload(Strict):
    unit: Unit
    lines: Lines = 200


class ContainerPayload(Strict):
    container: Container


class ContainerLogsPayload(Strict):
    container: Container
    lines: Lines = 200


# ---------------------------------------------------------------------------
# Deployments (internal: created by app.apps.service, not the actions API)
# ---------------------------------------------------------------------------

AppName = Annotated[
    str, StringConstraints(pattern=r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")
]
HexId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
GitUrl = Annotated[
    str,
    StringConstraints(
        max_length=500, pattern=r"^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._~/-]+$"
    ),
]


def _no_parent(value: str) -> str:
    # No ".." anywhere: refs and paths must not climb out of the checkout.
    if ".." in value:
        raise ValueError("must not contain '..'")
    return value


# Pydantic's regex engine has no look-ahead, so the ".." rule is a validator.
GitRef = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9._/][A-Za-z0-9._/-]{0,199}$"),
    AfterValidator(_no_parent),
]
ImageRef = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._/:@-]{0,299}$")]
RelPath = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9._-][A-Za-z0-9._/-]{0,199}$"),
    AfterValidator(_no_parent),
]
HealthPath = Annotated[
    str, StringConstraints(pattern=r"^/[A-Za-z0-9._~/?=&%-]{0,199}$")
]
Port = Annotated[int, Field(ge=1, le=65535)]
HostPort = Annotated[int, Field(ge=1024, le=65535)]
Cpus = Annotated[str, StringConstraints(pattern=r"^\d{1,2}(\.\d{1,2})?$")]
Memory = Annotated[str, StringConstraints(pattern=r"^\d{1,6}[kmg]$")]
# A single-line shell command run inside the build/app container.
Command = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=1, max_length=500, pattern=r"^[^\r\n]+$"
    ),
]


class GitSource(Strict):
    type: Literal["git"]
    url: GitUrl
    ref: GitRef
    # Private GitHub repo: the agent fetches a short-lived token with the env.
    auth: bool = False


class ImageSource(Strict):
    type: Literal["image"]
    image: ImageRef
    # False for rollbacks: the image was built here earlier.
    pull: bool = True


class ReleaseSource(Strict):
    """A release kept on the server (native and Compose rollbacks)."""

    type: Literal["release"]
    release: HexId


Runtime = Literal["docker", "systemd", "compose"]
ComposeService = Annotated[
    str, StringConstraints(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")
]


class AppDeployPayload(Strict):
    app: AppName
    deployment_id: HexId
    runtime: Runtime = "docker"
    source: GitSource | ImageSource | ReleaseSource = Field(discriminator="type")
    compose_file: RelPath | None = None
    compose_service: ComposeService | None = None

    @model_validator(mode="after")
    def _source_fits_runtime(self):
        allowed = {
            "docker": ("git", "image"),
            "systemd": ("git", "release"),
            "compose": ("git", "release"),
        }
        if self.source.type not in allowed[self.runtime]:
            raise ValueError(f"A {self.source.type} source can't run on {self.runtime}")
        return self

    dockerfile: RelPath = "Dockerfile"
    context: RelPath = "."
    container_port: Port
    host_port: HostPort
    health_path: HealthPath = "/"
    health_timeout: Annotated[int, Field(ge=5, le=600)] = 60
    cpus: Cpus | None = None
    memory: Memory | None = None
    # The agent fetches env values for this job over its authenticated
    # channel; they are never stored in the job payload.
    has_env: bool = False
    # For repositories without a Dockerfile: override the detected commands.
    build_command: Command | None = None
    start_command: Command | None = None


class AppRemovePayload(Strict):
    app: AppName


Since = Annotated[
    str,
    StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$"),
]


class AppLogsPayload(Strict):
    """Read the running container's output (stdout + stderr)."""

    app: AppName
    lines: Annotated[int, Field(ge=1, le=1000)] = 200
    since: Since | None = None
    runtime: Runtime = "docker"
    service: ComposeService | None = None  # the public service of a Compose app


# ---------------------------------------------------------------------------
# Databases (internal: created by app.databases.service)
# ---------------------------------------------------------------------------

Engine = Literal["postgres", "mysql", "mariadb", "redis"]
DbIdent = Annotated[str, StringConstraints(pattern=r"^[a-z_][a-z0-9_]{0,62}$")]
DbHost = Annotated[
    str, StringConstraints(pattern=r"^([A-Za-z0-9.-]{1,253}|\[[0-9a-fA-F:]{2,39}\])$")
]
DbObject = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_$ -]{1,128}$")]


class DbTarget(Strict):
    mode: Literal["managed", "external"]
    engine: Engine
    name: AppName | None = None  # managed
    user: (
        Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.@-]{1,63}$")] | None
    ) = None
    host: DbHost | None = None  # external
    port: Port | None = None
    tls: Literal["disable", "prefer", "require", "verify"] | None = None


class DbJob(Strict):
    instance_id: HexId
    # Passwords and SQL are fetched by the agent, never stored in the job.
    has_secrets: bool = True


class DbCreatePayload(DbJob):
    name: AppName
    engine: Engine
    version: Annotated[str, StringConstraints(pattern=r"^[0-9.]{1,8}$")]
    user: DbIdent | None = None
    database: DbIdent | None = None
    local_port: HostPort | None = None


class DbRemovePayload(Strict):
    instance_id: HexId
    name: AppName
    delete_data: bool = False


class DbControlPayload(Strict):
    instance_id: HexId
    name: AppName
    action: Literal["start", "stop", "restart"]


class DbQueryPayload(DbJob):
    target: DbTarget
    query_id: HexId
    database: DbIdent | None = None
    readonly: bool = True
    max_rows: Annotated[int, Field(ge=1, le=1000)] = 500
    timeout: Annotated[int, Field(ge=1, le=120)] = 15


class DbExplorePayload(DbJob):
    target: DbTarget
    what: Literal["databases", "users", "stats", "tables", "columns"]
    # A periodic metrics sample (stored, not shown to anyone).
    sample: bool = False
    database: DbIdent | None = None
    namespace: DbObject | None = None  # schema (PostgreSQL) or database (MySQL)
    table: DbObject | None = None


class DbAdminPayload(DbJob):
    target: DbTarget
    action: Literal[
        "create_database", "drop_database", "create_user", "set_password", "drop_user"
    ]
    database: DbIdent | None = None
    user: DbIdent | None = None
    access: Literal["owner", "readwrite", "readonly"] = "readwrite"
    credential_id: HexId | None = None


class DbRedisPayload(DbJob):
    target: DbTarget
    action: Literal[
        "info", "scan", "get", "delete", "acl_list", "acl_setuser", "acl_deluser"
    ]
    # ACL logins (the password comes with the job's secrets)
    user: DbIdent | None = None
    access: Literal["readwrite", "readonly"] | None = None
    credential_id: HexId | None = None
    sample: bool = False
    pattern: (
        Annotated[str, StringConstraints(pattern=r"^[^\x00-\x1f\x7f]{1,200}$")] | None
    ) = None
    cursor: Annotated[int, Field(ge=0)] = 0
    count: Annotated[int, Field(ge=1, le=1000)] = 100
    key: (
        Annotated[str, StringConstraints(pattern=r"^[^\x00-\x1f\x7f]{1,512}$")] | None
    ) = None


class DbExportPayload(DbJob):
    """Dump one database as portable SQL (gzip); the agent uploads it."""

    target: DbTarget
    database: DbIdent


class DbImportPayload(DbJob):
    """Load an uploaded SQL file (or pg_dump archive) into a database."""

    target: DbTarget
    database: DbIdent
    format: Literal["sql", "sql.gz", "pgdump"]
    upload_id: HexId
    size: Annotated[int, Field(ge=0)]


class LogsReadPayload(Strict):
    """Read the systemd journal or a container's output (Logs page)."""

    source: Literal["journal", "container"]
    unit: (
        Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9@._:-]{1,200}$")] | None
    ) = None
    container: Container | None = None
    lines: Annotated[int, Field(ge=1, le=1000)] = 200
    since: Since | None = None  # container
    cursor: (
        Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9=;_-]{1,512}$")] | None
    ) = None  # journal
    priority: Annotated[int, Field(ge=0, le=7)] | None = (
        None  # journal: this level or more severe
    )


ProxyHost = Annotated[
    str,
    StringConstraints(
        max_length=253,
        pattern=r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$",
    ),
]


class ProxySite(Strict):
    host: ProxyHost
    tls: Literal["auto", "internal", "off"]
    upstream: (
        Annotated[
            str,
            StringConstraints(
                pattern=r"^(vp-[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?|host):\d{1,5}$"
            ),
        ]
        | None
    ) = None
    redirect_to: ProxyHost | None = None


class ProxyApplyPayload(Strict):
    sites: Annotated[list[ProxySite], Field(max_length=500)]
    email: (
        Annotated[
            str,
            StringConstraints(pattern=r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}$"),
        ]
        | None
    ) = None


class ProxyStatusPayload(Strict):
    hosts: Annotated[list[ProxyHost], Field(max_length=200)]


class BackupStorage(Strict):
    endpoint: Annotated[
        str, StringConstraints(pattern=r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?$")
    ]
    region: Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]{1,40}$")]
    bucket: Annotated[
        str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
    ]
    prefix: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._/-]{0,200}$")] = ""


BackupPath = Annotated[str, StringConstraints(pattern=r"^/[A-Za-z0-9._/-]{1,400}$")]
RemoteKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._/-]{1,500}$")]


class BackupCreatePayload(DbJob):
    target: DbTarget
    backup_id: HexId
    database: DbIdent | None = None
    keep_local: bool = True
    storage: BackupStorage | None = None


class BackupRestorePayload(DbJob):
    target: DbTarget
    backup_id: HexId
    database: DbIdent | None = None
    mode: Literal["replace", "new", "verify"]
    into: DbIdent | None = None
    path: BackupPath | None = None
    remote_key: RemoteKey | None = None
    sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")] | None = None
    storage: BackupStorage | None = None


class BackupDeleteItem(Strict):
    path: BackupPath | None = None
    remote_key: RemoteKey | None = None


class BackupDeletePayload(Strict):
    items: Annotated[list[BackupDeleteItem], Field(max_length=500)]
    storage: BackupStorage | None = None
    has_secrets: bool = True


class BackupStorageTestPayload(Strict):
    storage: BackupStorage
    has_secrets: bool = True


JOB_TYPES: dict[str, type[Strict]] = {
    "backup.create": BackupCreatePayload,
    "backup.restore": BackupRestorePayload,
    "backup.delete": BackupDeletePayload,
    "backup.storage_test": BackupStorageTestPayload,
    "proxy.apply": ProxyApplyPayload,
    "proxy.status": ProxyStatusPayload,
    "logs.read": LogsReadPayload,
    "db.create": DbCreatePayload,
    "db.remove": DbRemovePayload,
    "db.control": DbControlPayload,
    "db.query": DbQueryPayload,
    "db.explore": DbExplorePayload,
    "db.admin": DbAdminPayload,
    "db.redis": DbRedisPayload,
    "db.export": DbExportPayload,
    "db.import": DbImportPayload,
    "app.deploy": AppDeployPayload,
    "app.remove": AppRemovePayload,
    "app.logs": AppLogsPayload,
    "service.restart": ServicePayload,
    "service.start": ServicePayload,
    "service.stop": ServicePayload,
    "service.logs": ServiceLogsPayload,
    "container.restart": ContainerPayload,
    "container.start": ContainerPayload,
    "container.stop": ContainerPayload,
    "container.logs": ContainerLogsPayload,
}

JobType = Literal[
    "service.restart",
    "service.start",
    "service.stop",
    "service.logs",
    "container.restart",
    "container.start",
    "container.stop",
    "container.logs",
]


class PolicyError(ValueError):
    pass


def validate(job_type: str, payload: dict) -> dict:
    """Return the normalised payload or raise PolicyError / ValidationError."""
    schema = JOB_TYPES.get(job_type)
    if schema is None:
        raise PolicyError(f"Unknown job type: {job_type}")
    data = schema.model_validate(payload).model_dump()
    unit = data.get("unit")
    if unit in PROTECTED_UNITS and job_type != "service.logs":
        raise PolicyError(f"{unit} is managed by VPSPilot and can't be changed here")
    if unit in NO_STOP_UNITS and job_type == "service.stop":
        raise PolicyError("Stopping SSH could lock you out of the server")
    container = data.get("container") or ""
    if job_type == "container.stop" and container.startswith("vpspilot-"):
        raise PolicyError(
            f"{container} is part of VPSPilot; stopping it would cut you off"
        )
    return data
