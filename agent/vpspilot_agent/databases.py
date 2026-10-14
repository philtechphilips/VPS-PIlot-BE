"""Database operations, run by the privileged helper (root).

Managed databases are Docker containers named vpdb-<name> on the private
`vpspilot` network, with data in a named volume. External databases (ones
you already run) are reached with a throwaway client container using the
host network, so no database clients need installing on the server.

Rules that keep this safe:
- every name is checked against a strict pattern here, again;
- SQL goes in on stdin, never on a command line;
- passwords reach clients through environment variables (root-only
  /proc/<pid>/environ), never as arguments;
- results are bounded (rows, bytes, time).
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from typing import Any

from vpspilot_agent.errors import Rejected

NETWORK = "vpspilot"
DATA_DIR = os.environ.get("VPSPILOT_DB_DIR", "/var/lib/vpspilot-db")
PREFIX = "vpdb-"

NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?")
IDENT_RE = re.compile(r"[a-z_][a-z0-9_]{0,62}")
PASSWORD_RE = re.compile(r"[A-Za-z0-9]{16,128}")
HOST_RE = re.compile(r"[A-Za-z0-9.-]{1,253}|\[[0-9a-fA-F:]{2,39}\]")
REDIS_KEY_RE = re.compile(r"[^\x00-\x1f\x7f]{1,512}")
REDIS_PATTERN_RE = re.compile(r"[^\x00-\x1f\x7f]{1,200}")

ENGINES: dict[str, dict[str, Any]] = {
    "postgres": {
        "images": {"17": "postgres:17-alpine", "16": "postgres:16-alpine"},
        "port": 5432,
        "data": "/var/lib/postgresql/data",
    },
    "mysql": {"images": {"8.4": "mysql:8.4"}, "port": 3306, "data": "/var/lib/mysql"},
    "mariadb": {"images": {"11": "mariadb:11"}, "port": 3306, "data": "/var/lib/mysql"},
    "redis": {"images": {"7": "redis:7-alpine"}, "port": 6379, "data": "/data"},
}

# External connections: TLS mode, and where each client image keeps the
# system CA bundle (for "verify" without a custom CA).
TLS_MODES = ("disable", "prefer", "require", "verify")
SYSTEM_CA = {
    "postgres": "/etc/ssl/certs/ca-certificates.crt",
    "mysql": "/etc/pki/tls/certs/ca-bundle.crt",
    "mariadb": "/etc/ssl/certs/ca-certificates.crt",
    "redis": "/etc/ssl/certs/ca-certificates.crt",
}
CA_PATH = "/vp-ca.pem"
CA_RE = re.compile(
    r"(-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*)+"
)
# Names that reach the server itself or cloud metadata services.
BLOCKED_NAMES = ("localhost", "metadata.google.internal", "metadata")

PG_NULL = "\\N"  # how psql prints NULL, so it differs from ''
MAX_ROWS = 1000
MAX_CELL = 4000
MAX_OUTPUT = 512 * 1024
CREATE_TIMEOUT = 600
READY_TIMEOUT = 120
SQL_TIMEOUT = 30

Emit = Callable[[str, str], None]


class DbError(Exception):
    """A database said no (bad SQL, wrong password...): reported, not a bug."""


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _match(regex: re.Pattern[str], value: Any, what: str) -> str:
    if not isinstance(value, str) or not regex.fullmatch(value):
        raise Rejected(f"invalid {what}")
    return value


def _int(value: Any, low: int, high: int, what: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not low <= value <= high
    ):
        raise Rejected(f"invalid {what}")
    return value


def _engine(args: dict[str, Any]) -> str:
    engine = args.get("engine")
    if engine not in ENGINES:
        raise Rejected("invalid engine")
    return engine


def _target(args: dict[str, Any]) -> dict[str, Any]:
    """Where to connect: a managed container, or an external endpoint."""
    target = args.get("target")
    if not isinstance(target, dict):
        raise Rejected("invalid target")
    engine = _engine(target)
    secrets = args.get("secrets") or {}
    password = secrets.get("password")
    if password is not None and (
        not isinstance(password, str) or len(password) > 512 or "\n" in password
    ):
        raise Rejected("invalid password")
    if target.get("mode") == "managed":
        return {
            "mode": "managed",
            "engine": engine,
            "container": PREFIX + _match(NAME_RE, target.get("name"), "database name"),
            "user": _match(IDENT_RE, target.get("user"), "user")
            if engine != "redis"
            else None,
            "password": password,
        }
    if target.get("mode") == "external":
        image = ENGINES[engine]["images"][sorted(ENGINES[engine]["images"])[-1]]
        host = _match(HOST_RE, target.get("host"), "host")
        tls = target.get("tls", "prefer")
        if tls not in TLS_MODES:
            raise Rejected("invalid TLS mode")
        ca = secrets.get("ca")
        if ca is not None and (
            not isinstance(ca, str) or len(ca) > 65536 or not CA_RE.fullmatch(ca)
        ):
            raise Rejected("invalid CA certificate")
        return {
            "mode": "external",
            "engine": engine,
            "host": host,
            "address": guard_host(host),
            "tls": tls,
            "ca": ca,
            "port": _int(target.get("port"), 1, 65535, "port"),
            "user": (
                _match(re.compile(r"[A-Za-z0-9_.@-]{1,63}"), target.get("user"), "user")
                if engine != "redis" and target.get("user") is not None
                else None
            ),
            "password": password,
            "image": image,
        }
    raise Rejected("invalid target mode")


def guard_host(host: str) -> str | None:
    """Resolve an external database host and refuse addresses on this server
    or link-local ones (cloud metadata): the agent must not become a way to
    probe them. Returns the address to pin (None for a literal IP)."""
    name = host.strip("[]").lower().rstrip(".")
    if name in BLOCKED_NAMES or name.endswith(".localhost"):
        raise Rejected(f"{host} points at this server; use a managed database instead")
    try:
        literal = ipaddress.ip_address(name)
    except ValueError:
        literal = None
    if literal is not None:
        addresses = [literal]
    else:
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, UnicodeError):
            raise Rejected(f"{host} doesn't resolve from this server") from None
        addresses = [ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos]
    for address in addresses:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if (
            address.is_loopback
            or address.is_link_local
            or address.is_unspecified
            or address.is_multicast
            or address.is_reserved
        ):
            raise Rejected(
                f"{host} resolves to {address}, which isn't allowed for external "
                "databases (it reaches this server or cloud metadata). Use a "
                "managed database, or the database's own address."
            )
    return None if literal is not None else str(addresses[0])


def external_options(
    target: dict[str, Any], workdir: str
) -> tuple[list[str], dict[str, str], list[str]]:
    """Docker args, environment and client flags for an external target:
    the pinned address and TLS settings."""
    engine, tls = target["engine"], target["tls"]
    docker: list[str] = []
    if target.get("address"):
        # Resolve the name to the vetted address (no DNS rebinding), while
        # TLS still checks the certificate against the name.
        docker += ["--add-host", f"{target['host']}:{target['address']}"]
    ca = SYSTEM_CA[engine]
    if target.get("ca"):
        path = os.path.join(workdir, "ca.pem")
        with open(path, "w") as handle:
            handle.write(target["ca"])
        os.chmod(path, 0o644)
        docker += ["-v", f"{path}:{CA_PATH}:ro"]
        ca = CA_PATH
    env: dict[str, str] = {}
    flags: list[str] = []
    if engine == "postgres":
        env["PGSSLMODE"] = {
            "disable": "disable",
            "prefer": "prefer",
            "require": "require",
            "verify": "verify-full",
        }[tls]
        if tls == "verify":
            env["PGSSLROOTCERT"] = ca
    elif engine == "mysql":
        flags.append(
            "--ssl-mode="
            + {
                "disable": "DISABLED",
                "prefer": "PREFERRED",
                "require": "REQUIRED",
                "verify": "VERIFY_IDENTITY",
            }[tls]
        )
        if tls == "verify":
            flags.append(f"--ssl-ca={ca}")
    elif engine == "mariadb":
        if tls == "disable":
            flags.append("--skip-ssl")
        elif tls == "require":
            flags += ["--ssl", "--disable-ssl-verify-server-cert"]
        elif tls == "verify":
            flags += ["--ssl", "--ssl-verify-server-cert", f"--ssl-ca={ca}"]
    elif tls == "require":
        flags += ["--tls", "--insecure"]
    elif tls == "verify":
        flags += ["--tls", "--cacert", ca]
    return docker, env, flags


def tempdir() -> str:
    """A private folder for client files. Not under /tmp: the helper runs
    with PrivateTmp, and Docker bind mounts resolve on the host."""
    base = os.path.join(DATA_DIR, ".tmp")
    os.makedirs(base, mode=0o700, exist_ok=True)
    return tempfile.mkdtemp(prefix="vpdb-", dir=base)


def cleanup(env_file: str | None) -> None:
    """Remove a client's temporary env file (and its folder)."""
    if not env_file:
        return
    folder = os.path.dirname(env_file)
    if os.path.basename(folder).startswith("vpdb-"):
        shutil.rmtree(folder, ignore_errors=True)
    elif os.path.exists(env_file):
        os.unlink(env_file)


# ---------------------------------------------------------------------------
# Running clients
# ---------------------------------------------------------------------------


def _run(
    cmd: list[str], timeout: int = 60, stdin: str | None = None
) -> tuple[int, str, str]:
    try:
        done = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"Timed out after {timeout}s"
    except OSError as error:
        return 127, "", str(error)
    return done.returncode, done.stdout, done.stderr


def _client(
    target: dict[str, Any],
    database: str | None,
    extra_env: dict[str, str] | None = None,
) -> tuple[list[str], str | None]:
    """The client command for this target, and an env-file to delete after."""
    engine = target["engine"]
    env = dict(extra_env or {})
    if target["mode"] == "managed":
        container = target["container"]
        env_args = [
            arg for k, v in env.items() for arg in ("-e", f"{k}={v}")
        ]  # non-secret only
        if engine == "postgres":
            # Local socket inside the container: trusted by the official image.
            cmd = [
                "psql",
                "-X",
                "-q",
                "-v",
                "ON_ERROR_STOP=1",
                "--csv",
                "-P",
                f"null={PG_NULL}",
                "-U",
                target["user"],
                "-d",
                database or "postgres",
            ]
            return ["docker", "exec", "-i", *env_args, container, *cmd], None
        if engine in ("mysql", "mariadb"):
            client = "mysql" if engine == "mysql" else "mariadb"
            var = (
                "MYSQL_ROOT_PASSWORD" if engine == "mysql" else "MARIADB_ROOT_PASSWORD"
            )
            db = f" {database}" if database else ""
            script = f'MYSQL_PWD="${var}" exec {client} -uroot --batch --default-character-set=utf8mb4{db}'
            return [
                "docker",
                "exec",
                "-i",
                *env_args,
                container,
                "sh",
                "-c",
                script,
            ], None
        # "$@" passes the command through; the trailing "redis-cli" is $0.
        script = 'REDISCLI_AUTH="$VP_REDIS_PASSWORD" exec redis-cli --json "$@"'
        return [
            "docker",
            "exec",
            "-i",
            *env_args,
            container,
            "sh",
            "-c",
            script,
            "redis-cli",
        ], None

    # External: a throwaway client container on the host network. Secrets go
    # through a root-only env file, never the command line.
    workdir = tempdir()
    docker_args, tls_env, flags = external_options(target, workdir)
    env.update(tls_env)
    secret_env = {}
    if engine == "postgres":
        secret_env["PGPASSWORD"] = target["password"] or ""
        cmd = [
            "psql",
            "-X",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "--csv",
            "-P",
            f"null={PG_NULL}",
            "-h",
            target["host"],
            "-p",
            str(target["port"]),
            "-U",
            target["user"] or "postgres",
            "-d",
            database or "postgres",
        ]
    elif engine in ("mysql", "mariadb"):
        secret_env["MYSQL_PWD"] = target["password"] or ""
        client = "mysql" if engine == "mysql" else "mariadb"
        cmd = [
            client,
            *flags,
            "-h",
            target["host"],
            "-P",
            str(target["port"]),
            "-u",
            target["user"] or "root",
            "--batch",
            "--default-character-set=utf8mb4",
        ]
        if database:
            cmd.append(database)
    else:
        if target["password"]:
            secret_env["REDISCLI_AUTH"] = target["password"]
        cmd = [
            "redis-cli",
            *flags,
            "-h",
            target["host"],
            "-p",
            str(target["port"]),
            "--json",
        ]
    env_file = os.path.join(workdir, "env")
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        for key, value in {**secret_env, **env}.items():
            handle.write(f"{key}={value}\n")
    return [
        "docker",
        "run",
        "--rm",
        "-i",
        "--network",
        "host",
        "--env-file",
        env_file,
        *docker_args,
        target["image"],
        *cmd,
    ], env_file


def _stream_rows(
    cmd: list[str], stdin: str, max_lines: int, timeout: int
) -> tuple[int, list[str], str, bool]:
    """Run a client, keeping at most max_lines of stdout. Returns
    (exit code, lines, stderr, truncated)."""
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
    )
    timer = threading.Timer(timeout, proc.kill)
    timer.start()
    err_chunks: list[str] = []
    reader = threading.Thread(
        target=lambda: err_chunks.append(proc.stderr.read()[-8000:]), daemon=True
    )  # type: ignore[union-attr]
    reader.start()
    lines: list[str] = []
    truncated = False
    size = 0
    try:
        assert proc.stdin is not None and proc.stdout is not None
        try:
            proc.stdin.write(stdin)
            proc.stdin.close()
        except BrokenPipeError:
            pass
        for line in proc.stdout:
            if len(lines) >= max_lines or size > MAX_OUTPUT:
                truncated = True
                proc.kill()
                break
            lines.append(line)
            size += len(line)
        code = proc.wait()
    finally:
        timer.cancel()
    reader.join(timeout=2)
    stderr = "".join(err_chunks)
    if code < 0 and not truncated:
        return 124, lines, f"Timed out after {timeout}s", False
    return (0 if truncated else code), lines, stderr, truncated


def _clean_error(stderr: str) -> str:
    lines = [
        ln.strip()
        for ln in stderr.splitlines()
        if ln.strip() and not ln.startswith(("mysql: [Warning]", "mariadb: [Warning]"))
    ]
    errors = [ln for ln in lines if re.search(r"\b(ERROR|FATAL|error)\b", ln)]
    message = (errors or lines or ["The database returned an error"])[0]
    detail = next(
        (ln for ln in lines if ln.startswith(("LINE ", "DETAIL:", "HINT:"))), None
    )
    if detail and detail.startswith(("DETAIL:", "HINT:")):
        message = f"{message} ({detail})"
    message = re.sub(r"^psql:<stdin>:\d+: ", "", message)
    message = re.sub(r"^(ERROR|FATAL):\s+", "", message)
    message = re.sub(r"^ERROR \d+ \(\w+\)( at line \d+)?: ", "", message)
    return message[:500]


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------


def _sql_prelude(engine: str, readonly: bool, timeout: int) -> str:
    if engine == "postgres":
        return ""  # set through PGOPTIONS (see _run_sql)
    if engine == "mysql":
        lines = [f"SET SESSION max_execution_time={timeout * 1000};"]
    else:
        lines = [f"SET SESSION max_statement_time={timeout};"]
    if readonly:
        lines.append("SET SESSION TRANSACTION READ ONLY;")
    return "\n".join(lines) + "\n"


def _unescape_mysql(value: str) -> str | None:
    if value == "NULL":
        return None
    return re.sub(
        r"\\(.)",
        lambda m: {"n": "\n", "t": "\t", "0": "\0", "\\": "\\"}.get(
            m.group(1), m.group(1)
        ),
        value,
    )


def _run_sql(
    target: dict[str, Any],
    sql: str,
    database: str | None,
    readonly: bool,
    max_rows: int,
    timeout: int,
) -> dict[str, Any]:
    engine = target["engine"]
    env = {}
    if engine == "postgres":
        options = [f"-c statement_timeout={timeout * 1000}"]
        if readonly:
            options.append("-c default_transaction_read_only=on")
        env["PGOPTIONS"] = " ".join(options)
    cmd, env_file = _client(target, database, env)
    started = time.monotonic()
    try:
        code, lines, stderr, truncated = _stream_rows(
            cmd,
            _sql_prelude(engine, readonly, timeout) + sql + "\n",
            max_rows + 1,
            timeout + 5,
        )
    finally:
        if env_file:
            cleanup(env_file)
    duration = int((time.monotonic() - started) * 1000)
    if code != 0:
        raise DbError(_clean_error(stderr) if code != 124 else stderr)
    if engine == "postgres":
        rows = [
            [None if cell == PG_NULL else cell for cell in row]
            for row in csv.reader(lines)
        ]
    else:
        rows = [
            [_unescape_mysql(cell) for cell in line.rstrip("\n").split("\t")]
            for line in lines
        ]
    columns = rows[0] if rows else []
    body = rows[1:]
    if len(body) > max_rows:
        body, truncated = body[:max_rows], True
    body = [[(c[:MAX_CELL] if isinstance(c, str) else c) for c in row] for row in body]
    return {
        "columns": columns,
        "rows": body,
        "truncated": truncated,
        "duration_ms": duration,
    }


def _quote_literal(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def _ident(engine: str, name: str) -> str:
    _match(IDENT_RE, name, "name")
    return f'"{name}"' if engine == "postgres" else f"`{name}`"


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


def _ready_check(engine: str, container: str, user: str | None) -> list[str]:
    if engine == "postgres":
        return ["docker", "exec", container, "pg_isready", "-U", user or "postgres"]
    if engine == "mysql":
        return [
            "docker",
            "exec",
            container,
            "sh",
            "-c",
            'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -uroot -e "SELECT 1"',
        ]
    if engine == "mariadb":
        return [
            "docker",
            "exec",
            container,
            "sh",
            "-c",
            'MYSQL_PWD="$MARIADB_ROOT_PASSWORD" exec mariadb -uroot -e "SELECT 1"',
        ]
    return [
        "docker",
        "exec",
        container,
        "sh",
        "-c",
        'REDISCLI_AUTH="$VP_REDIS_PASSWORD" exec redis-cli ping',
    ]


def create(args: dict[str, Any], emit: Emit) -> dict[str, Any]:
    """Start a managed database container and wait until it accepts queries."""
    name = _match(NAME_RE, args.get("name"), "database name")
    engine = _engine(args)
    version = args.get("version")
    if version not in ENGINES[engine]["images"]:
        raise Rejected("invalid version")
    user = _match(IDENT_RE, args.get("user"), "user") if engine == "postgres" else None
    database = (
        _match(IDENT_RE, args.get("database"), "database")
        if engine != "redis"
        else None
    )
    local_port = args.get("local_port")
    if local_port is not None:
        _int(local_port, 1024, 65535, "local port")
    password = (args.get("secrets") or {}).get("password")
    _match(PASSWORD_RE, password, "password")
    if shutil.which("docker") is None:
        return {
            "exit_code": 1,
            "output": "",
            "error": "Docker isn't installed on this server",
        }

    spec = ENGINES[engine]
    image = spec["images"][version]
    container = PREFIX + name
    workdir = os.path.join(DATA_DIR, name)
    os.makedirs(workdir, mode=0o700, exist_ok=True)

    if _run(["docker", "network", "inspect", NETWORK], 15)[0] != 0:
        emit("step", f"Creating the private network {NETWORK}")
        _run(["docker", "network", "create", NETWORK], 30)
    if _run(["docker", "container", "inspect", container], 15)[0] == 0:
        return {
            "exit_code": 1,
            "output": "",
            "error": f"A container named {container} already exists",
        }

    emit("step", f"Pulling {image}")
    code, _, err = _run(["docker", "pull", image], CREATE_TIMEOUT)
    if code != 0:
        return {
            "exit_code": code,
            "output": "",
            "error": f"Couldn't pull {image}: {_clean_error(err)}",
        }

    env: dict[str, str] = {}
    extra: list[str] = []
    if engine == "postgres":
        env = {
            "POSTGRES_USER": user,
            "POSTGRES_PASSWORD": password,
            "POSTGRES_DB": database,
        }  # type: ignore[dict-item]
    elif engine == "mysql":
        env = {"MYSQL_ROOT_PASSWORD": password, "MYSQL_DATABASE": database}  # type: ignore[dict-item]
    elif engine == "mariadb":
        env = {"MARIADB_ROOT_PASSWORD": password, "MARIADB_DATABASE": database}  # type: ignore[dict-item]
    else:
        # The password lives in a root-owned config file readable by the redis
        # user, not on the redis-server command line.
        conf = os.path.join(workdir, "redis.conf")
        fd = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(f"requirepass {password}\nappendonly yes\nprotected-mode no\n")
        try:
            os.chown(conf, 999, 1000)  # the redis user in the official image
        except PermissionError:
            os.chmod(conf, 0o644)  # only when not running as root (tests)
        env = {"VP_REDIS_PASSWORD": password}  # for redis-cli via REDISCLI_AUTH
        extra = ["-v", f"{conf}:/usr/local/etc/redis/redis.conf:ro"]

    env_file = os.path.join(workdir, "env")
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        for key, value in env.items():
            handle.write(f"{key}={value}\n")
    cmd = [
        "docker", "run", "-d", "--name", container,
        "--network", NETWORK, "--restart", "unless-stopped",
        "--env-file", env_file,
        "-v", f"{container}:{spec['data']}",
        "--label", f"vpspilot.database={name}",
        "--log-opt", "max-size=10m", "--log-opt", "max-file=3",
        *extra,
    ]  # fmt: skip
    if local_port:
        # Reachable from the server itself (e.g. an SSH tunnel), never publicly.
        cmd += ["-p", f"127.0.0.1:{local_port}:{spec['port']}"]
    cmd.append(image)
    if engine == "redis":
        cmd += ["redis-server", "/usr/local/etc/redis/redis.conf"]
    emit("step", f"Starting {container}")
    code, _, err = _run(cmd, 120)
    os.unlink(env_file)
    if code != 0:
        return {
            "exit_code": code,
            "output": "",
            "error": f"Couldn't start the database: {_clean_error(err)}",
        }

    emit("step", "Waiting until it accepts connections")
    deadline = time.monotonic() + READY_TIMEOUT
    while time.monotonic() < deadline:
        if _run(_ready_check(engine, container, user), 15)[0] == 0:
            # MySQL/MariaDB restart once after initialising; check twice.
            time.sleep(2)
            if _run(_ready_check(engine, container, user), 15)[0] == 0:
                emit("step", "Ready")
                return {
                    "exit_code": 0,
                    "output": "",
                    "result": {"container": container},
                }
        time.sleep(2)
    code, logs, _ = _run(["docker", "logs", "--tail", "30", container], 15)
    for line in logs.splitlines()[-30:]:
        emit("output", line[:500])
    return {
        "exit_code": 1,
        "output": "",
        "error": "The database didn't become ready in time",
    }


def remove(args: dict[str, Any], emit: Emit) -> dict[str, Any]:
    name = _match(NAME_RE, args.get("name"), "database name")
    container = PREFIX + name
    _run(["docker", "rm", "-f", container], 120)
    if args.get("delete_data") is True:
        _run(["docker", "volume", "rm", "-f", container], 120)
        shutil.rmtree(os.path.join(DATA_DIR, name), ignore_errors=True)
        emit("info", "Removed the container and its data")
    else:
        emit("info", f"Removed the container; data kept in the volume {container}")
    return {"exit_code": 0, "output": ""}


def control(args: dict[str, Any]) -> dict[str, Any]:
    name = _match(NAME_RE, args.get("name"), "database name")
    action = args.get("action")
    if action not in ("start", "stop", "restart"):
        raise Rejected("invalid action")
    code, out, err = _run(["docker", action, PREFIX + name], 120)
    return {"exit_code": code, "output": (out + err)[-2000:]}


def _respond(fn: Callable[[], Any]) -> dict[str, Any]:
    """Run an operation, returning JSON output or a clean error."""
    try:
        body = fn()
    except DbError as error:
        return {"exit_code": 1, "output": "", "error": str(error)}
    return {"exit_code": 0, "output": json.dumps(body, default=str)}


def query(args: dict[str, Any]) -> dict[str, Any]:
    target = _target(args)
    if target["engine"] == "redis":
        raise Rejected("use redis operations for Redis")
    sql = (args.get("secrets") or {}).get("sql")
    if not isinstance(sql, str) or not sql.strip() or len(sql) > 100_000:
        raise Rejected("invalid query")
    database = args.get("database")
    if database is not None:
        _match(IDENT_RE, database, "database")
    readonly = args.get("readonly", True) is not False
    max_rows = _int(args.get("max_rows", 500), 1, MAX_ROWS, "row limit")
    timeout = _int(args.get("timeout", 15), 1, 120, "timeout")
    return _respond(
        lambda: _run_sql(target, sql, database, readonly, max_rows, timeout)
    )


# Metadata queries per engine (no user input in them).
PG_DATABASES = (
    "SELECT datname AS name, pg_database_size(datname) AS size, "
    "pg_get_userbyid(datdba) AS owner FROM pg_database "
    "WHERE NOT datistemplate ORDER BY datname"
)
PG_USERS = (
    "SELECT rolname AS name, rolsuper AS superuser, rolcanlogin AS login, "
    "rolcreatedb AS createdb FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY rolname"
)
PG_TABLES = (
    "SELECT n.nspname AS schema, c.relname AS name, "
    "CASE c.relkind WHEN 'r' THEN 'table' WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized view' "
    "WHEN 'p' THEN 'table' ELSE c.relkind::text END AS kind, "
    "GREATEST(c.reltuples, 0)::bigint AS rows, pg_total_relation_size(c.oid) AS size "
    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE c.relkind IN ('r','v','m','p') AND n.nspname NOT IN ('pg_catalog','information_schema') "
    "AND n.nspname !~ '^pg_toast' ORDER BY n.nspname, c.relname"
)
PG_STATS = (
    "SELECT version() AS version, "
    "(SELECT count(*) FROM pg_stat_activity) AS connections, "
    "current_setting('max_connections') AS max_connections, "
    "(SELECT sum(pg_database_size(datname)) FROM pg_database) AS size, "
    "date_trunc('second', now() - pg_postmaster_start_time())::text AS uptime"
)
MY_DATABASES = (
    "SELECT s.SCHEMA_NAME AS name, COALESCE(SUM(t.DATA_LENGTH + t.INDEX_LENGTH), 0) AS size "
    "FROM information_schema.SCHEMATA s LEFT JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = s.SCHEMA_NAME "
    "WHERE s.SCHEMA_NAME NOT IN ('mysql','information_schema','performance_schema','sys') "
    "GROUP BY s.SCHEMA_NAME ORDER BY s.SCHEMA_NAME"
)
MY_USERS = "SELECT User AS name, Host AS host FROM mysql.user WHERE User NOT LIKE 'mysql.%' ORDER BY User"
MY_STATS = (
    "SELECT VERSION() AS version, "
    "(SELECT COUNT(*) FROM information_schema.PROCESSLIST) AS connections, "
    "@@max_connections AS max_connections, "
    "(SELECT COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) FROM information_schema.TABLES) AS size"
)


def _columns_sql(engine: str, schema: str, table: str) -> str:
    if engine == "postgres":
        return (
            "SELECT column_name AS name, data_type AS type, is_nullable AS nullable, column_default AS default "
            f"FROM information_schema.columns WHERE table_schema = {_quote_literal(schema)} "
            f"AND table_name = {_quote_literal(table)} ORDER BY ordinal_position"
        )
    return (
        "SELECT COLUMN_NAME AS name, COLUMN_TYPE AS type, IS_NULLABLE AS nullable, COLUMN_DEFAULT AS `default`, COLUMN_KEY AS `key` "
        f"FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = {_quote_literal(schema)} "
        f"AND TABLE_NAME = {_quote_literal(table)} ORDER BY ORDINAL_POSITION"
    )


def _my_tables(database: str) -> str:
    return (
        "SELECT TABLE_SCHEMA AS `schema`, TABLE_NAME AS name, LOWER(TABLE_TYPE) AS kind, "
        "COALESCE(TABLE_ROWS, 0) AS `rows`, COALESCE(DATA_LENGTH + INDEX_LENGTH, 0) AS size "
        f"FROM information_schema.TABLES WHERE TABLE_SCHEMA = {_quote_literal(database)} ORDER BY TABLE_NAME"
    )


OBJECT_RE = re.compile(r"[A-Za-z0-9_$ -]{1,128}")


def explore(args: dict[str, Any]) -> dict[str, Any]:
    """Databases, users, tables, columns and stats, read-only."""
    target = _target(args)
    engine = target["engine"]
    if engine == "redis":
        raise Rejected("use redis operations for Redis")
    what = args.get("what")
    database = args.get("database")
    if database is not None:
        _match(IDENT_RE, database, "database")
    pg = engine == "postgres"
    if what == "databases":
        sql = PG_DATABASES if pg else MY_DATABASES
    elif what == "users":
        sql = PG_USERS if pg else MY_USERS
    elif what == "stats":
        sql = PG_STATS if pg else MY_STATS
    elif what == "tables":
        if not database:
            raise Rejected("database required")
        sql = PG_TABLES if pg else _my_tables(database)
    elif what == "columns":
        schema = _match(OBJECT_RE, args.get("namespace"), "schema")
        table = _match(OBJECT_RE, args.get("table"), "table")
        sql = _columns_sql(engine, schema, table)
    else:
        raise Rejected("invalid request")
    return _respond(
        lambda: _run_sql(
            target,
            sql,
            database if what in ("tables", "columns") else None,
            True,
            MAX_ROWS,
            15,
        )
    )


def admin(args: dict[str, Any]) -> dict[str, Any]:
    """Typed admin actions: create/drop databases and users, passwords."""
    target = _target(args)
    engine = target["engine"]
    if engine == "redis":
        raise Rejected("not available for Redis")
    action = args.get("action")
    pg = engine == "postgres"
    new_password = (args.get("secrets") or {}).get("new_password")
    if action in ("create_user", "set_password"):
        _match(PASSWORD_RE, new_password, "new password")
    database = args.get("database")
    user = args.get("user")
    access = args.get("access", "readwrite")
    if access not in ("readwrite", "readonly", "owner"):
        raise Rejected("invalid access")

    statements: list[tuple[str | None, str]] = []  # (database to run in, sql)
    if action == "create_database":
        db = _ident(engine, database)
        owner = f" OWNER {_ident(engine, user)}" if pg and user else ""
        statements.append((None, f"CREATE DATABASE {db}{owner};"))
    elif action == "drop_database":
        statements.append((None, f"DROP DATABASE {_ident(engine, database)};"))
    elif action == "create_user":
        u = _ident(engine, user)
        pw = _quote_literal(new_password)
        if pg:
            statements.append((None, f"CREATE ROLE {u} LOGIN PASSWORD {pw};"))
            if database:
                db = _ident(engine, database)
                if access == "owner":
                    statements.append((None, f"ALTER DATABASE {db} OWNER TO {u};"))
                    statements.append((database, f"ALTER SCHEMA public OWNER TO {u};"))
                else:
                    statements.append((None, f"GRANT CONNECT ON DATABASE {db} TO {u};"))
                    if access == "readwrite":
                        statements.append(
                            (
                                database,
                                f"GRANT USAGE, CREATE ON SCHEMA public TO {u}; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {u}; GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {u}; ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {u}; ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {u};",
                            )
                        )
                    else:
                        statements.append(
                            (
                                database,
                                f"GRANT USAGE ON SCHEMA public TO {u}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {u}; ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {u};",
                            )
                        )
        else:
            account = f"{_quote_literal(user)}@'%'"
            statements.append((None, f"CREATE USER {account} IDENTIFIED BY {pw};"))
            if database:
                db = _ident(engine, database)
                privs = "SELECT" if access == "readonly" else "ALL PRIVILEGES"
                statements.append((None, f"GRANT {privs} ON {db}.* TO {account};"))
    elif action == "set_password":
        pw = _quote_literal(new_password)
        if pg:
            statements.append(
                (None, f"ALTER ROLE {_ident(engine, user)} PASSWORD {pw};")
            )
        else:
            statements.append(
                (None, f"ALTER USER {_quote_literal(user)}@'%' IDENTIFIED BY {pw};")
            )
    elif action == "drop_user":
        _match(IDENT_RE, user, "user")
        if pg:
            statements.append((None, f"DROP ROLE {_ident(engine, user)};"))
        else:
            statements.append((None, f"DROP USER {_quote_literal(user)}@'%';"))
    else:
        raise Rejected("invalid action")

    def run() -> dict[str, Any]:
        for db, sql in statements:
            _run_sql(target, sql, db, False, 10, 30)
        return {"ok": True}

    return _respond(run)


def _redis(target: dict[str, Any], *command: str, timeout: int = 15) -> Any:
    cmd, env_file = _client(target, None)
    try:
        code, out, err = _run([*cmd, *command], timeout)
    finally:
        if env_file:
            cleanup(env_file)
    if code != 0:
        raise DbError(_clean_error(err or out))
    text = out.strip()
    try:
        value = json.loads(text) if text else None
    except ValueError:
        value = text
    if isinstance(value, str) and value.startswith(
        ("ERR", "WRONGTYPE", "NOAUTH", "NOPERM")
    ):
        raise DbError(value)
    return value


# Redis ACL users: what each access level may run. Dangerous commands
# (FLUSHALL, CONFIG, KEYS, DEBUG, ...) are never allowed.
REDIS_ACCESS = {
    "readonly": "-@all +@read +@connection -@dangerous",
    "readwrite": "-@all +@read +@write +@connection +@transaction +@scripting "
    "+@pubsub -@dangerous",
}


def _redis_conf(target: dict[str, Any]) -> str | None:
    """The managed instance's config file, where ACL users are kept."""
    if target["mode"] != "managed":
        return None
    path = os.path.join(DATA_DIR, target["container"][len(PREFIX) :], "redis.conf")
    return path if os.path.isfile(path) else None


def _save_acl_user(conf: str, user: str, rule: str | None) -> None:
    """Add, replace or (rule None) remove one `user` line. Written in place:
    the file is bind-mounted into the container."""
    with open(conf, "r+") as handle:
        lines = [
            line
            for line in handle.read().splitlines()
            if not line.startswith(f"user {user} ")
        ]
        if rule:
            lines.append(f"user {user} {rule}")
        handle.seek(0)
        handle.write("\n".join(lines) + "\n")
        handle.truncate()


def _acl_users(target: dict[str, Any]) -> list[dict[str, Any]]:
    users = []
    for line in _redis(target, "ACL", "LIST") or []:
        parts = str(line).split()
        if len(parts) < 3 or parts[0] != "user":
            continue
        rules = [p for p in parts[2:] if not p.startswith(("#", ">", "<", "!"))]
        users.append(
            {
                "name": parts[1],
                "enabled": "on" in rules,
                "keys": [r[1:] for r in rules if r.startswith("~")],
                "rules": " ".join(r for r in rules if r not in ("on", "off"))[:500],
            }
        )
    return users


def redis(args: dict[str, Any]) -> dict[str, Any]:
    """Redis: info, scan (never KEYS), type-aware reads, delete one key,
    and ACL users (hashed passwords, persisted for managed instances)."""
    target = _target(args)
    if target["engine"] != "redis":
        raise Rejected("not a Redis database")
    action = args.get("action")
    if action in ("acl_setuser", "acl_deluser"):
        user = _match(IDENT_RE, args.get("user"), "user")
        if user == "default":
            raise Rejected("the default user is managed by VPSPilot")

    def acl() -> Any:
        conf = _redis_conf(target)
        if action == "acl_list":
            return {"users": _acl_users(target), "persisted": conf is not None}
        if action == "acl_deluser":
            _redis(target, "ACL", "DELUSER", user)
            if conf:
                _save_acl_user(conf, user, None)
            return {"deleted": user}
        access = args.get("access", "readwrite")
        if access not in REDIS_ACCESS:
            raise Rejected("invalid access")
        pattern = _match(REDIS_PATTERN_RE, args.get("pattern") or "*", "key pattern")
        if " " in pattern:
            raise Rejected("invalid key pattern")
        password = (args.get("secrets") or {}).get("new_password")
        _match(PASSWORD_RE, password, "new password")
        # Only the hash ever appears in a command line or file.
        digest = hashlib.sha256(password.encode()).hexdigest()
        rule = f"on #{digest} ~{pattern} &* {REDIS_ACCESS[access]}"
        _redis(target, "ACL", "SETUSER", user, "reset", *rule.split())
        if conf:
            _save_acl_user(conf, user, rule)
        return {"user": user, "persisted": conf is not None}

    if action and action.startswith("acl_"):
        if action not in ("acl_list", "acl_setuser", "acl_deluser"):
            raise Rejected("invalid action")
        return _respond(acl)

    def run() -> Any:
        if action == "info":
            raw = _redis(target, "INFO")
            info = {}
            for line in str(raw).splitlines():
                if ":" in line and not line.startswith("#"):
                    k, _, v = line.partition(":")
                    info[k] = v.strip()
            keys = sum(int(m) for m in re.findall(r"keys=(\d+)", str(raw)))
            return {"info": info, "keys": keys}
        if action == "scan":
            cursor = str(_int(int(args.get("cursor", 0)), 0, 2**63, "cursor"))
            pattern = _match(REDIS_PATTERN_RE, args.get("pattern") or "*", "pattern")
            count = str(_int(args.get("count", 100), 1, 1000, "count"))
            reply = _redis(target, "SCAN", cursor, "MATCH", pattern, "COUNT", count)
            next_cursor, keys = reply[0], reply[1]
            details = []
            for key in keys[:200]:
                details.append(
                    {
                        "key": key,
                        "type": _redis(target, "TYPE", key),
                        "ttl": _redis(target, "TTL", key),
                    }
                )
            return {"cursor": str(next_cursor), "keys": details}
        key = _match(REDIS_KEY_RE, args.get("key"), "key")
        if action == "get":
            kind = _redis(target, "TYPE", key)
            ttl = _redis(target, "TTL", key)
            if kind == "string":
                value: Any = _redis(target, "GETRANGE", key, "0", str(MAX_CELL * 4))
            elif kind == "hash":
                value = _redis(target, "HSCAN", key, "0", "COUNT", "200")[1]
            elif kind == "list":
                value = _redis(target, "LRANGE", key, "0", "199")
            elif kind == "set":
                value = _redis(target, "SSCAN", key, "0", "COUNT", "200")[1]
            elif kind == "zset":
                value = _redis(target, "ZRANGE", key, "0", "199", "WITHSCORES")
            elif kind == "none":
                value = None
            else:
                value = f"({kind} values aren't shown)"
            return {"key": key, "type": kind, "ttl": ttl, "value": value}
        if action == "delete":
            return {"deleted": _redis(target, "UNLINK", key)}
        raise Rejected("invalid action")

    return _respond(run)


OPERATIONS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "db.control": control,
    "db.query": query,
    "db.explore": explore,
    "db.admin": admin,
    "db.redis": redis,
}

STREAMING: dict[str, Callable[[dict[str, Any], Emit], dict[str, Any]]] = {
    "db.create": create,
    "db.remove": remove,
}
