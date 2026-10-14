"""Database backups (run by the privileged helper).

A backup is one database dumped with its engine's own tool, compressed,
encrypted with AES-256 (openssl, key from the control plane via the job
secrets channel, never on a command line), written under
/var/lib/vpspilot-backups and optionally uploaded to S3-compatible storage
(SigV4, standard library only). Restores and verification run the same
pipeline backwards; verification restores into a throwaway database and
drops it afterwards.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from vpspilot_agent import databases as dbs
from vpspilot_agent.errors import Rejected

DIR = os.environ.get("VPSPILOT_BACKUP_DIR", "/var/lib/vpspilot-backups")
ID_RE = re.compile(r"[0-9a-f]{32}")
BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
PREFIX_RE = re.compile(r"[A-Za-z0-9._/-]{0,200}")
REGION_RE = re.compile(r"[a-z0-9-]{1,40}")
# http is allowed for self-hosted storage (e.g. MinIO on a private network).
ENDPOINT_RE = re.compile(r"https?://[A-Za-z0-9.-]+(:\d{1,5})?")
DUMP_TIMEOUT = 3 * 3600
OPENSSL = [
    "openssl",
    "enc",
    "-aes-256-cbc",
    "-pbkdf2",
    "-iter",
    "100000",
    "-pass",
    "env:VPB_KEY",
]

Emit = Callable[[str, str], None]


class Failed(Exception):
    pass


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _key(args: dict[str, Any]) -> str:
    key = (args.get("secrets") or {}).get("backup_key")
    if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key):
        raise Rejected("missing backup key")
    return key


DRIVE_ID_RE = re.compile(r"[A-Za-z0-9_-]{10,200}")
DRIVE_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]{20,4096}")
DRIVE_API = "https://www.googleapis.com"
DRIVE_CHUNK = 8 * 1024 * 1024  # a multiple of 256 KiB, as Drive requires


def _storage(args: dict[str, Any]) -> dict[str, Any] | None:
    storage = args.get("storage")
    if storage is None:
        return None
    if not isinstance(storage, dict):
        raise Rejected("invalid storage")
    secrets = args.get("secrets") or {}
    if storage.get("provider") == "gdrive":
        token = secrets.get("gdrive_token")
        if not isinstance(token, str) or not DRIVE_TOKEN_RE.fullmatch(token):
            raise Rejected("missing Google Drive access")
        return {
            "provider": "gdrive",
            "folder_id": dbs._match(DRIVE_ID_RE, storage.get("folder_id"), "folder"),
            "token": token,
            "label": "Google Drive",
        }
    if storage.get("provider", "s3") != "s3":
        raise Rejected("invalid storage provider")
    access, secret = secrets.get("s3_access_key"), secrets.get("s3_secret_key")
    if (
        not isinstance(access, str)
        or not isinstance(secret, str)
        or not access
        or not secret
    ):
        raise Rejected("missing storage credentials")
    return {
        "endpoint": dbs._match(ENDPOINT_RE, storage.get("endpoint"), "endpoint"),
        "region": dbs._match(REGION_RE, storage.get("region") or "auto", "region"),
        "bucket": dbs._match(BUCKET_RE, storage.get("bucket"), "bucket"),
        "prefix": dbs._match(PREFIX_RE, storage.get("prefix") or "", "prefix").strip(
            "/"
        ),
        "access_key": access,
        "secret_key": secret,
        "provider": "s3",
        "label": storage.get("bucket"),
    }


def _paths(args: dict[str, Any]) -> tuple[str, str, str]:
    instance = dbs._match(ID_RE, args.get("instance_id"), "instance")
    backup = dbs._match(ID_RE, args.get("backup_id"), "backup")
    database = args.get("database")
    if database is not None:
        dbs._match(dbs.IDENT_RE, database, "database")
    return instance, backup, database or "redis"


# ---------------------------------------------------------------------------
# S3 (SigV4, path-style, unsigned payload over HTTPS)
# ---------------------------------------------------------------------------


def _s3(
    storage: dict[str, Any], method: str, key: str, body=None, length: int | None = None
) -> bytes:
    with _s3_open(storage, method, key, body, length) as response:
        return response.read() if method == "GET" else b""


def _s3_open(
    storage: dict[str, Any], method: str, key: str, body=None, length: int | None = None
):
    now = dt.datetime.now(dt.timezone.utc)
    amz_date, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    host = urllib.parse.urlparse(storage["endpoint"]).netloc
    path = "/" + urllib.parse.quote(f"{storage['bucket']}/{key}", safe="/-_.~")
    headers = {
        "host": host,
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        "x-amz-date": amz_date,
    }
    signed = ";".join(sorted(headers))
    canonical = "\n".join(
        [
            method,
            path,
            "",
            "".join(f"{k}:{headers[k]}\n" for k in sorted(headers)),
            signed,
            "UNSIGNED-PAYLOAD",
        ]
    )
    scope = f"{date}/{storage['region']}/s3/aws4_request"
    to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical.encode()).hexdigest(),
        ]
    )
    k = ("AWS4" + storage["secret_key"]).encode()
    for part in (date, storage["region"], "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        storage["endpoint"] + path, data=body, method=method
    )
    for name, value in headers.items():
        if name != "host":
            request.add_header(name, value)
    request.add_header(
        "Authorization",
        f"AWS4-HMAC-SHA256 Credential={storage['access_key']}/{scope}, SignedHeaders={signed}, Signature={signature}",
    )
    if length is not None:
        request.add_header("Content-Length", str(length))
    try:
        return urllib.request.urlopen(request, timeout=3600)
    except urllib.error.HTTPError as error:
        detail = error.read()[:300].decode(errors="replace")
        code = re.search(r"<Code>([^<]+)</Code>", detail)
        raise Failed(
            f"Storage said {error.code}{': ' + code.group(1) if code else ''}"
        ) from None
    except (urllib.error.URLError, OSError) as error:
        raise Failed(
            f"Couldn't reach the storage: {getattr(error, 'reason', error)}"
        ) from None


def _remote_key(
    storage: dict[str, Any], instance: str, database: str, backup: str, ext: str
) -> str:
    parts = [storage["prefix"], instance, database, f"{backup}.{ext}"]
    return "/".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# Google Drive (resumable uploads with a short-lived access token)
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Drive answers 308 between upload chunks; that's not a redirect."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_drive_opener = urllib.request.build_opener(_NoRedirect)


def _drive(
    storage: dict[str, Any],
    method: str,
    url: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 600,
):
    request = urllib.request.Request(url, data=body, method=method)
    request.add_header("Authorization", f"Bearer {storage['token']}")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        return _drive_opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        if error.code == 308:
            return error  # upload chunk accepted, more to come
        detail = error.read()[:400].decode(errors="replace")
        reason = re.search(r'"message":\s*"([^"]+)"', detail)
        raise Failed(
            f"Google Drive said {error.code}"
            + (f": {reason.group(1)}" if reason else "")
        ) from None
    except (urllib.error.URLError, OSError) as error:
        raise Failed(
            f"Couldn't reach Google Drive: {getattr(error, 'reason', error)}"
        ) from None


def _drive_upload(storage: dict[str, Any], name: str, path: str, size: int) -> str:
    """Upload in chunks; returns the new file's id."""
    meta = json.dumps({"name": name, "parents": [storage["folder_id"]]}).encode()
    with _drive(
        storage,
        "POST",
        f"{DRIVE_API}/upload/drive/v3/files?uploadType=resumable&fields=id",
        meta,
        {
            "Content-Type": "application/json; charset=UTF-8",
            "X-Upload-Content-Type": "application/octet-stream",
            "X-Upload-Content-Length": str(size),
        },
    ) as response:
        session = response.headers.get("Location")
    if not session or not session.startswith(DRIVE_API + "/"):
        raise Failed("Google Drive didn't start the upload")
    with open(path, "rb") as handle:
        offset = 0
        while True:
            chunk = handle.read(DRIVE_CHUNK)
            end = offset + len(chunk) - 1
            response = _drive(
                storage,
                "PUT",
                session,
                chunk,
                {
                    "Content-Length": str(len(chunk)),
                    "Content-Range": f"bytes {offset}-{end}/{size}"
                    if chunk
                    else f"bytes */{size}",
                },
            )
            with response:
                if response.status in (200, 201):
                    data = json.loads(response.read() or b"{}")
                    file_id = data.get("id")
                    if not isinstance(file_id, str) or not DRIVE_ID_RE.fullmatch(
                        file_id
                    ):
                        raise Failed("Google Drive didn't return a file id")
                    return file_id
                # 308: resume after the last byte Drive has.
                done = re.match(r"bytes=0-(\d+)", response.headers.get("Range") or "")
                offset = int(done.group(1)) + 1 if done else 0
            handle.seek(offset)
            if not chunk:
                raise Failed("The upload to Google Drive didn't finish")


# ---------------------------------------------------------------------------
# One interface over the providers
# ---------------------------------------------------------------------------


def _put(storage: dict[str, Any], key: str, path: str, size: int) -> str:
    """Upload; returns the remote key (the object key, or Drive's file id)."""
    if storage["provider"] == "gdrive":
        return _drive_upload(storage, key.replace("/", "-"), path, size)
    with open(path, "rb") as handle:
        _s3(storage, "PUT", key, handle, size)
    return key


def _get(storage: dict[str, Any], key: str, dest: str) -> None:
    """Download to dest, streaming (backups can be large)."""
    if storage["provider"] == "gdrive":
        if not DRIVE_ID_RE.fullmatch(key):
            raise Failed("invalid Google Drive file id")
        response = _drive(
            storage, "GET", f"{DRIVE_API}/drive/v3/files/{key}?alt=media", timeout=3600
        )
    else:
        response = _s3_open(storage, "GET", key)
    with response, open(dest, "wb") as out:
        while chunk := response.read(1 << 20):
            out.write(chunk)


def _remove(storage: dict[str, Any], key: str) -> None:
    if storage["provider"] == "gdrive":
        if DRIVE_ID_RE.fullmatch(key):
            _drive(storage, "DELETE", f"{DRIVE_API}/drive/v3/files/{key}").close()
        return
    _s3(storage, "DELETE", key)


# ---------------------------------------------------------------------------
# Dump / restore commands per engine
# ---------------------------------------------------------------------------


def _client_cmd(
    target: dict[str, Any], tool: list[str], database: str | None, stdin: bool
) -> tuple[list[str], str | None]:
    """Run an engine tool (pg_dump, mysqldump, ...) against the target, the
    same way the database module runs its clients."""
    engine = target["engine"]
    if target["mode"] == "managed":
        container = target["container"]
        flag = ["-i"] if stdin else []
        if engine == "postgres":
            return [
                "docker",
                "exec",
                *flag,
                container,
                *tool,
                "-U",
                target["user"],
                *(["-d", database] if database else []),
            ], None
        if engine in ("mysql", "mariadb"):
            var = (
                "MYSQL_ROOT_PASSWORD" if engine == "mysql" else "MARIADB_ROOT_PASSWORD"
            )
            script = f'MYSQL_PWD="${var}" exec "$@"'
            return [
                "docker",
                "exec",
                *flag,
                container,
                "sh",
                "-c",
                script,
                "sh",
                *tool,
                "-uroot",
                *([database] if database else []),
            ], None
        script = 'REDISCLI_AUTH="$VP_REDIS_PASSWORD" exec "$@"'
        return [
            "docker",
            "exec",
            *flag,
            container,
            "sh",
            "-c",
            script,
            "sh",
            *tool,
        ], None
    # External: throwaway client container; password through an env file.

    workdir = dbs.tempdir()
    docker_args, tls_env, flags = dbs.external_options(target, workdir)
    env_file = os.path.join(workdir, "env")
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        for key, value in tls_env.items():
            handle.write(f"{key}={value}\n")
        if engine == "postgres":
            handle.write(f"PGPASSWORD={target['password'] or ''}\n")
        elif engine in ("mysql", "mariadb"):
            handle.write(f"MYSQL_PWD={target['password'] or ''}\n")
        elif target["password"]:
            handle.write(f"REDISCLI_AUTH={target['password']}\n")
    flag = ["-i"] if stdin else []
    base = [
        "docker",
        "run",
        "--rm",
        *flag,
        "--network",
        "host",
        "--env-file",
        env_file,
        *docker_args,
        target["image"],
    ]
    if engine == "postgres":
        return [
            *base,
            *tool,
            "-h",
            target["host"],
            "-p",
            str(target["port"]),
            "-U",
            target["user"] or "postgres",
            *(["-d", database] if database else []),
        ], env_file
    if engine in ("mysql", "mariadb"):
        return [
            *base,
            *tool,
            *flags,
            "-h",
            target["host"],
            "-P",
            str(target["port"]),
            "-u",
            target["user"] or "root",
            *([database] if database else []),
        ], env_file
    return [
        *base,
        *tool,
        *flags,
        "-h",
        target["host"],
        "-p",
        str(target["port"]),
    ], env_file


def _dump_tool(engine: str) -> tuple[list[str], str]:
    """Tool and file extension. Postgres' custom format is compressed and
    restores into any database name; the SQL dumps are gzipped."""
    if engine == "postgres":
        return ["pg_dump", "-Fc", "--no-owner"], "pgdump.enc"
    if engine == "mysql":
        return [
            "mysqldump",
            "--single-transaction",
            "--routines",
            "--triggers",
            "--no-tablespaces",
        ], "sql.gz.enc"
    if engine == "mariadb":
        return [
            "mariadb-dump",
            "--single-transaction",
            "--routines",
            "--triggers",
        ], "sql.gz.enc"
    return ["redis-cli", "--rdb", "/data/vpspilot-backup.rdb"], "rdb.gz.enc"


def _pipeline(
    stages: list[list[str]],
    env_for: dict[int, dict[str, str]],
    stdin_file: str | int | None,
    stdout_file: str | None,
    timeout: int,
) -> tuple[int, str]:
    """Run commands piped together; returns (first non-zero code, stderr).
    stdin_file may be an already-open descriptor (checked by the caller)."""
    procs = []
    errors: list[str] = []
    if isinstance(stdin_file, int):
        previous = os.fdopen(stdin_file, "rb")
    else:
        previous = open(stdin_file, "rb") if stdin_file else subprocess.DEVNULL
    out_handle = open(stdout_file, "wb") if stdout_file else None
    try:
        for i, cmd in enumerate(stages):
            last = i == len(stages) - 1
            env = {**os.environ, **env_for[i]} if i in env_for else None
            proc = subprocess.Popen(
                cmd,
                stdin=previous,
                stdout=out_handle if last and out_handle else subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            if hasattr(previous, "close") and previous is not subprocess.DEVNULL:
                previous.close()
            previous = proc.stdout
            procs.append(proc)
        timer = threading.Timer(timeout, lambda: [p.kill() for p in procs])
        timer.start()
        readers = [
            threading.Thread(
                target=lambda p=p: errors.append(
                    p.stderr.read()[-2000:].decode(errors="replace")
                ),
                daemon=True,
            )
            for p in procs
        ]  # type: ignore[union-attr]
        for r in readers:
            r.start()
        if not out_handle and procs[-1].stdout:
            procs[-1].stdout.read()
        codes = [p.wait() for p in procs]
        timer.cancel()
        for r in readers:
            r.join(timeout=2)
    finally:
        if out_handle:
            out_handle.close()
    bad = next((c for c in codes if c != 0), 0)
    return bad, "\n".join(e.strip() for e in errors if e.strip())


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


def create(args: dict[str, Any], emit: Emit) -> dict[str, Any]:
    target = dbs._target(args)
    key = _key(args)
    storage = _storage(args)
    instance, backup, database = _paths(args)
    keep_local = args.get("keep_local", True) is not False or storage is None
    engine = target["engine"]
    tool, ext = _dump_tool(engine)
    folder = os.path.join(DIR, instance, database)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    os.chmod(DIR, 0o700)
    path = os.path.join(folder, f"{backup}.{ext}")
    env_file = None
    try:
        emit("step", f"Dumping {database if engine != 'redis' else 'Redis'}")
        if engine == "redis":
            # Snapshot inside the container, then stream the file out.
            cmd, env_file = _client_cmd(target, tool, None, False)
            code, out = (
                lambda r: (r.returncode, (r.stdout + r.stderr).decode(errors="replace"))
            )(subprocess.run(cmd, capture_output=True, timeout=600))
            if code != 0:
                raise Failed(f"Redis snapshot failed: {out.strip()[-300:]}")
            if target["mode"] != "managed":
                raise Failed("Backups of external Redis aren't supported yet")
            stages = [
                [
                    "docker",
                    "exec",
                    target["container"],
                    "cat",
                    "/data/vpspilot-backup.rdb",
                ],
                ["gzip", "-c"],
                OPENSSL,
            ]
        else:
            cmd, env_file = _client_cmd(target, tool, database, False)
            stages = [cmd, *([] if engine == "postgres" else [["gzip", "-c"]]), OPENSSL]
        code, errors = _pipeline(
            stages, {len(stages) - 1: {"VPB_KEY": key}}, None, path, DUMP_TIMEOUT
        )
        if code != 0:
            raise Failed(dbs._clean_error(errors) if errors else "The dump failed")
        os.chmod(path, 0o600)
        size, checksum = os.path.getsize(path), _sha256(path)
        if size < 64:
            raise Failed("The dump came out empty")
        emit("info", f"Encrypted backup: {size} bytes, sha256 {checksum[:16]}…")
        remote = None
        if storage:
            emit("step", f"Uploading to {storage['label']}")
            remote = _put(
                storage, _remote_key({**storage, "prefix": storage.get("prefix", "")},
                                     instance, database, backup, ext),
                path, size,
            )  # fmt: skip
        if not keep_local:
            os.unlink(path)
        return {
            "exit_code": 0,
            "output": "",
            "result": {
                "path": path if keep_local else None,
                "remote_key": remote,
                "storage": storage["provider"] if storage else None,
                "size": size,
                "sha256": checksum,
            },
        }
    except Failed as error:
        if os.path.exists(path):
            os.unlink(path)
        emit("error", str(error))
        return {"exit_code": 1, "output": "", "error": str(error)}
    finally:
        if env_file:
            dbs.cleanup(env_file)


def _fetch(args: dict[str, Any], emit: Emit) -> tuple[str, bool]:
    """Path to the encrypted artifact, downloading it when needed. The bool
    says whether it's a temporary download to delete afterwards."""
    path, remote = args.get("path"), args.get("remote_key")
    if isinstance(path, str) and path:
        real = os.path.realpath(path)
        if not real.startswith(os.path.realpath(DIR) + os.sep):
            raise Rejected("invalid backup path")
        if os.path.exists(real):
            return real, False
    storage = _storage(args)
    if not storage or not isinstance(remote, str) or not PREFIX_RE.fullmatch(remote):
        raise Failed("The backup file isn't on the server and there's no remote copy")
    emit("step", "Downloading the backup")
    import tempfile

    fd, tmp = tempfile.mkstemp(prefix="vpb-", dir=DIR)
    os.close(fd)
    try:
        _get(storage, remote, tmp)
    except BaseException:
        os.unlink(tmp)
        raise
    return tmp, True


def _verify_checksum(path: str, expected: Any) -> None:
    if isinstance(expected, str) and expected and _sha256(path) != expected:
        raise Failed("Checksum mismatch: the backup file was changed or corrupted")


def restore(args: dict[str, Any], emit: Emit) -> dict[str, Any]:
    """mode=replace: into the original database; new: into `into`;
    verify: into a throwaway database that is dropped afterwards."""
    target = dbs._target(args)
    key = _key(args)
    engine = target["engine"]
    mode = args.get("mode")
    if mode not in ("replace", "new", "verify"):
        raise Rejected("invalid mode")
    _, _, database = _paths(args)
    into = args.get("into")
    if mode == "new":
        dbs._match(dbs.IDENT_RE, into, "new database name")
    path, temporary = None, False
    env_file = None
    try:
        path, temporary = _fetch(args, emit)
        _verify_checksum(path, args.get("sha256"))
        emit("info", "Checksum verified")
        if engine == "redis":
            return _restore_redis(target, path, key, mode, emit)
        destination = (
            database
            if mode == "replace"
            else into
            if mode == "new"
            else f"vpb_verify_{os.urandom(4).hex()}"
        )
        if mode != "replace":
            emit("step", f"Creating {destination}")
            dbs._run_sql(
                target,
                f"CREATE DATABASE {dbs._ident(engine, destination)};",
                None,
                False,
                1,
                60,
            )
        emit("step", f"Restoring into {destination}")
        if engine == "postgres":
            tool = [
                "pg_restore",
                "--no-owner",
                "--exit-on-error",
                *(["--clean", "--if-exists"] if mode == "replace" else []),
            ]
            cmd, env_file = _client_cmd(target, tool, destination, True)
            stages = [[*OPENSSL, "-d", "-in", path], cmd]
        else:
            client = "mysql" if engine == "mysql" else "mariadb"
            cmd, env_file = _client_cmd(target, [client], destination, True)
            stages = [[*OPENSSL, "-d", "-in", path], ["gunzip", "-c"], cmd]
        code, errors = _pipeline(
            stages, {0: {"VPB_KEY": key}}, None, None, DUMP_TIMEOUT
        )
        if code != 0:
            if mode == "verify":
                dbs._run_sql(
                    target,
                    f"DROP DATABASE IF EXISTS {dbs._ident(engine, destination)};",
                    None,
                    False,
                    1,
                    60,
                )
            if "bad decrypt" in errors:
                raise Failed(
                    "Couldn't decrypt the backup: it was made with a different key, or the file is damaged"
                )
            raise Failed(
                "Restore failed: "
                + (dbs._clean_error(errors) if errors else "unknown error")
            )
        count_sql = (
            "SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')"
            if engine == "postgres"
            else f"SELECT count(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = {dbs._quote_literal(destination)}"
        )
        tables = int(
            dbs._run_sql(
                target,
                count_sql,
                destination if engine == "postgres" else None,
                True,
                1,
                60,
            )["rows"][0][0]
        )
        emit("info", f"Restored {tables} table{'s' if tables != 1 else ''}")
        if mode == "verify":
            dbs._run_sql(
                target,
                f"DROP DATABASE {dbs._ident(engine, destination)};",
                None,
                False,
                1,
                60,
            )
            emit("info", "Dropped the verification database")
        return {
            "exit_code": 0,
            "output": "",
            "result": {
                "verified": True,
                "tables": tables,
                "database": destination if mode != "verify" else None,
            },
        }
    except (Failed, dbs.DbError) as error:
        emit("error", str(error))
        return {"exit_code": 1, "output": "", "error": str(error)[:500]}
    finally:
        if temporary and path and os.path.exists(path):
            os.unlink(path)
        if env_file:
            dbs.cleanup(env_file)


REDIS_IMAGE = "redis:7-alpine"


def _redis_ready(container: str, timeout: int = 60) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        code, out, _ = dbs._run(
            ["docker", "exec", container, "sh", "-c",
             'REDISCLI_AUTH="$VP_REDIS_PASSWORD" redis-cli PING'],
            15,
        )  # fmt: skip
        if code == 0 and "PONG" in out:
            return True
        time.sleep(1)
    return False


def _restore_redis(
    target: dict[str, Any], path: str, key: str, mode: str, emit: Emit
) -> dict[str, Any]:
    """Check the snapshot; for mode=replace, swap it into a managed
    instance. Redis ignores dump.rdb while AOF is on, so the snapshot is
    loaded with AOF off, AOF is switched on (Redis rewrites it from memory)
    and the instance is started again from that."""

    if mode == "new":
        raise Failed("Redis snapshots restore into the same instance")
    if mode == "replace" and target["mode"] != "managed":
        raise Failed(
            "Restore external Redis by hand: VPSPilot only replaces data of databases it runs"
        )
    workdir = dbs.tempdir()
    try:
        rdb = os.path.join(workdir, "dump.rdb")
        code, errors = _pipeline(
            [[*OPENSSL, "-d", "-in", path], ["gunzip", "-c"]],
            {0: {"VPB_KEY": key}},
            None,
            rdb,
            DUMP_TIMEOUT,
        )
        if code != 0:
            raise Failed("Couldn't decrypt the backup (wrong key?)")
        with open(rdb, "rb") as handle:
            if handle.read(5) != b"REDIS":
                raise Failed("The snapshot isn't a valid Redis RDB file")
        emit("info", "The snapshot is a valid Redis RDB file")
        if mode == "verify":
            return {
                "exit_code": 0,
                "output": "",
                "result": {"verified": True, "tables": 0},
            }

        container = target["container"]
        volume = container
        loader = f"vprestore-{container[len(dbs.PREFIX) :]}"
        aside = f"appendonlydir.before-restore-{int(time.time())}"
        os.chmod(workdir, 0o755)
        os.chmod(rdb, 0o644)
        emit("step", f"Stopping {container}")
        dbs._run(["docker", "stop", "-t", "30", container], 60)
        swap = (
            f"mv /data/appendonlydir /data/{aside} 2>/dev/null; "
            "cp /restore/dump.rdb /data/dump.rdb && chown redis:redis /data/dump.rdb"
        )
        code, _, err = dbs._run(
            ["docker", "run", "--rm", "-v", f"{volume}:/data",
             "-v", f"{workdir}:/restore:ro", REDIS_IMAGE, "sh", "-c", swap],
            120,
        )  # fmt: skip
        if code != 0:
            dbs._run(["docker", "start", container], 60)
            raise Failed(f"Couldn't copy the snapshot: {dbs._clean_error(err)}")
        try:
            emit("step", "Loading the snapshot")
            dbs._run(["docker", "rm", "-f", loader], 30)
            code, _, err = dbs._run(
                ["docker", "run", "-d", "--name", loader, "-v", f"{volume}:/data",
                 REDIS_IMAGE, "redis-server", "--appendonly", "no", "--save", ""],
                60,
            )  # fmt: skip
            if code != 0:
                raise Failed(f"Couldn't load the snapshot: {dbs._clean_error(err)}")

            def cli(*command: str) -> str:
                return dbs._run(["docker", "exec", loader, "redis-cli", *command], 60)[
                    1
                ]

            deadline = time.monotonic() + 120
            while "PONG" not in cli("PING") and time.monotonic() < deadline:
                time.sleep(1)
            keys = cli("DBSIZE").strip()
            emit("info", f"Loaded {keys} keys")
            cli("CONFIG", "SET", "appendonly", "yes")
            deadline = time.monotonic() + DUMP_TIMEOUT
            while time.monotonic() < deadline:
                info = cli("INFO", "persistence")
                if (
                    "aof_enabled:1" in info
                    and "aof_rewrite_in_progress:0" in info
                    and "aof_rewrite_scheduled:0" in info
                ):
                    break
                time.sleep(1)
            else:
                raise Failed("Redis didn't finish writing its append-only file")
            cli("SHUTDOWN")
            dbs._run(["docker", "wait", loader], 60)
        except Failed:
            # Put the previous data back.
            dbs._run(["docker", "rm", "-f", loader], 30)
            dbs._run(
                ["docker", "run", "--rm", "-v", f"{volume}:/data", REDIS_IMAGE, "sh",
                 "-c", f"[ -d /data/{aside} ] && mv /data/appendonlydir /data/appendonlydir.failed; mv /data/{aside} /data/appendonlydir"],
                120,
            )  # fmt: skip
            dbs._run(["docker", "start", container], 60)
            raise
        finally:
            dbs._run(["docker", "rm", "-f", loader], 30)
        emit("step", f"Starting {container}")
        dbs._run(["docker", "start", container], 60)
        if not _redis_ready(container):
            raise Failed(f"{container} didn't come back after the restore")
        code, out, _ = dbs._run(
            ["docker", "exec", container, "sh", "-c",
             'REDISCLI_AUTH="$VP_REDIS_PASSWORD" redis-cli DBSIZE'],
            30,
        )  # fmt: skip
        emit("info", f"{container} is back with {out.strip()} keys")
        return {
            "exit_code": 0,
            "output": "",
            "result": {"verified": True, "tables": 0, "keys": out.strip()},
        }
    finally:
        import shutil

        shutil.rmtree(workdir, ignore_errors=True)


def delete(args: dict[str, Any]) -> dict[str, Any]:
    """Retention: remove local files and remote objects of old backups."""
    items = args.get("items")
    if not isinstance(items, list) or len(items) > 500:
        raise Rejected("invalid items")
    storage = _storage(args) if args.get("storage") else None
    removed = 0
    for item in items:
        path = item.get("path") if isinstance(item, dict) else None
        if isinstance(path, str) and path:
            real = os.path.realpath(path)
            if real.startswith(os.path.realpath(DIR) + os.sep) and os.path.exists(real):
                os.unlink(real)
                removed += 1
        remote = item.get("remote_key") if isinstance(item, dict) else None
        if storage and isinstance(remote, str) and PREFIX_RE.fullmatch(remote):
            try:
                _remove(storage, remote)
                removed += 1
            except Failed:
                pass
    return {"exit_code": 0, "output": json.dumps({"removed": removed})}


def storage_test(args: dict[str, Any]) -> dict[str, Any]:
    storage = _storage(args)
    if storage is None:
        raise Rejected("missing storage")
    import tempfile

    key = _remote_key(
        {**storage, "prefix": storage.get("prefix", "")},
        "vpspilot-test", "check", "0" * 32, "txt",
    )  # fmt: skip
    fd, probe = tempfile.mkstemp(
        prefix="vpb-test-", dir=DIR if os.path.isdir(DIR) else None
    )
    with os.fdopen(fd, "wb") as handle:
        handle.write(b"vpspilot storage check")
    try:
        _remove(storage, _put(storage, key, probe, 22))
    except Failed as error:
        return {"exit_code": 1, "output": "", "error": str(error)}
    finally:
        os.unlink(probe)
    return {"exit_code": 0, "output": json.dumps({"ok": True})}


OPERATIONS = {"backup.delete": delete, "backup.storage_test": storage_test}
STREAMING = {"backup.create": create, "backup.restore": restore}
