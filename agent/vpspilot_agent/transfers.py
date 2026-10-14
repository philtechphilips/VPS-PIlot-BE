"""Database export and import, run by the privileged helper.

Files cross between the helper (root) and the agent (unprivileged) in two
places, chosen so neither can be used to touch other files:

- exports are written by root into a root-owned directory, readable by the
  agent's group; the agent uploads them, then asks for them to be removed;
- imports are downloaded by the agent into its own directory; root opens
  them without following links and only if the agent owns them.
"""

from __future__ import annotations

import grp
import os
import pwd
import re
import stat
from typing import Any

from vpspilot_agent import backups
from vpspilot_agent import databases as dbs
from vpspilot_agent.errors import Rejected

OUT_DIR = "/var/lib/vpspilot-transfers"
IN_DIR = "/var/lib/vpspilot/transfers"
AGENT_USER = "vpspilot"
TIMEOUT = backups.DUMP_TIMEOUT


def _job_id(args: dict[str, Any]) -> str:
    return dbs._match(re.compile(r"[0-9a-f]{32}"), args.get("job_id"), "job id")


def _agent_ids() -> tuple[int, int] | None:
    try:
        entry = pwd.getpwnam(AGENT_USER)
    except KeyError:
        return None
    return entry.pw_uid, grp.getgrgid(entry.pw_gid).gr_gid


def out_path(job_id: str) -> str:
    return os.path.join(OUT_DIR, f"{job_id}.sql.gz")


def export(args: dict[str, Any], emit: dbs.Emit) -> dict[str, Any]:
    """Plain SQL (portable to any server of the same engine), gzipped."""
    target = dbs._target(args)
    engine = target["engine"]
    if engine == "redis":
        raise Rejected("Redis is exported with backups")
    database = dbs._match(dbs.IDENT_RE, args.get("database"), "database")
    job_id = _job_id(args)
    tool = {
        "postgres": ["pg_dump", "--no-owner", "--no-privileges"],
        "mysql": ["mysqldump", "--single-transaction", "--routines", "--triggers",
                  "--no-tablespaces"],
        "mariadb": ["mariadb-dump", "--single-transaction", "--routines",
                    "--triggers", "--no-tablespaces"],
    }[engine]  # fmt: skip
    os.makedirs(OUT_DIR, mode=0o711, exist_ok=True)
    os.chmod(OUT_DIR, 0o711)
    path = out_path(job_id)
    # A fresh file in a root-owned directory: nothing to follow or replace.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    cmd, env_file = backups._client_cmd(target, tool, database, False)
    try:
        emit("step", f"Exporting {database}")
        code, errors = backups._pipeline([cmd, ["gzip", "-c"]], {}, None, path, TIMEOUT)
    finally:
        dbs.cleanup(env_file)
    if code != 0:
        os.unlink(path)
        message = dbs._clean_error(errors) if errors else "the dump failed"
        emit("error", message)
        return {"exit_code": 1, "output": "", "error": f"Export failed: {message}"}
    ids = _agent_ids()
    if ids:
        os.chown(path, 0, ids[1])
        os.chmod(path, 0o640)
    size = os.path.getsize(path)
    emit("info", f"Exported {size} bytes (gzip)")
    return {"exit_code": 0, "output": "", "result": {"path": path, "size": size}}


def cleanup(args: dict[str, Any]) -> dict[str, Any]:
    path = out_path(_job_id(args))
    if os.path.lexists(path):
        os.unlink(path)
    return {"exit_code": 0, "output": ""}


def _open_upload(path: Any) -> int:
    """Open the agent's download without following links, and only if the
    agent owns it (so it can't point root at someone else's file)."""
    if not isinstance(path, str) or os.path.dirname(path) != IN_DIR:
        raise Rejected("invalid upload path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    ids = _agent_ids()
    if not stat.S_ISREG(info.st_mode) or (ids and info.st_uid != ids[0]):
        os.close(fd)
        raise Rejected("invalid upload")
    return fd


def import_(args: dict[str, Any], emit: dbs.Emit) -> dict[str, Any]:
    target = dbs._target(args)
    engine = target["engine"]
    if engine == "redis":
        raise Rejected("Redis is restored from backups")
    database = dbs._match(dbs.IDENT_RE, args.get("database"), "database")
    fmt = args.get("format")
    if fmt not in ("sql", "sql.gz", "pgdump") or (
        fmt == "pgdump" and engine != "postgres"
    ):
        raise Rejected("invalid format")
    fd = _open_upload(args.get("path"))
    if engine == "postgres":
        tool = (
            ["pg_restore", "--no-owner", "--no-privileges", "--exit-on-error",
             "--single-transaction"]
            if fmt == "pgdump"
            else ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "--single-transaction"]
        )  # fmt: skip
    else:
        tool = ["mysql" if engine == "mysql" else "mariadb"]
    cmd, env_file = backups._client_cmd(target, tool, database, True)
    stages = [["gunzip", "-c"], cmd] if fmt == "sql.gz" else [cmd]
    try:
        emit("step", f"Importing into {database}")
        code, errors = backups._pipeline(stages, {}, fd, None, TIMEOUT)
    finally:
        dbs.cleanup(env_file)
    if code != 0:
        message = dbs._clean_error(errors) if errors else "the import failed"
        emit("error", message)
        rolled = " Nothing was changed." if engine == "postgres" else ""
        return {
            "exit_code": 1,
            "output": "",
            "error": f"Import failed: {message}.{rolled}",
        }
    count_sql = (
        "SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN "
        "('pg_catalog','information_schema')"
        if engine == "postgres"
        else "SELECT count(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = "
        + dbs._quote_literal(database)
    )
    try:
        tables = int(
            dbs._run_sql(
                target,
                count_sql,
                database if engine == "postgres" else None,
                True,
                1,
                60,
            )["rows"][0][0]
        )
    except (dbs.DbError, KeyError, IndexError, ValueError):
        tables = None
    if tables is not None:
        emit("info", f"{database} now has {tables} table{'s' if tables != 1 else ''}")
    return {"exit_code": 0, "output": "", "result": {"tables": tables}}


OPERATIONS = {"transfer.cleanup": cleanup}
STREAMING = {"db.export": export, "db.import": import_}
