"""Reading logs for the Logs page (run by the privileged helper).

- journal: systemd's journal (all units or one), read as JSON so every line
  keeps its unit and priority. Following uses the journal cursor, so no line
  is skipped or repeated.
- container: a container's stdout and stderr, merged by timestamp.

Output is bounded in lines and bytes; nothing is ever written.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any

from vpspilot_agent.errors import Rejected

UNIT_RE = re.compile(r"[A-Za-z0-9@._:-]{1,200}")
CONTAINER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
CURSOR_RE = re.compile(r"[A-Za-z0-9=;_\-]{1,512}")
SINCE_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z")
MAX_JSON = 60 * 1024
MAX_LINE = 2000
TIMEOUT = 30


def _lines(args: dict[str, Any]) -> int:
    lines = args.get("lines", 200)
    if not isinstance(lines, int) or isinstance(lines, bool) or not 1 <= lines <= 1000:
        raise Rejected("lines must be 1-1000")
    return lines


def _bounded(body: dict[str, Any]) -> str:
    text = json.dumps(body)
    while len(text) > MAX_JSON and body["lines"]:
        # Keep the newest lines.
        body["lines"] = body["lines"][len(body["lines"]) // 4 + 1 :]
        text = json.dumps(body)
    return text


def _journal(args: dict[str, Any]) -> dict[str, Any]:
    if shutil.which("journalctl") is None:
        return {
            "exit_code": 1,
            "output": "",
            "error": "This server has no systemd journal",
        }
    lines = _lines(args)
    cmd = ["journalctl", "--no-pager", "-o", "json", "-n", str(lines)]
    unit = args.get("unit")
    if unit is not None:
        if not isinstance(unit, str) or not UNIT_RE.fullmatch(unit):
            raise Rejected("invalid unit")
        cmd += ["-u", unit]
    priority = args.get("priority")
    if priority is not None:
        if (
            not isinstance(priority, int)
            or isinstance(priority, bool)
            or not 0 <= priority <= 7
        ):
            raise Rejected("invalid priority")
        cmd += ["-p", str(priority)]
    cursor = args.get("cursor")
    if cursor is not None:
        if not isinstance(cursor, str) or not CURSOR_RE.fullmatch(cursor):
            raise Rejected("invalid cursor")
        cmd += ["--after-cursor", cursor]
    try:
        done = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=TIMEOUT,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return {
            "exit_code": 124,
            "output": "",
            "error": "Reading the journal timed out",
        }
    if done.returncode != 0 and not done.stdout:
        return {
            "exit_code": done.returncode,
            "output": "",
            "error": (done.stderr.strip() or "journalctl failed")[-300:],
        }
    entries = []
    last_cursor = cursor
    for raw in done.stdout.splitlines():
        try:
            entry = json.loads(raw)
        except ValueError:
            continue
        message = entry.get("MESSAGE")
        if isinstance(message, list):  # binary messages come as byte arrays
            message = bytes(
                b for b in message if isinstance(b, int) and 0 <= b < 256
            ).decode("utf-8", "replace")
        try:
            usec = int(entry.get("__REALTIME_TIMESTAMP", "0"))
        except ValueError:
            usec = 0
        entries.append(
            {
                "t": usec,
                "u": str(
                    entry.get("_SYSTEMD_UNIT")
                    or entry.get("SYSLOG_IDENTIFIER")
                    or entry.get("_COMM")
                    or "kernel"
                )[:120],
                "p": int(entry.get("PRIORITY", 6))
                if str(entry.get("PRIORITY", "6")).isdigit()
                else 6,
                "m": str(message or "")[:MAX_LINE],
            }
        )
        last_cursor = entry.get("__CURSOR") or last_cursor
    return {
        "exit_code": 0,
        "output": _bounded(
            {"source": "journal", "cursor": last_cursor, "lines": entries}
        ),
    }


def _ts_key(ts: str) -> str:
    head, _, frac = ts.rstrip("Z").partition(".")
    return f"{head}.{frac.ljust(9, '0')}"


def _container(args: dict[str, Any]) -> dict[str, Any]:
    name = args.get("container")
    if not isinstance(name, str) or not CONTAINER_RE.fullmatch(name):
        raise Rejected("invalid container")
    lines = _lines(args)
    since = args.get("since")
    if since is not None and (
        not isinstance(since, str) or not SINCE_RE.fullmatch(since)
    ):
        raise Rejected("invalid since")
    cmd = ["docker", "logs", "--timestamps", "--tail", str(lines)]
    if since:
        cmd += ["--since", since]
    try:
        done = subprocess.run(
            [*cmd, name],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=TIMEOUT,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return {"exit_code": 124, "output": "", "error": "Reading logs timed out"}
    if done.returncode != 0 and "No such container" in done.stderr:
        return {"exit_code": 1, "output": "", "error": f"No container named {name}"}
    entries = []
    for stream, text in (("out", done.stdout), ("err", done.stderr)):
        for line in text.splitlines():
            ts, _, message = line.partition(" ")
            if SINCE_RE.fullmatch(ts):
                entries.append({"t": ts, "s": stream, "m": message[:MAX_LINE]})
    entries.sort(key=lambda e: _ts_key(e["t"]))
    return {
        "exit_code": 0,
        "output": _bounded({"source": "container", "lines": entries[-lines:]}),
    }


def read(args: dict[str, Any]) -> dict[str, Any]:
    source = args.get("source")
    if source == "journal":
        return _journal(args)
    if source == "container":
        return _container(args)
    raise Rejected("invalid source")


OPERATIONS = {"logs.read": read}
