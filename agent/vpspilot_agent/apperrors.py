"""Error lines in the apps' logs, counted per app and minute.

The agent asks for this once a minute (helper op "app.errors") and sends the
counts to the control plane, which alerts on them. Only counts and the latest
error line per app and minute leave the server, with secrets masked.

An error line is one the app logged at error level: a JSON log with level
error/fatal (or pino's 50+), a journal entry with priority err or worse, or a
line with an error marker (ERROR, FATAL, Traceback, TypeError:, [error]...).
Text on stderr alone doesn't count: many apps log everything there.
"""

from __future__ import annotations

import calendar
import hashlib
import json
import re
import subprocess
import time
from typing import Any

from vpspilot_agent import deploy as d
from vpspilot_agent.errors import Rejected

MAX_LINES = 20_000  # per app and read; the rest of a flood is skipped
MAX_SECONDS = 40  # whole scan, so the agent's helper call doesn't time out
MAX_ROWS = 2000
MAX_SAMPLE = 300
SKIP_SUFFIXES = ("-candidate", "-build")  # deploys in progress, not the live app

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
ERROR_RE = re.compile(
    r"\b(?:ERROR|FATAL|CRITICAL|PANIC|EMERG)\b"
    r"|\b(?:Error|Fatal|Panic)\b"
    r"|\b[A-Z]\w*(?:Error|Exception)\b"  # TypeError, ValueError, IOException
    r"|^Traceback \(most recent call last\)"
    r"|\[(?:error|fatal|crit|critical|emerg|alert)\]"
    r"|\blevel=\"?(?:error|fatal|panic|critical)\b"
    r"|^(?:error|fatal|panic)(?:\[|:)"
    r"|\bnpm (?:ERR!|error)"
    r"|\b(?:uncaughtException|unhandledRejection)\b"
    r"|^\s*⨯ "  # Next.js marks server errors with ⨯
)
JSON_LEVELS = {"error", "err", "fatal", "critical", "crit", "panic", "emerg", "alert"}
SECRETS = (
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [redacted]"),
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key"
            r"|authorization|cookie)(\"?\s*[:=]\s*\"?)[^\s\"',;&]+"
        ),
        r"\1\2[redacted]",
    ),
    (re.compile(r"(://[^:/\s@]+:)[^@\s/]+@"), r"\1[redacted]@"),
)


def is_error(message: str, priority: str | None = None) -> bool:
    if priority is not None and priority in ("0", "1", "2", "3"):
        return True
    text = message.strip()
    if text.startswith("{"):
        try:
            entry = json.loads(text)
        except ValueError:
            entry = None
        if isinstance(entry, dict):
            keys = ("level", "severity", "lvl", "log.level")
            level = next((entry[k] for k in keys if k in entry), None)
            if isinstance(level, (int, float)) and not isinstance(level, bool):
                return level >= 50  # pino / bunyan
            if isinstance(level, str):
                return level.strip().lower() in JSON_LEVELS
    return bool(ERROR_RE.search(text))


FINGERPRINT_PARTS = (
    (re.compile(r"^\S*\d{4}-\d{2}-\d{2}[T ][\d:.]+\S*\s*"), ""),  # leading timestamps
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27}"), "<id>"),  # UUIDs
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), "<id>"),  # hashes, object ids
    (re.compile(r"(['\"`])(?:(?!\1).){0,200}\1"), "<s>"),  # quoted values
    (re.compile(r"\d+(\.\d+)?"), "<n>"),  # numbers, ports, durations
    (re.compile(r"\s+"), " "),
)
MAX_GROUPS = 20  # per app and minute


def fingerprint(message: str) -> str:
    """The same bug gives the same fingerprint, whatever the ids, numbers
    and quoted values in its message."""
    text = message.strip()
    for pattern, replacement in FINGERPRINT_PARTS:
        text = pattern.sub(replacement, text)
    return hashlib.sha1(text[:300].encode()).hexdigest()[:16]


def redact(message: str) -> str:
    for pattern, replacement in SECRETS:
        message = pattern.sub(replacement, message)
    return message[:MAX_SAMPLE]


def _epoch(ts: str) -> float:
    head, _, frac = ts.rstrip("Z").partition(".")
    return calendar.timegm(time.strptime(head, "%Y-%m-%dT%H:%M:%S")) + float(
        f"0.{frac or '0'}"
    )


def _stamp(epoch: float) -> str:
    whole = int(epoch)
    nanos = int(round((epoch - whole) * 1e9))
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(whole)) + f".{nanos:09d}Z"


def _sources() -> list[tuple[str, str, str]]:
    """(app, kind, name) for every running app: docker containers, the
    services of Compose projects, and systemd units."""
    found: list[tuple[str, str, str]] = []
    code, out = d._run(
        [
            "docker", "ps", "--format",
            '{{.Names}}\t{{.Label "com.docker.compose.project"}}',
        ],
        timeout=15,
    )  # fmt: skip
    for line in out.splitlines() if code == 0 else []:
        name, _, project = line.partition("\t")
        if project.startswith("vp-"):
            app = project[3:]
        elif name.startswith("vp-") and not project:
            app = name[3:]
        else:
            continue
        if d.APP_RE.match(app) and not app.endswith(SKIP_SUFFIXES):
            found.append((app, "docker", name))
    code, out = d._run(
        [
            "systemctl", "list-units", "--type=service", "--state=running",
            "--no-legend", "--plain", "vp-*.service",
        ],
        timeout=15,
    )  # fmt: skip
    for line in out.splitlines() if code == 0 else []:
        unit = line.split(" ", 1)[0]
        app = unit.removeprefix("vp-").removesuffix(".service")
        if not unit.startswith("vp-") or app.endswith(SKIP_SUFFIXES):
            continue
        if d.APP_RE.match(app):
            found.append((app, "systemd", unit))
    return found


def _docker_lines(name: str, since: str, until: str, deadline: float, limit: int | None = MAX_LINES):
    """(epoch, message, priority) for lines logged in (since, until]."""
    proc = subprocess.Popen(
        ["docker", "logs", "--timestamps", "--since", since, "--until", until, name],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        errors="replace",
    )
    low, high = d._ts_key(since), d._ts_key(until)
    assert proc.stdout is not None
    try:
        for count, line in enumerate(proc.stdout):
            if (limit is not None and count >= limit) or time.monotonic() > deadline:
                break
            ts, _, message = line.rstrip("\n").partition(" ")
            if not d.SINCE_RE.fullmatch(ts) or not low < d._ts_key(ts) <= high:
                continue
            yield _epoch(ts), message, None
    finally:
        proc.kill()
        proc.wait()


def _journal_lines(unit: str, since: float, until: float, deadline: float, limit: int | None = MAX_LINES):
    proc = subprocess.Popen(
        [
            "journalctl", "-u", unit, "-o", "json", "--no-pager",
            "--since", f"@{int(since)}", "--until", f"@{int(until) + 1}",
            "--output-fields=MESSAGE,PRIORITY",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        text=True,
        errors="replace",
    )  # fmt: skip
    low, high = int(since * 1_000_000), int(until * 1_000_000)
    assert proc.stdout is not None
    try:
        for count, line in enumerate(proc.stdout):
            if (limit is not None and count >= limit) or time.monotonic() > deadline:
                break
            try:
                row = json.loads(line)
                stamp = int(row["__REALTIME_TIMESTAMP"])
            except (ValueError, KeyError, TypeError):
                continue
            if not low < stamp <= high:
                continue
            message = row.get("MESSAGE")
            if isinstance(message, list):  # non-UTF-8 output comes as bytes
                message = bytes(b for b in message if isinstance(b, int)).decode(
                    "utf-8", "replace"
                )
            yield stamp / 1_000_000, str(message or ""), str(row.get("PRIORITY", "6"))
    finally:
        proc.kill()
        proc.wait()


def _ignore(value: Any) -> dict[str, list[str]]:
    """Per app, lowercased substrings to leave out (plain text, not regex)."""
    if not isinstance(value, dict):
        return {}
    out = {}
    for app, patterns in list(value.items())[:500]:
        if not isinstance(app, str) or not isinstance(patterns, list):
            continue
        if d.APP_RE.match(app):
            # Plain text (substrings), and "fp:<fingerprint>" for ignored groups.
            out[app] = [
                p.lower()
                for p in patterns[:200]
                if isinstance(p, str) and 0 < len(p) <= 200
            ]
    return out


def scan(args: dict[str, Any]) -> dict[str, Any]:
    """Error lines per app and minute since `since` (a Docker log timestamp).
    Returns {"until": cursor, "rows": [{"app", "minute", "errors", "sample"}]}."""
    since = args.get("since")
    if not isinstance(since, str) or not d.SINCE_RE.fullmatch(since):
        raise Rejected("invalid since")
    ignore = _ignore(args.get("ignore"))
    # A second back, so lines still being written land in the next read.
    until_epoch = time.time() - 1
    since_epoch = _epoch(since)
    if since_epoch >= until_epoch:
        return {"exit_code": 0, "output": json.dumps({"until": since, "rows": []})}
    until = _stamp(until_epoch)
    deadline = time.monotonic() + MAX_SECONDS
    buckets: dict[tuple[str, int], dict[str, Any]] = {}
    for app, kind, name in _sources():
        lines = (
            _docker_lines(name, since, until, deadline)
            if kind == "docker"
            else _journal_lines(name, since_epoch, until_epoch, deadline)
        )
        for epoch, message, priority in lines:
            message = ANSI_RE.sub("", message)
            if not is_error(message, priority):
                continue
            lowered = message.lower()
            skip = ignore.get(app, ())
            if any(p in lowered for p in skip if not p.startswith("fp:")):
                continue
            fp = fingerprint(message)
            if f"fp:{fp}" in skip:
                continue
            minute = int(epoch) // 60 * 60
            row = buckets.setdefault(
                (app, minute),
                {"app": app, "minute": minute, "errors": 0, "sample": "", "groups": {}},
            )
            row["errors"] += 1
            row["sample"] = redact(message.strip())
            group = row["groups"].get(fp)
            if group is None and len(row["groups"]) < MAX_GROUPS:
                group = row["groups"][fp] = {"fp": fp, "count": 0, "sample": row["sample"]}
            if group is not None:
                group["count"] += 1
    rows = sorted(buckets.values(), key=lambda r: r["minute"])[-MAX_ROWS:]
    for row in rows:
        row["groups"] = list(row["groups"].values())
    return {"exit_code": 0, "output": json.dumps({"until": until, "rows": rows})}


MAX_MATCHES = 500


def search(args: dict[str, Any]) -> dict[str, Any]:
    """Lines containing `query` (plain text, any case) in the apps' logs since
    `since`, newest last. Only what the server still keeps: Docker keeps 30 MB
    per app, the journal what its settings allow."""
    query = args.get("query")
    if not isinstance(query, str) or not 1 <= len(query) <= 200:
        raise Rejected("invalid query")
    since = args.get("since")
    if not isinstance(since, str) or not d.SINCE_RE.fullmatch(since):
        raise Rejected("invalid since")
    apps = args.get("apps")
    if apps is not None and (
        not isinstance(apps, list) or not all(isinstance(a, str) and d.APP_RE.match(a) for a in apps)
    ):
        raise Rejected("invalid apps")
    needle = query.lower()
    until_epoch = time.time()
    since_epoch = _epoch(since)
    deadline = time.monotonic() + MAX_SECONDS
    matches: list[dict[str, Any]] = []
    truncated = False
    for app, kind, name in _sources():
        if apps is not None and app not in apps:
            continue
        lines = (
            _docker_lines(name, since, _stamp(until_epoch), deadline, limit=None)
            if kind == "docker"
            else _journal_lines(name, since_epoch, until_epoch, deadline, limit=None)
        )
        for epoch, message, _ in lines:
            message = ANSI_RE.sub("", message)
            if needle in message.lower():
                matches.append({"app": app, "t": epoch, "line": redact(message.strip())})
    matches.sort(key=lambda m: m["t"])
    if len(matches) > MAX_MATCHES:
        matches, truncated = matches[-MAX_MATCHES:], True
    body = {"matches": matches, "truncated": truncated, "timed_out": time.monotonic() > deadline}
    return {"exit_code": 0, "output": json.dumps(body), "result": {"count": len(matches)}}


OPERATIONS = {"app.errors": scan, "logs.search": search}
