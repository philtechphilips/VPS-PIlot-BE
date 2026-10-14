"""Runs claimed jobs by asking the privileged helper for one fixed operation."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

from vpspilot_agent import helper
from vpspilot_agent.client import ApiError, Client, NotEnrolled

log = logging.getLogger("vpspilot_agent")

SUPPORTED_VERSION = 1
# Job types map one-to-one onto helper operations.
SUPPORTED = {
    "service.restart",
    "service.start",
    "service.stop",
    "service.logs",
    "container.restart",
    "container.start",
    "container.stop",
    "container.logs",
    "app.deploy",
    "app.remove",
    "app.logs",
    "db.create",
    "db.remove",
    "db.control",
    "db.query",
    "db.explore",
    "db.admin",
    "db.redis",
    "logs.read",
    "proxy.apply",
    "proxy.status",
    "backup.create",
    "backup.restore",
    "backup.delete",
    "backup.storage_test",
}
# Long operations that stream progress from the helper.
STREAMING = {
    "app.deploy",
    "app.remove",
    "db.create",
    "db.remove",
    "proxy.apply",
    "backup.create",
    "backup.restore",
}
# Read-only, frequent: no "Running ..." progress event.
QUIET = {"app.logs", "logs.read", "db.query", "db.explore", "db.redis", "proxy.status"}
STREAM_IDLE_TIMEOUT = 30 * 60
MAX_OUTPUT = 256 * 1024
MAX_EVENT = 2000
FLUSH_SECONDS = 2.0

HelperCall = Callable[..., dict[str, Any]]


class EventSink:
    """Batches progress lines into job events so a long build becomes a few
    hundred events, not thousands, and keeps the full log for the output."""

    def __init__(self, client: Client, base: str):
        self.client = client
        self.base = base
        self.pending: list[dict[str, str]] = []
        self.chunk: list[str] = []
        self.log: list[str] = []
        self.size = 0
        self.last_flush = time.monotonic()

    def __call__(self, level: str, message: str) -> None:
        self.log.append(message if level == "output" else f"==> {message}")
        self.size += len(message) + 1
        while self.size > MAX_OUTPUT and self.log:
            self.size -= len(self.log.pop(0)) + 1
        if level == "output":
            if sum(len(x) + 1 for x in self.chunk) + len(message) > MAX_EVENT:
                self._close_chunk()
            self.chunk.append(message[:MAX_EVENT])
        else:
            self._close_chunk()
            level = "info" if level == "step" else level
            if level not in ("info", "warn", "error"):
                level = "info"
            self.pending.append(
                {"level": level, "message": f"==> {message}"[:MAX_EVENT]}
            )
        if time.monotonic() - self.last_flush >= FLUSH_SECONDS:
            self.flush()

    def _close_chunk(self) -> None:
        if self.chunk:
            self.pending.append({"level": "info", "message": "\n".join(self.chunk)})
            self.chunk = []

    def flush(self) -> None:
        self._close_chunk()
        self.last_flush = time.monotonic()
        while self.pending:
            batch, self.pending = self.pending[:50], self.pending[50:]
            try:
                self.client.post(f"{self.base}/events", {"events": batch})
            except NotEnrolled:
                raise
            except (ApiError, OSError) as error:
                # Progress is best effort; the final result still carries the log.
                log.warning("couldn't send job events: %s", error)

    def output(self) -> str:
        return "\n".join(self.log)[-MAX_OUTPUT:]


def run_job(client: Client, job: dict[str, Any], call: HelperCall = helper.call) -> str:
    """Execute one job and report the outcome. Returns the final status."""
    job_id, job_type = job["id"], job["type"]
    base = f"/agent/v1/jobs/{job_id}"

    def finish(
        ok: bool,
        exit_code: int | None,
        output: str,
        error: str | None,
        result: dict[str, Any] | None = None,
    ) -> str:
        status = "succeeded" if ok else "failed"
        client.post(
            f"{base}/complete",
            {
                "status": status,
                "exit_code": exit_code,
                "output": output,
                "error": error,
                "result": result or {},
            },
        )
        log.info("job %s %s: %s", job_id, job_type, status)
        return status

    if job_type not in SUPPORTED or int(job.get("version", 1)) > SUPPORTED_VERSION:
        return finish(False, None, "", f"This agent doesn't support {job_type}")

    if job_type in STREAMING:
        return _run_streaming(client, job, call, finish)

    args = dict(job.get("payload") or {})
    if args.pop("has_secrets", False):
        try:
            args["secrets"] = client.get(f"{base}/secrets").get("secrets") or {}
        except ApiError as error:
            if isinstance(error, NotEnrolled):
                raise
            return finish(
                False, None, "", f"Couldn't load credentials: {error.message}"
            )
    if job_type not in QUIET:
        client.post(
            f"{base}/events",
            {"events": [{"level": "info", "message": f"Running {job_type}"}]},
        )
    try:
        result = call(job_type, args)
    except OSError as error:
        return finish(False, None, "", f"Privileged helper unavailable: {error}")
    if "error" in result and "exit_code" not in result:
        return finish(False, None, "", result["error"])
    return finish(
        bool(result.get("ok")),
        result.get("exit_code"),
        result.get("output", ""),
        None if result.get("ok") else (result.get("error") or "Command failed"),
    )


def _run_streaming(
    client: Client, job: dict[str, Any], call: HelperCall, finish
) -> str:
    base = f"/agent/v1/jobs/{job['id']}"
    args = dict(job.get("payload") or {})
    if job["type"] == "app.deploy" and args.pop("has_env", False):
        try:
            secrets = client.get(f"{base}/secrets")
            args["env"] = secrets.get("env") or {}
            args["secret_keys"] = secrets.get("secret_keys") or []
            if secrets.get("git_token"):
                args["git_token"] = secrets["git_token"]
        except ApiError as error:
            if isinstance(error, NotEnrolled):
                raise
            return finish(
                False, None, "", f"Couldn't load environment: {error.message}"
            )
    elif args.pop("has_secrets", False):
        try:
            args["secrets"] = client.get(f"{base}/secrets").get("secrets") or {}
        except ApiError as error:
            if isinstance(error, NotEnrolled):
                raise
            return finish(
                False, None, "", f"Couldn't load credentials: {error.message}"
            )
    sink = EventSink(client, base)
    try:
        result = call(job["type"], args, timeout=STREAM_IDLE_TIMEOUT, on_event=sink)
    except OSError as error:
        sink.flush()
        return finish(
            False, None, sink.output(), f"Privileged helper unavailable: {error}"
        )
    sink.flush()
    ok = bool(result.get("ok"))
    return finish(
        ok,
        result.get("exit_code"),
        sink.output() or result.get("output", ""),
        None if ok else (result.get("error") or "The operation failed"),
        {k: v for k, v in (result.get("result") or {}).items() if v is not None},
    )
