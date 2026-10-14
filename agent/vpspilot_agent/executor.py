"""Runs claimed jobs by asking the privileged helper for one fixed operation."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from vpspilot_agent import helper
from vpspilot_agent.client import Client

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
}

HelperCall = Callable[[str, dict[str, Any]], dict[str, Any]]


def run_job(client: Client, job: dict[str, Any], call: HelperCall = helper.call) -> str:
    """Execute one job and report the outcome. Returns the final status."""
    job_id, job_type = job["id"], job["type"]
    base = f"/agent/v1/jobs/{job_id}"

    def finish(ok: bool, exit_code: int | None, output: str, error: str | None) -> str:
        status = "succeeded" if ok else "failed"
        client.post(
            f"{base}/complete",
            {
                "status": status,
                "exit_code": exit_code,
                "output": output,
                "error": error,
            },
        )
        log.info("job %s %s: %s", job_id, job_type, status)
        return status

    if job_type not in SUPPORTED or int(job.get("version", 1)) > SUPPORTED_VERSION:
        return finish(False, None, "", f"This agent doesn't support {job_type}")

    client.post(
        f"{base}/events",
        {"events": [{"level": "info", "message": f"Running {job_type}"}]},
    )
    try:
        result = call(job_type, job.get("payload") or {})
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
