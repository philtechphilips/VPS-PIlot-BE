"""Run a command inside an app (scheduled jobs), run by the privileged helper.

The command runs where the app does, never on the host as root: inside the
app's container (Docker), its public service's container (Compose), or as
the app's own user in its current release with its environment, sandboxed
like the app itself (systemd). It's the same trust as the app's start
command.
"""

from __future__ import annotations

import os
import subprocess
import threading
from typing import Any

from vpspilot_agent import deploy as d
from vpspilot_agent import native
from vpspilot_agent.errors import Rejected

MAX_TIMEOUT = 6 * 3600
TAIL_LINES = 200


def _command(args: dict[str, Any]) -> list[str]:
    app = d._match(d.APP_RE, args.get("app"), "app name")
    runtime = args.get("runtime")
    command = args.get("command")
    if not isinstance(command, str) or not 0 < len(command) <= 500 or "\n" in command:
        raise Rejected("invalid command")
    if runtime == "docker":
        return ["docker", "exec", f"vp-{app}", "sh", "-c", command]
    if runtime == "compose":
        service = d._match(d.SERVICE_RE, args.get("service"), "service")
        return ["docker", "exec", f"vp-{app}-{service}-1", "sh", "-c", command]
    if runtime != "systemd":
        raise Rejected("invalid runtime")
    paths = native._paths(app)
    if not os.path.islink(paths["current"]):
        raise Rejected("the app has no live release")
    job = d._match(d.HEX_RE, args.get("job_id"), "job id")
    return [
        "systemd-run", "--wait", "--pipe", "--quiet", "--collect",
        f"--unit=vp-{app}-run-{job[:8]}",
        *native._sandbox(native.user_for(app), paths, {"cpus": None, "memory": None}),
        "-p", f"WorkingDirectory={paths['current']}",
        "-p", f"EnvironmentFile={paths['env']}",
        "/bin/sh", "-c", command,
    ]  # fmt: skip


def run(args: dict[str, Any], emit) -> dict[str, Any]:
    cmd = _command(args)
    timeout = args.get("timeout", 3600)
    if not isinstance(timeout, int) or not 60 <= timeout <= MAX_TIMEOUT:
        raise Rejected("invalid timeout")
    emit("step", f"Running: {args['command'][:200]}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            errors="replace",
            env={"PATH": native.SYSTEM_PATH},
        )
    except OSError as error:
        return {"exit_code": 127, "output": "", "error": str(error)}
    timer = threading.Timer(timeout, proc.kill)
    timer.start()
    tail: list[str] = []
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            line = line.rstrip("\n")
            emit("output", line[:2000])
            tail = (tail + [line])[-TAIL_LINES:]
        code = proc.wait()
    finally:
        timed_out = not timer.is_alive() and proc.returncode not in (0, None)
        timer.cancel()
    output = "\n".join(tail)
    if timed_out and code < 0:
        return {"exit_code": 124, "output": output, "error": f"Stopped after {timeout // 60} min"}
    if code != 0:
        last = next((line for line in reversed(tail) if line.strip()), "")
        message = f"Exited with code {code}" + (f": {last[:200]}" if last else "")
        if code == 1 and "No such container" in output:
            message = "The app isn't running"
        return {"exit_code": code, "output": output, "error": message}
    emit("info", "Finished")
    return {"exit_code": 0, "output": output}


STREAMING = {"app.exec": run}
