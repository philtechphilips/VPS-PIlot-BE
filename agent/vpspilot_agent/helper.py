"""Privileged helper: the only part of VPSPilot that runs as root.

It accepts one JSON request per connection on a Unix socket readable only by
the vpspilot group, checks the caller's credentials, and runs one operation
from a fixed allowlist with argument lists (never a shell). There is no
"run this command" operation.

    python3 -m vpspilot_agent.helper --socket /run/vpspilot/helper.sock
"""

from __future__ import annotations

import argparse
import grp
import json
import logging
import os
import pwd
import re
import shutil
import socket
import struct
import subprocess
import sys
from collections.abc import Callable
from typing import Any

log = logging.getLogger("vpspilot_helper")

UNIT_RE = re.compile(r"^[A-Za-z0-9@._:-]{1,200}\.service$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
PROTECTED_UNITS = {"vpspilot-agent.service", "vpspilot-helper.service"}
NO_STOP_UNITS = {"ssh.service", "sshd.service"}
MAX_OUTPUT = 64 * 1024
MAX_REQUEST = 16 * 1024
TIMEOUT = 60


class Rejected(Exception):
    pass


def _unit(args: dict[str, Any]) -> str:
    unit = args.get("unit")
    if not isinstance(unit, str) or not UNIT_RE.match(unit):
        raise Rejected("invalid unit name")
    return unit


def _container(args: dict[str, Any]) -> str:
    name = args.get("container")
    if not isinstance(name, str) or not CONTAINER_RE.match(name):
        raise Rejected("invalid container name")
    return name


def _lines(args: dict[str, Any]) -> int:
    lines = args.get("lines", 200)
    if not isinstance(lines, int) or not 1 <= lines <= 500:
        raise Rejected("lines must be 1-500")
    return lines


def _run(cmd: list[str], timeout: int = TIMEOUT) -> dict[str, Any]:
    try:
        done = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return {"exit_code": 124, "output": f"Timed out after {timeout}s"}
    except OSError as error:
        return {"exit_code": 127, "output": str(error)}
    output = (done.stdout or "") + (done.stderr or "")
    return {"exit_code": done.returncode, "output": output[-MAX_OUTPUT:]}


def _service(verb: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def op(args: dict[str, Any]) -> dict[str, Any]:
        unit = _unit(args)
        if unit in PROTECTED_UNITS:
            raise Rejected(f"{unit} is managed by VPSPilot")
        if verb == "stop" and unit in NO_STOP_UNITS:
            raise Rejected("stopping SSH is not allowed")
        result = _run(["systemctl", verb, unit])
        if result["exit_code"] == 0:
            state = _run(["systemctl", "is-active", unit], timeout=10)
            result["output"] = (
                f"{result['output']}{unit}: {state['output'].strip()}".strip()
            )
        return result

    return op


def _service_logs(args: dict[str, Any]) -> dict[str, Any]:
    cmd = ["journalctl", "-u", _unit(args), "-n", str(_lines(args))]
    return _run([*cmd, "--no-pager", "-o", "short-iso"])


def _docker(verb: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def op(args: dict[str, Any]) -> dict[str, Any]:
        return _run(["docker", verb, _container(args)])

    return op


def _container_logs(args: dict[str, Any]) -> dict[str, Any]:
    tail = str(_lines(args))
    return _run(["docker", "logs", "--tail", tail, "--timestamps", _container(args)])


def _docker_ps(args: dict[str, Any]) -> dict[str, Any]:
    if shutil.which("docker") is None:
        return {"exit_code": 127, "output": "docker not installed"}
    return _run(["docker", "ps", "-a", "--format", "{{json .}}"], timeout=15)


OPERATIONS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "ping": lambda args: {"exit_code": 0, "output": "pong"},
    "service.restart": _service("restart"),
    "service.start": _service("start"),
    "service.stop": _service("stop"),
    "service.logs": _service_logs,
    "container.restart": _docker("restart"),
    "container.start": _docker("start"),
    "container.stop": _docker("stop"),
    "container.logs": _container_logs,
    "docker.ps": _docker_ps,
}


def handle(request: dict[str, Any]) -> dict[str, Any]:
    op = request.get("op")
    args = request.get("args") or {}
    if op not in OPERATIONS or not isinstance(args, dict):
        return {"ok": False, "error": f"operation not allowed: {op}"}
    try:
        result = OPERATIONS[op](args)
    except Rejected as error:
        return {"ok": False, "error": str(error)}
    return {"ok": result["exit_code"] == 0, **result}


def _peer_allowed(conn: socket.socket, allowed_uids: set[int]) -> bool:
    creds = conn.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid in allowed_uids


def serve(path: str, group: str = "vpspilot", agent_user: str = "vpspilot") -> None:
    allowed = {0, pwd.getpwnam(agent_user).pw_uid}
    if os.path.exists(path):
        os.unlink(path)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    os.chown(path, 0, grp.getgrnam(group).gr_gid)
    os.chmod(path, 0o660)
    server.listen(8)
    log.info("helper listening on %s", path)
    while True:
        conn, _ = server.accept()
        with conn:
            try:
                if not _peer_allowed(conn, allowed):
                    log.warning("rejected connection from unexpected user")
                    continue
                raw = b""
                while not raw.endswith(b"\n") and len(raw) < MAX_REQUEST:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                request = json.loads(raw or b"{}")
                response = handle(request)
                log.info(
                    "%s %s -> %s",
                    request.get("op"),
                    json.dumps(request.get("args") or {})[:200],
                    "ok" if response.get("ok") else response.get("error") or "failed",
                )
            except (ValueError, OSError) as error:
                response = {"ok": False, "error": f"bad request: {error}"}
            try:
                conn.sendall(json.dumps(response).encode() + b"\n")
            except OSError:
                pass


def call(
    op: str,
    args: dict[str, Any] | None = None,
    path: str = "/run/vpspilot/helper.sock",
    timeout: float = TIMEOUT + 5,
) -> dict[str, Any]:
    """Client used by the (unprivileged) agent."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        conn.connect(path)
        conn.sendall(json.dumps({"op": op, "args": args or {}}).encode() + b"\n")
        raw = b""
        while not raw.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break
            raw += chunk
    return json.loads(raw)


def main() -> int:
    parser = argparse.ArgumentParser(prog="vpspilot-helper")
    parser.add_argument("--socket", default="/run/vpspilot/helper.sock")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stdout
    )
    if os.geteuid() != 0:
        print("The helper must run as root.", file=sys.stderr)
        return 1
    serve(args.socket)
    return 0


if __name__ == "__main__":
    sys.exit(main())
