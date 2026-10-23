"""Operating system updates and reboots (run by the privileged helper).

apt runs in its own transient systemd unit, so it finishes even if the
helper is restarted mid-upgrade (a half-done dpkg run is worse than either
state). needrestart is told to stay out of the way: it would ask questions,
or restart the helper and with it this job.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any

from vpspilot_agent.errors import Rejected

UNIT = "vpspilot-os-upgrade"
TIMEOUT = 45 * 60
APT_OPTIONS = (
    "-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
)
SCRIPTS = {
    # Security fixes only, the way the server's own unattended-upgrades would.
    "security": "apt-get update -q && unattended-upgrade -v",
    # Every pending update; never removes packages (that's dist-upgrade).
    "all": f"apt-get update -q && apt-get {APT_OPTIONS} upgrade",
}


def upgrade(args: dict[str, Any], emit) -> dict[str, Any]:
    mode = args.get("mode")
    if mode not in SCRIPTS:
        raise Rejected("invalid mode")
    if shutil.which("apt-get") is None:
        return {"exit_code": 1, "output": "", "error": "Only apt-based systems are supported"}
    if mode == "security" and shutil.which("unattended-upgrade") is None:
        return {
            "exit_code": 1,
            "output": "",
            "error": "Security-only updates need the unattended-upgrades package; "
            "install it or apply all updates",
        }
    subprocess.run(["systemctl", "reset-failed", f"{UNIT}.service"], capture_output=True, check=False)
    emit("step", "Installing security updates" if mode == "security" else "Installing all updates")
    proc = subprocess.Popen(
        [
            "systemd-run", f"--unit={UNIT}", "--wait", "--pipe", "--quiet", "--collect",
            "--setenv=DEBIAN_FRONTEND=noninteractive",
            "--setenv=NEEDRESTART_SUSPEND=1",
            "--setenv=APT_LISTCHANGES_FRONTEND=none",
            "/bin/sh", "-c", SCRIPTS[mode],
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        errors="replace",
    )  # fmt: skip
    tail: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip()
        if line:
            emit("output", line[:500])
            tail = (tail + [line])[-20:]
    try:
        code = proc.wait(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        return {"exit_code": 124, "output": "", "error": "The upgrade took too long; it keeps running on the server"}
    if code != 0:
        return {"exit_code": code, "output": "\n".join(tail), "error": "The upgrade failed: " + (tail[-1] if tail else f"exit {code}")}
    reboot = os.path.exists("/var/run/reboot-required")
    emit("info", "Updates installed" + ("; a reboot is required to finish" if reboot else ""))
    return {"exit_code": 0, "output": "\n".join(tail), "result": {"reboot_required": reboot}}


def reboot(args: dict[str, Any]) -> dict[str, Any]:
    """Reboot in a few seconds, so this job can report back first."""
    code = subprocess.run(
        ["systemd-run", "--on-active=10", "--unit=vpspilot-reboot", "--collect", "systemctl", "reboot"],
        capture_output=True,
        text=True,
        check=False,
    )
    if code.returncode != 0:
        return {"exit_code": code.returncode, "output": code.stderr[-300:], "error": "Couldn't schedule the reboot"}
    return {"exit_code": 0, "output": "Rebooting in 10 seconds"}


OPERATIONS = {"os.reboot": reboot}
STREAMING = {"os.upgrade": upgrade}
