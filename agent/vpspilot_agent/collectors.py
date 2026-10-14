"""Host facts, metrics and inventory. Read-only; needs no privileges."""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

import psutil

from vpspilot_agent import __version__


def _os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as handle:
            for line in handle:
                key, sep, value = line.strip().partition("=")
                if sep:
                    values[key] = value.strip('"')
    except OSError:
        pass
    return values


def _ip_addresses() -> list[str]:
    found: list[str] = []
    for name, addrs in psutil.net_if_addrs().items():
        if name == "lo" or name.startswith(("docker", "veth", "br-")):
            continue
        for addr in addrs:
            if addr.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            try:
                ip = ipaddress.ip_address(addr.address.split("%")[0])
            except ValueError:
                continue
            if ip.is_loopback or ip.is_link_local:
                continue
            found.append(str(ip))
    return found[:16]


def facts() -> dict[str, Any]:
    release = _os_release()
    return {
        "hostname": socket.gethostname(),
        "os_name": release.get("NAME", platform.system()),
        "os_version": release.get("VERSION", release.get("VERSION_ID", "")),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu_count": psutil.cpu_count() or 1,
        "memory_total": psutil.virtual_memory().total,
        "disk_total": psutil.disk_usage("/").total,
        "ip_addresses": _ip_addresses(),
        "agent_version": __version__,
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "capabilities": {
            "metrics": True,
            "systemd": shutil.which("systemctl") is not None,
            "docker": shutil.which("docker") is not None,
        },
    }


class MetricsSampler:
    """Produces one sample per call; network rates are averaged since the
    previous call, so the first sample reports 0 bytes/s."""

    def __init__(self) -> None:
        psutil.cpu_percent(interval=None)  # prime the CPU counter
        self._last_net = self._net_totals()
        self._last_time = time.monotonic()

    @staticmethod
    def _net_totals() -> tuple[int, int]:
        rx = tx = 0
        for name, counters in psutil.net_io_counters(pernic=True).items():
            if name == "lo":
                continue
            rx += counters.bytes_recv
            tx += counters.bytes_sent
        return rx, tx

    def sample(self) -> dict[str, Any]:
        now = time.monotonic()
        elapsed = max(now - self._last_time, 1e-6)
        rx, tx = self._net_totals()
        rx_bps = max(0, rx - self._last_net[0]) / elapsed
        tx_bps = max(0, tx - self._last_net[1]) / elapsed
        self._last_net, self._last_time = (rx, tx), now

        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        try:
            vfs = os.statvfs("/")
            inode_percent = (
                round(100 * (vfs.f_files - vfs.f_ffree) / vfs.f_files, 2)
                if vfs.f_files
                else None
            )
        except OSError:
            inode_percent = None
        load_1, load_5, load_15 = os.getloadavg()
        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "cpu_percent": round(psutil.cpu_percent(interval=None), 2),
            "memory_percent": round(memory.percent, 2),
            "memory_used": int(memory.total - memory.available),
            "swap_percent": round(psutil.swap_memory().percent, 2),
            "disk_percent": round(disk.percent, 2),
            "disk_used": int(disk.used),
            "inode_percent": inode_percent,
            "load_1": round(load_1, 2),
            "load_5": round(load_5, 2),
            "load_15": round(load_15, 2),
            "net_rx_bps": round(rx_bps, 1),
            "net_tx_bps": round(tx_bps, 1),
        }


def _run(cmd: list[str], timeout: float = 5) -> tuple[int, str]:
    try:
        done = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""
    return done.returncode, (done.stdout or done.stderr).strip()


def _services() -> list[dict[str, str]]:
    if shutil.which("systemctl") is None:
        return []
    code, out = _run(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--plain",
            "--no-pager",
        ]
    )
    if code != 0:
        return []
    services = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4 or parts[1] != "loaded":
            continue
        services.append(
            {
                "name": parts[0][:128],
                "active": parts[2][:64],
                "sub": parts[3][:64],
                "description": (parts[4] if len(parts) > 4 else "")[:255],
            }
        )
    return services[:500]


def _docker_ps() -> tuple[int, str]:
    """List containers through the privileged helper (the agent itself has no
    Docker access, which would be root-equivalent); fall back to the CLI."""
    if os.path.exists(HELPER_SOCKET):
        try:
            from vpspilot_agent import helper

            result = helper.call("docker.ps", {}, HELPER_SOCKET, timeout=20)
            return int(result.get("exit_code", 1)), result.get("output", "")
        except (OSError, ValueError):
            pass
    return _run(["docker", "ps", "-a", "--format", "{{json .}}"])


def _containers() -> tuple[bool, list[dict[str, str]]]:
    if shutil.which("docker") is None:
        return False, []
    code, out = _docker_ps()
    if code != 0:
        # No helper and no permission on the Docker socket.
        return False, []
    containers = []
    for line in out.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        containers.append(
            {
                "id": str(row.get("ID", ""))[:64],
                "name": str(row.get("Names", ""))[:128],
                "image": str(row.get("Image", ""))[:255],
                "state": str(row.get("State", ""))[:64],
                "status": str(row.get("Status", ""))[:128],
                "ports": str(row.get("Ports", ""))[:255],
            }
        )
    return True, containers[:200]


HELPER_SOCKET = "/run/vpspilot/helper.sock"

RUNTIMES = {
    "docker": ["docker", "--version"],
    "node": ["node", "--version"],
    "python": ["python3", "--version"],
    "pm2": ["pm2", "--version"],
    "nginx": ["nginx", "-v"],
    "caddy": ["caddy", "version"],
    "postgres": ["psql", "--version"],
    "mysql": ["mysql", "--version"],
    "redis": ["redis-server", "--version"],
}


def _runtimes() -> dict[str, str | None]:
    found: dict[str, str | None] = {}
    for name, cmd in RUNTIMES.items():
        if shutil.which(cmd[0]) is None:
            continue
        code, out = _run(cmd, timeout=3)
        first = out.splitlines()[0] if out else ""
        found[name] = first[:64] if first else None
    return found


def inventory() -> dict[str, Any]:
    docker_access, containers = _containers()
    return {
        "services": _services(),
        "containers": containers,
        "runtimes": _runtimes(),
        "docker_access": docker_access,
    }
