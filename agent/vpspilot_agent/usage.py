"""Per-app CPU and memory, disk usage and safe cleanup (privileged helper).

Apps are found the same way as for error scanning: containers named
vp-<app>, Compose projects vp-<app> (summed over their services) and
systemd units vp-<app>.service (from their cgroup counters).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from typing import Any

from vpspilot_agent import deploy as d
from vpspilot_agent.errors import Rejected

SIZE_RE = re.compile(r"^([\d.]+)\s*([kKMGTP]?i?B)$")
UNITS = {"B": 1, "kB": 1e3, "KB": 1e3, "KiB": 1024, "MB": 1e6, "MiB": 1024**2,
         "GB": 1e9, "GiB": 1024**3, "TB": 1e12, "TiB": 1024**4}  # fmt: skip
SKIP_SUFFIXES = ("-candidate", "-build", "-release")
_cpu_seen: dict[str, tuple[float, int]] = {}  # systemd unit: (time, CPU ns)


def _bytes(text: str) -> int:
    match = SIZE_RE.match(text.strip())
    if not match:
        return 0
    return int(float(match.group(1)) * UNITS.get(match.group(2), 1))


def _app_of(name: str, project: str) -> str | None:
    if project.startswith("vp-"):
        app = project[3:]
    elif name.startswith("vp-") and not project:
        app = name[3:]
    else:
        return None
    if not d.APP_RE.match(app) or app.endswith(SKIP_SUFFIXES):
        return None
    return app


def apps_usage(args: dict[str, Any]) -> dict[str, Any]:
    """{"rows": [{"app", "cpu_percent", "memory_bytes"}]} for running apps."""
    usage: dict[str, dict[str, float]] = {}
    if shutil.which("docker"):
        code, labels = d._run(
            [
                "docker",
                "ps",
                "--format",
                '{{.Names}}\t{{.Label "com.docker.compose.project"}}',
            ],
            timeout=15,
        )
        projects = (
            dict(line.split("\t", 1) for line in labels.splitlines() if "\t" in line)
            if code == 0
            else {}
        )
        code, out = d._run(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}"], timeout=30
        )
        for line in out.splitlines() if code == 0 else []:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            app = _app_of(row.get("Name", ""), projects.get(row.get("Name", ""), ""))
            if app is None:
                continue
            entry = usage.setdefault(app, {"cpu_percent": 0.0, "memory_bytes": 0})
            entry["cpu_percent"] += float(str(row.get("CPUPerc", "0")).rstrip("%") or 0)
            entry["memory_bytes"] += _bytes(
                str(row.get("MemUsage", "0B")).split("/")[0]
            )
    if shutil.which("systemctl"):
        code, out = d._run(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=running",
                "--no-legend",
                "--plain",
                "vp-*.service",
            ],
            timeout=15,
        )
        units = (
            [line.split(" ", 1)[0] for line in out.splitlines()] if code == 0 else []
        )
        for unit in units:
            app = unit.removeprefix("vp-").removesuffix(".service")
            if not d.APP_RE.match(app) or app.endswith(SKIP_SUFFIXES):
                continue
            code, props = d._run(
                [
                    "systemctl",
                    "show",
                    unit,
                    "-p",
                    "MemoryCurrent",
                    "-p",
                    "CPUUsageNSec",
                ],
                timeout=15,
            )
            values = (
                dict(p.split("=", 1) for p in props.splitlines() if "=" in p)
                if code == 0
                else {}
            )
            now = time.monotonic()
            try:
                cpu_ns = int(values.get("CPUUsageNSec", ""))
            except ValueError:
                cpu_ns = None
            cpu = 0.0
            if cpu_ns is not None:
                seen = _cpu_seen.get(unit)
                if seen and now > seen[0]:
                    cpu = max(0.0, (cpu_ns - seen[1]) / 1e9 / (now - seen[0]) * 100)
                _cpu_seen[unit] = (now, cpu_ns)
            memory = values.get("MemoryCurrent", "")
            usage[app] = {
                "cpu_percent": cpu,
                "memory_bytes": int(memory) if memory.isdigit() else 0,
            }
    rows = [
        {
            "app": app,
            "cpu_percent": round(v["cpu_percent"], 2),
            "memory_bytes": int(v["memory_bytes"]),
        }
        for app, v in usage.items()
    ]
    return {"exit_code": 0, "output": json.dumps({"rows": rows[:500]})}


def _du(path: str) -> int:
    if not os.path.exists(path):
        return 0
    code, out = d._run(["du", "-sb", path], timeout=120)
    try:
        return int(out.split()[0]) if code == 0 else 0
    except (ValueError, IndexError):
        return 0


def disk_usage(args: dict[str, Any]) -> dict[str, Any]:
    """Where the disk went, and what a cleanup could free."""
    total, used, free = shutil.disk_usage("/")
    parts: list[dict[str, Any]] = []
    if shutil.which("docker"):
        code, out = d._run(
            ["docker", "system", "df", "--format", "{{json .}}"], timeout=120
        )
        for line in out.splitlines() if code == 0 else []:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            reclaimable = _bytes(str(row.get("Reclaimable", "0B")).split(" ")[0])
            parts.append(
                {
                    "name": {"Images": "Docker images", "Containers": "Containers",
                             "Local Volumes": "Volumes (app and database data)",
                             "Build Cache": "Docker build cache"}.get(row.get("Type"), row.get("Type")),
                    "bytes": _bytes(str(row.get("Size", "0B"))),
                    "reclaimable": reclaimable if row.get("Type") in ("Build Cache",) else 0,
                }
            )  # fmt: skip
    for name, path in (
        ("Backups on this server", "/var/lib/vpspilot-backups"),
        ("App checkouts and releases", "/var/lib/vpspilot-apps"),
        ("Native app releases", "/srv/vpspilot"),
        ("apt package cache", "/var/cache/apt/archives"),
    ):
        size = _du(path)
        if size:
            parts.append(
                {
                    "name": name,
                    "bytes": size,
                    "reclaimable": size if "apt" in name else 0,
                }
            )
    code, out = d._run(["journalctl", "--disk-usage"], timeout=30)
    match = re.search(r"take up ([\d.]+\s*[KMGT]?)\b", out) if code == 0 else None
    if match:
        text = match.group(1).strip()
        size = _bytes(text + ("iB" if text[-1] in "KMGT" else "B"))
        parts.append(
            {
                "name": "System logs (journal)",
                "bytes": size,
                "reclaimable": max(0, size - 200 * 1024**2),
            }
        )
    code, out = (
        d._run(["docker", "images", "-f", "dangling=true", "-q"], timeout=30)
        if shutil.which("docker")
        else (1, "")
    )
    dangling = len(out.split()) if code == 0 else 0
    body = {
        "total": total,
        "used": used,
        "free": free,
        "parts": parts,
        "dangling_images": dangling,
    }
    return {"exit_code": 0, "output": json.dumps(body), "result": body}


CLEANUPS = {
    "build_cache": (["docker", "builder", "prune", "-f"], "Docker build cache"),
    "dangling_images": (["docker", "image", "prune", "-f"], "Untagged images"),
    "journal": (["journalctl", "--vacuum-size=200M"], "System logs over 200 MB"),
    "apt_cache": (["apt-get", "clean"], "apt package cache"),
}


def disk_cleanup(args: dict[str, Any], emit) -> dict[str, Any]:
    """Remove only what nothing needs: never containers, volumes or the
    images kept for rollbacks."""
    targets = args.get("targets")
    if (
        not isinstance(targets, list)
        or not targets
        or any(t not in CLEANUPS for t in targets)
    ):
        raise Rejected("invalid cleanup targets")
    before = shutil.disk_usage("/").used
    for target in targets:
        cmd, label = CLEANUPS[target]
        if shutil.which(cmd[0]) is None:
            continue
        emit("step", f"Cleaning: {label}")
        code, tail = d._stream(cmd, emit, 600)
        if code != 0:
            emit("warn", f"{label}: {tail[-1] if tail else f'exit {code}'}")
    freed = max(0, before - shutil.disk_usage("/").used)
    emit("info", f"Freed {freed // (1024 * 1024)} MB")
    return {
        "exit_code": 0,
        "output": json.dumps({"freed": freed}),
        "result": {"freed": freed},
    }


OPERATIONS = {"apps.usage": apps_usage, "disk.usage": disk_usage}
STREAMING = {"disk.cleanup": disk_cleanup}
