"""Security check and firewall (privileged helper).

The check is read-only. Fixes are a short fixed list: turn on ufw (SSH, 80
and 443 are allowed first, so nobody is locked out), add or remove a port
rule (never for SSH, 80 or 443), and turn on automatic security updates.
SSH settings are reported, not changed: the helper can't see home folders
(ProtectHome), so it can't tell whether you'd still have a key to log in.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
from typing import Any

from vpspilot_agent import deploy as d
from vpspilot_agent.errors import Rejected

DATABASE_PORTS = {
    5432: "PostgreSQL",
    3306: "MySQL/MariaDB",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
}
AUTO_UPGRADES = "/etc/apt/apt.conf.d/20auto-upgrades"
PORT_RE = re.compile(r"^\d{1,5}$")


def _sshd() -> dict[str, str]:
    if shutil.which("sshd") is None:
        return {}
    code, out = d._run(["sshd", "-T"], timeout=15)
    settings = {}
    for line in out.splitlines() if code == 0 else []:
        key, _, value = line.partition(" ")
        settings[key.lower()] = value.strip().lower()
    return settings


def ssh_ports() -> set[int]:
    ports = {int(p) for p in _sshd().get("port", "22").split() if p.isdigit()}
    return ports or {22}


def _ufw() -> dict[str, Any]:
    ufw = shutil.which("ufw")
    if ufw is None:
        return {"installed": False, "active": False, "rules": []}
    code, out = d._run([ufw, "status", "numbered"], timeout=15)
    rules = []
    for line in out.splitlines() if code == 0 else []:
        match = re.match(
            r"^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?: IN)?\s+(.+)$",
            line.strip(),
        )
        if match:
            rules.append(
                {
                    "number": int(match.group(1)),
                    "to": match.group(2).strip(),
                    "action": match.group(3),
                    "from": match.group(4).strip(),
                }
            )
    return {"installed": True, "active": "Status: active" in out, "rules": rules}


def _public_ports() -> list[dict[str, Any]]:
    """TCP ports listening on every address (reachable from outside unless
    a firewall says otherwise), with the program holding them."""
    code, out = d._run(["ss", "-ltnHp"], timeout=15)
    found: dict[int, str] = {}
    for line in out.splitlines() if code == 0 else []:
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        host, _, port = local.rpartition(":")
        if host not in ("0.0.0.0", "*", "[::]", "::") or not port.isdigit():
            continue
        program = re.search(r'users:\(\("([^"]+)"', line)
        found.setdefault(int(port), program.group(1) if program else "")
    return [{"port": p, "program": prog} for p, prog in sorted(found.items())]


def _docker_published() -> dict[int, str]:
    """Host ports Docker publishes on every address: ufw doesn't filter these."""
    if shutil.which("docker") is None:
        return {}
    code, out = d._run(
        ["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"], timeout=15
    )
    ports: dict[int, str] = {}
    for line in out.splitlines() if code == 0 else []:
        name, _, mapping = line.partition("\t")
        for match in re.finditer(r"(?:0\.0\.0\.0|\[::\]|::):(\d+)->", mapping):
            ports[int(match.group(1))] = name
    return ports


def check(args: dict[str, Any]) -> dict[str, Any]:
    sshd = _sshd()
    ufw = _ufw()
    public = _public_ports()
    docker = _docker_published()
    checks: list[dict[str, Any]] = []

    def add(
        key: str, status: str, title: str, detail: str, fix: str | None = None
    ) -> None:
        checks.append(
            {"id": key, "status": status, "title": title, "detail": detail, "fix": fix}
        )

    if sshd:
        password = sshd.get("passwordauthentication", "yes") == "yes"
        add("ssh_password", "warn" if password else "ok",
            "SSH password login " + ("is on" if password else "is off"),
            "Bots try passwords on every public server. With an SSH key set up, turn it off: set "
            "PasswordAuthentication no in /etc/ssh/sshd_config.d/99-hardening.conf, then sudo systemctl reload ssh."
            if password else "Only SSH keys can log in.")  # fmt: skip
        root = sshd.get("permitrootlogin", "yes")
        add("ssh_root", "warn" if root == "yes" else "ok",
            "Root can log in over SSH" + (" with a password" if root == "yes" else " with a key only" if root in ("prohibit-password", "without-password") else ": no"),
            "Set PermitRootLogin prohibit-password (keys only) or no, and log in as a normal user with sudo."
            if root == "yes" else "Fine.")  # fmt: skip
    if not ufw["installed"]:
        add(
            "firewall",
            "warn",
            "No firewall (ufw) installed",
            "Install it with sudo apt install ufw, then turn it on here.",
        )
    elif not ufw["active"]:
        add(
            "firewall",
            "bad",
            "The firewall (ufw) is off",
            "Every listening port is reachable from the internet.",
            "firewall_enable",
        )
    else:
        add("firewall", "ok", "The firewall (ufw) is on", f"{len(ufw['rules'])} rules.")
    exposed = []
    for entry in public:
        port = entry["port"]
        if port in docker:
            continue  # reported below: ufw doesn't apply
        if port in DATABASE_PORTS and not (ufw["active"] and not _allowed(ufw, port)):
            exposed.append(f"{DATABASE_PORTS[port]} on port {port}")
    if exposed:
        add("database_ports", "bad", "Databases reachable from the internet", ", ".join(exposed)
            + ". Close the port in the firewall below, or bind the database to 127.0.0.1.")  # fmt: skip
    docker_public = [
        f"{name} ({port})"
        for port, name in sorted(docker.items())
        if port not in (80, 443)
    ]
    if docker_public:
        add("docker_ports", "warn", "Container ports open to the internet",
            "Docker publishes these past the firewall: " + ", ".join(docker_public[:10])
            + ". For apps with a domain, turn on Private port in the app's settings and redeploy.")  # fmt: skip
    auto = (
        os.path.exists(AUTO_UPGRADES)
        and 'Unattended-Upgrade "1"' in open(AUTO_UPGRADES).read()
    )
    add("auto_updates", "ok" if auto else "warn",
        "Automatic security updates " + ("are on" if auto else "are off"),
        "unattended-upgrades installs security fixes daily." if auto else "Security fixes wait until someone installs them.",
        None if auto else "auto_updates")  # fmt: skip
    if os.path.exists("/var/run/reboot-required"):
        add(
            "reboot",
            "warn",
            "A reboot is needed",
            "Updates installed since the last boot (often the kernel) only apply after a reboot.",
        )
    body = {
        "checks": checks,
        "firewall": ufw,
        "ssh_ports": sorted(ssh_ports()),
        "public_ports": public,
        "docker_ports": [
            {"port": p, "container": n} for p, n in sorted(docker.items())
        ],
    }
    return {"exit_code": 0, "output": json.dumps(body), "result": body}


def _allowed(ufw: dict[str, Any], port: int) -> bool:
    return any(
        r["action"] in ("ALLOW", "LIMIT")
        and re.match(rf"^{port}(/tcp)?( \(v6\))?$", r["to"])
        for r in ufw["rules"]
    )


def _protected() -> set[int]:
    return ssh_ports() | {80, 443}


def firewall(args: dict[str, Any], emit) -> dict[str, Any]:
    ufw = shutil.which("ufw")
    if ufw is None:
        raise Rejected("ufw isn't installed")
    action = args.get("action")
    if action == "enable":
        for port in sorted(_protected()):
            emit("step", f"Allowing port {port}")
            d._run([ufw, "allow", f"{port}/tcp"], timeout=30)
        code, tail = d._stream([ufw, "--force", "enable"], emit, 60)
        if code != 0:
            return {
                "exit_code": code,
                "output": "",
                "error": "Couldn't turn the firewall on",
            }
        emit(
            "info",
            "Firewall on: SSH, 80 and 443 are open, everything else is closed unless allowed",
        )
        return {"exit_code": 0, "output": ""}
    port = args.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise Rejected("invalid port")
    proto = args.get("proto", "tcp")
    if proto not in ("tcp", "udp"):
        raise Rejected("invalid protocol")
    source = args.get("source")
    if source is not None:
        try:
            source = str(ipaddress.ip_network(source, strict=False))
        except (ValueError, TypeError):
            raise Rejected("invalid source address") from None
    if action == "allow":
        cmd = (
            [
                ufw,
                "allow",
                "from",
                source,
                "to",
                "any",
                "port",
                str(port),
                "proto",
                proto,
            ]
            if source
            else [ufw, "allow", f"{port}/{proto}"]
        )
    elif action == "remove":
        if port in _protected():
            raise Rejected(
                "SSH, 80 and 443 stay open: removing them could cut you or your sites off"
            )
        cmd = (
            [
                ufw,
                "delete",
                "allow",
                "from",
                source,
                "to",
                "any",
                "port",
                str(port),
                "proto",
                proto,
            ]
            if source
            else [ufw, "delete", "allow", f"{port}/{proto}"]
        )
    else:
        raise Rejected("invalid action")
    code, tail = d._stream(cmd, emit, 60)
    if code != 0:
        return {
            "exit_code": code,
            "output": "",
            "error": tail[-1] if tail else "ufw failed",
        }
    return {"exit_code": 0, "output": ""}


def auto_updates(args: dict[str, Any], emit) -> dict[str, Any]:
    """Install unattended-upgrades and turn on its daily run."""
    if shutil.which("unattended-upgrade") is None:
        emit("step", "Installing unattended-upgrades")
        code, tail = d._stream(
            ["apt-get", "install", "-y", "-q", "unattended-upgrades"],
            emit,
            600,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "DEBIAN_FRONTEND": "noninteractive",
            },
        )
        if code != 0:
            return {
                "exit_code": code,
                "output": "",
                "error": "Couldn't install unattended-upgrades",
            }
    with open(AUTO_UPGRADES, "w") as handle:
        handle.write(
            'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
        )
    emit("info", "Security updates now install automatically every day")
    return {"exit_code": 0, "output": ""}


OPERATIONS = {"security.check": check}
STREAMING = {"firewall.apply": firewall, "security.auto_updates": auto_updates}
