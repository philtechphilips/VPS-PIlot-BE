"""The reverse proxy for domains (run by the privileged helper).

VPSPilot runs one Caddy container per server, `vpspilot-proxy`, on the
private `vpspilot` network (so it reaches apps as vp-<app>:<port>) and on
ports 80/443. Caddy obtains and renews certificates by itself.

Applying is always: render the whole Caddyfile from the desired state ->
validate it with Caddy -> swap it in -> reload; if the reload fails, the
previous file is restored. Only VPSPilot's own config is ever touched.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import ssl
import subprocess
import time
from collections.abc import Callable
from typing import Any

from vpspilot_agent.errors import Rejected

CONTAINER = "vpspilot-proxy"
IMAGE = "caddy:2-alpine"
NETWORK = "vpspilot"
DIR = os.environ.get("VPSPILOT_PROXY_DIR", "/var/lib/vpspilot-proxy")
# Ports can be moved for tests on machines where 80/443 are taken.
HTTP_PORT, HTTPS_PORT = (
    int(p) for p in os.environ.get("VPSPILOT_PROXY_PORTS", "80,443").split(",")
)

HOST_RE = re.compile(
    r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
UPSTREAM_RE = re.compile(r"vp-[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?:\d{1,5}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}")

Emit = Callable[[str, str], None]


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        done = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return 124, f"Timed out after {timeout}s"
    except OSError as error:
        return 127, str(error)
    return done.returncode, (done.stdout + done.stderr).strip()


def _sites(args: dict[str, Any]) -> list[dict[str, Any]]:
    sites = args.get("sites")
    if not isinstance(sites, list) or len(sites) > 500:
        raise Rejected("invalid sites")
    clean = []
    seen = set()
    for site in sites:
        if not isinstance(site, dict):
            raise Rejected("invalid site")
        host = site.get("host")
        if not isinstance(host, str) or not HOST_RE.fullmatch(host) or host in seen:
            raise Rejected(f"invalid host {host!r}")
        seen.add(host)
        tls = site.get("tls")
        if tls not in ("auto", "internal", "off"):
            raise Rejected("invalid tls mode")
        if site.get("redirect_to") is not None:
            target = site["redirect_to"]
            if not isinstance(target, str) or not HOST_RE.fullmatch(target):
                raise Rejected("invalid redirect")
            clean.append({"host": host, "tls": tls, "redirect_to": target})
        else:
            upstream = site.get("upstream")
            if not isinstance(upstream, str) or not UPSTREAM_RE.fullmatch(upstream):
                raise Rejected("invalid upstream")
            clean.append({"host": host, "tls": tls, "upstream": upstream})
    return clean


def render(sites: list[dict[str, Any]], email: str | None) -> str:
    """The whole Caddyfile. Inputs are validated, so plain formatting is safe."""
    lines = ["# Managed by VPSPilot. Changes here are overwritten.", "{"]
    if email:
        lines.append(f"\temail {email}")
    if HTTP_PORT != 80 or HTTPS_PORT != 443:
        lines += [f"\thttp_port {HTTP_PORT}", f"\thttps_port {HTTPS_PORT}"]
    lines += ["}", ""]
    for site in sites:
        address = f"http://{site['host']}" if site["tls"] == "off" else site["host"]
        lines.append(f"{address} {{")
        if site["tls"] == "internal":
            lines.append("\ttls internal")
        if "redirect_to" in site:
            scheme = "http" if site["tls"] == "off" else "https"
            lines.append(f"\tredir {scheme}://{site['redirect_to']}{{uri}} permanent")
        else:
            lines.append("\tencode zstd gzip")
            lines.append(f"\treverse_proxy {site['upstream']}")
        lines += ["}", ""]
    return "\n".join(lines)


def _running() -> bool:
    code, out = _run(["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER], 15)
    return code == 0 and out.strip() == "true"


def _port_holder(port: int) -> str | None:
    """What holds a port, unless it's our own proxy."""
    code, out = _run(
        ["docker", "ps", "--filter", f"publish={port}", "--format", "{{.Names}}"], 15
    )
    names = [n for n in out.split() if n != CONTAINER] if code == 0 else []
    if names:
        return f"the container {names[0]}"
    if code == 0 and CONTAINER in out.split():
        return None
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("0.0.0.0", port))
    except OSError:
        return "another program (for example nginx or apache)"
    finally:
        probe.close()
    return None


def apply(args: dict[str, Any], emit: Emit) -> dict[str, Any]:
    sites = _sites(args)
    email = args.get("email")
    if email is not None and (
        not isinstance(email, str) or not EMAIL_RE.fullmatch(email)
    ):
        raise Rejected("invalid email")
    if shutil.which("docker") is None:
        return {
            "exit_code": 1,
            "output": "",
            "error": "Docker isn't installed on this server",
        }
    os.makedirs(DIR, mode=0o755, exist_ok=True)
    caddyfile = os.path.join(DIR, "Caddyfile")
    candidate = os.path.join(DIR, "Caddyfile.new")
    with open(candidate, "w") as handle:
        handle.write(render(sites, email))
    os.chmod(candidate, 0o644)

    if _run(["docker", "network", "inspect", NETWORK], 15)[0] != 0:
        _run(["docker", "network", "create", NETWORK], 30)
    running = _running()
    if not running:
        for port in (HTTP_PORT, HTTPS_PORT):
            holder = _port_holder(port)
            if holder:
                os.unlink(candidate)
                return {
                    "exit_code": 1,
                    "output": "",
                    "error": f"Port {port} is already used by {holder}. VPSPilot's proxy needs ports {HTTP_PORT} and {HTTPS_PORT}; stop that service or move its sites first.",
                }
        emit("step", f"Pulling {IMAGE}")
        code, out = _run(["docker", "pull", IMAGE], 300)
        if code != 0:
            return {
                "exit_code": 1,
                "output": out[-2000:],
                "error": f"Couldn't pull {IMAGE}",
            }

    emit("step", "Validating the proxy configuration")
    if running:
        check = [
            "docker",
            "exec",
            CONTAINER,
            "caddy",
            "validate",
            "--config",
            "/etc/caddy/Caddyfile.new",
            "--adapter",
            "caddyfile",
        ]
    else:
        check = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{DIR}:/etc/caddy:ro",
            IMAGE,
            "caddy",
            "validate",
            "--config",
            "/etc/caddy/Caddyfile.new",
            "--adapter",
            "caddyfile",
        ]
    code, out = _run(check, 60)
    if code != 0:
        os.unlink(candidate)
        lines = [
            ln for ln in out.splitlines() if "Error:" in ln or "error" in ln.lower()
        ]
        return {
            "exit_code": 1,
            "output": out[-4000:],
            "error": "The proxy configuration is invalid: "
            + (lines[-1] if lines else "caddy validate failed")[-300:],
        }

    previous = None
    if os.path.exists(caddyfile):
        with open(caddyfile) as handle:
            previous = handle.read()
    os.replace(candidate, caddyfile)

    if not running:
        emit("step", "Starting the proxy")
        _run(["docker", "rm", "-f", CONTAINER], 30)
        code, out = _run(
            [
                "docker", "run", "-d", "--name", CONTAINER,
                "--restart", "unless-stopped", "--network", NETWORK,
                "-p", f"{HTTP_PORT}:{HTTP_PORT}", "-p", f"{HTTPS_PORT}:{HTTPS_PORT}", "-p", f"{HTTPS_PORT}:{HTTPS_PORT}/udp",
                "-v", f"{DIR}:/etc/caddy:ro",
                "-v", "vpspilot-proxy-data:/data", "-v", "vpspilot-proxy-config:/config",
                "--label", "vpspilot.proxy=1",
                "--log-opt", "max-size=10m", "--log-opt", "max-file=3",
                IMAGE, "caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile",
            ],
            120,
        )  # fmt: skip
        if code != 0:
            return {
                "exit_code": 1,
                "output": out[-2000:],
                "error": "Couldn't start the proxy: " + out.splitlines()[-1][-300:]
                if out
                else "docker run failed",
            }
        time.sleep(2)
        if not _running():
            _, logs = _run(["docker", "logs", "--tail", "20", CONTAINER], 15)
            return {
                "exit_code": 1,
                "output": logs[-4000:],
                "error": "The proxy stopped right after starting",
            }
    else:
        emit("step", "Reloading the proxy")
        code, out = _run(
            [
                "docker",
                "exec",
                CONTAINER,
                "caddy",
                "reload",
                "--config",
                "/etc/caddy/Caddyfile",
                "--adapter",
                "caddyfile",
            ],
            60,
        )
        if code != 0:
            # Put the working config back.
            if previous is not None:
                with open(caddyfile, "w") as handle:
                    handle.write(previous)
                _run(
                    [
                        "docker",
                        "exec",
                        CONTAINER,
                        "caddy",
                        "reload",
                        "--config",
                        "/etc/caddy/Caddyfile",
                        "--adapter",
                        "caddyfile",
                    ],
                    60,
                )
            return {
                "exit_code": 1,
                "output": out[-4000:],
                "error": "The proxy rejected the new configuration; the previous one is back",
            }
    emit("step", f"Serving {len(sites)} site{'s' if len(sites) != 1 else ''}")
    return {"exit_code": 0, "output": ""}


def _certificate(host: str) -> dict[str, Any]:
    """What certificate the proxy presents for host (from the server itself)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as error:
        return {"host": host, "ok": False, "error": str(error)[:200]}
    if not der:
        return {"host": host, "ok": False, "error": "No certificate"}
    try:
        done = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-enddate", "-issuer", "-subject"],
            input=der, capture_output=True, timeout=10, check=False,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"host": host, "ok": False, "error": f"openssl unavailable: {error}"}
    info: dict[str, Any] = {"host": host, "ok": True}
    for line in done.stdout.decode(errors="replace").splitlines():
        key, _, value = line.partition("=")
        if key == "notAfter":
            info["not_after"] = value.strip()
        elif key == "issuer":
            match = re.search(r"O ?= ?([^,/]+)", value) or re.search(
                r"CN ?= ?([^,/]+)", value
            )
            info["issuer"] = (match.group(1) if match else value).strip()[:120]
        elif key == "subject":
            match = re.search(r"CN ?= ?([^,/]+)", value)
            info["subject"] = (match.group(1) if match else value).strip()[:200]
    return info


def status(args: dict[str, Any]) -> dict[str, Any]:
    hosts = args.get("hosts")
    if (
        not isinstance(hosts, list)
        or len(hosts) > 200
        or not all(isinstance(h, str) and HOST_RE.fullmatch(h) for h in hosts)
    ):
        raise Rejected("invalid hosts")
    import json

    body = {
        "running": _running(),
        "certificates": [_certificate(h) for h in hosts] if _running() else [],
    }
    return {"exit_code": 0, "output": json.dumps(body)}


OPERATIONS = {"proxy.status": status}
STREAMING = {"proxy.apply": apply}
