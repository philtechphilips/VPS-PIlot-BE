"""Native deployments: Node.js and Python apps run by systemd, no Docker.

Layout per app (under /srv/vpspilot/<app>):

    releases/<deployment id>/   one checkout + installed dependencies each
    meta/<deployment id>/       its start script and metadata (root-owned)
    current -> releases/<id>    what vp-<app>.service runs
    shared/                     survives releases (uploads, SQLite files, ...)
    home/                       the app user's HOME (npm/pip caches)

Each app runs as its own system user. Builds run as that user too, inside a
transient systemd unit with a timeout and the app's resource limits, so
repository scripts never run as root. A release is started as a candidate
on a spare port and health-checked before `current` is switched; if the
switched service then fails, `current` goes back to the previous release.

Apps must listen on $PORT (set by VPSPilot), like on Heroku or Render.
"""

from __future__ import annotations

import calendar
import hashlib
import json
import os
import platform
import pwd
import re
import shutil
import socket
import tarfile
import tempfile
import time
import urllib.request
from typing import Any

from vpspilot_agent import buildpacks
from vpspilot_agent import deploy as d

ROOT = "/srv/vpspilot"
UNIT_DIR = "/etc/systemd/system"
# Root-owned: /etc/vpspilot belongs to the (unprivileged) agent user.
ENV_DIR = "/etc/vpspilot-apps"
RUNTIMES = "/opt/vpspilot/runtimes"
KEEP_RELEASES = 5
NODE_DIST = "https://nodejs.org/dist"
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
HARDENING = [
    "NoNewPrivileges=yes",
    "PrivateTmp=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectControlGroups=yes",
    "ProtectKernelLogs=yes",
    "ProtectClock=yes",
    "ProtectHostname=yes",
    "ProtectProc=invisible",
    "PrivateDevices=yes",
    "RestrictSUIDSGID=yes",
    "RestrictNamespaces=yes",
    "RestrictRealtime=yes",
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
    "LockPersonality=yes",
    "SystemCallArchitectures=native",
    "CapabilityBoundingSet=",
    "UMask=0027",
]
EXCLUDE = {".git", "node_modules", ".venv", "venv", "__pycache__"}


def unit(app: str) -> str:
    return f"vp-{app}.service"


def user_for(app: str) -> str:
    """System user for an app (Linux user names are at most 32 chars)."""
    name = f"vp-{app}"
    if len(name) <= 32:
        return name
    digest = hashlib.sha256(app.encode()).hexdigest()[:6]
    return f"vp-{app[:22]}-{digest}"


def _paths(app: str) -> dict[str, str]:
    base = os.path.join(ROOT, app)
    return {
        "base": base,
        "releases": os.path.join(base, "releases"),
        "meta": os.path.join(base, "meta"),
        "current": os.path.join(base, "current"),
        "shared": os.path.join(base, "shared"),
        "home": os.path.join(base, "home"),
        "env": os.path.join(ENV_DIR, f"{app}.env"),
        "unit": os.path.join(UNIT_DIR, unit(app)),
    }


def _quote_env(value: str) -> str:
    # systemd EnvironmentFile: inside double quotes these four need a
    # backslash; nothing is expanded.
    return '"' + re.sub(r'(["\\`$])', r"\\\1", value) + '"'


def _write_env(path: str, values: dict[str, str]) -> None:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        for key, value in values.items():
            handle.write(f"{key}={_quote_env(value)}\n")
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Users, runtimes
# ---------------------------------------------------------------------------


def _ensure_user(user: str, home: str) -> tuple[int, int]:
    try:
        entry = pwd.getpwnam(user)
    except KeyError:
        code, out = d._run(
            [
                "useradd",
                "--system",
                "--user-group",
                "--home-dir",
                home,
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                user,
            ],
            timeout=30,
        )
        if code != 0:
            raise d.Failed(f"Couldn't create the user {user}: {out[:200]}") from None
        entry = pwd.getpwnam(user)
    return entry.pw_uid, entry.pw_gid


def _chown_tree(path: str, uid: int, gid: int) -> None:
    os.lchown(path, uid, gid)
    for parent, dirs, files in os.walk(path):
        for name in dirs + files:
            os.lchown(os.path.join(parent, name), uid, gid)


def _node_major(binary: str) -> int | None:
    code, out = d._run([binary, "--version"], timeout=15)
    match = re.match(r"v(\d+)\.", out.strip()) if code == 0 else None
    return int(match.group(1)) if match else None


def _node_bin(major: str, emit: d.Emit) -> str:
    """Directory holding node/npm for the major version the app asks for:
    the system's if it matches, else an official build from nodejs.org."""
    local = os.path.join(RUNTIMES, f"node-{major}", "bin")
    if os.path.isfile(os.path.join(local, "node")):
        return local
    system = shutil.which("node", path=SYSTEM_PATH)
    if (
        system
        and str(_node_major(system)) == major
        and shutil.which("npm", path=SYSTEM_PATH)
    ):
        return os.path.dirname(system)
    arch = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(
        platform.machine().lower()
    )
    if arch is None:
        raise d.Failed(f"No Node.js builds for {platform.machine()}")
    emit("step", f"Installing Node.js {major} (nodejs.org)")
    base = f"{NODE_DIST}/latest-v{major}.x"
    try:
        with urllib.request.urlopen(f"{base}/SHASUMS256.txt", timeout=30) as resp:
            sums = resp.read(200_000).decode()
    except OSError as error:
        raise d.Failed(f"Couldn't reach nodejs.org: {error}") from None
    match = re.search(
        rf"^([0-9a-f]{{64}})\s+(node-v{major}\.\d+\.\d+-linux-{arch}\.tar\.gz)$",
        sums,
        re.MULTILINE,
    )
    if not match:
        raise d.Failed(f"Node.js {major} isn't available for linux-{arch}")
    digest, filename = match.groups()
    os.makedirs(RUNTIMES, mode=0o755, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=RUNTIMES) as tmp:
        archive = os.path.join(tmp, filename)
        sha = hashlib.sha256()
        try:
            with (
                urllib.request.urlopen(f"{base}/{filename}", timeout=60) as resp,
                open(archive, "wb") as out,
            ):
                while chunk := resp.read(1 << 20):
                    sha.update(chunk)
                    out.write(chunk)
        except OSError as error:
            raise d.Failed(f"Couldn't download Node.js: {error}") from None
        if sha.hexdigest() != digest:
            raise d.Failed("The Node.js download didn't match its checksum")
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                name = os.path.normpath(member.name)
                if name.startswith(("/", "..")) or member.isdev():
                    raise d.Failed("Unexpected file in the Node.js archive")
            tar.extractall(tmp)  # noqa: S202 - checked above
        target = os.path.join(RUNTIMES, f"node-{major}")
        shutil.rmtree(target, ignore_errors=True)
        os.replace(os.path.join(tmp, filename[: -len(".tar.gz")]), target)
    emit("info", f"Node.js {match.group(2).split('-')[1]} installed in {target}")
    return local


def _python_bin(emit: d.Emit) -> str:
    python = shutil.which("python3", path=SYSTEM_PATH)
    if python and d._run([python, "-c", "import ensurepip, venv"], timeout=30)[0] == 0:
        return python
    if shutil.which("apt-get", path=SYSTEM_PATH) is None:
        raise d.Failed("Python 3 with venv isn't installed on this server")
    emit("step", "Installing Python 3 (apt: python3, python3-venv)")
    code, tail = d._stream(
        ["apt-get", "install", "-y", "-q", "python3", "python3-venv", "python3-pip"],
        emit,
        600,
        env={"PATH": SYSTEM_PATH, "DEBIAN_FRONTEND": "noninteractive"},
    )
    python = shutil.which("python3", path=SYSTEM_PATH)
    if code != 0 or not python:
        raise d.Failed("Couldn't install Python 3 with apt")
    return python


# ---------------------------------------------------------------------------
# systemd
# ---------------------------------------------------------------------------


def _limits(spec: dict[str, Any]) -> list[str]:
    props = []
    if spec["memory"]:
        props.append(f"MemoryMax={spec['memory'][:-1]}{spec['memory'][-1].upper()}")
    if spec["cpus"]:
        props.append(f"CPUQuota={round(float(spec['cpus']) * 100)}%")
    return props


def _active(name: str) -> bool:
    return d._run(["systemctl", "is-active", "--quiet", name], timeout=15)[0] == 0


def _journal(name: str, emit: d.Emit, redact: d.Redactor, lines: int = 40) -> None:
    code, out = d._run(
        ["journalctl", "-u", name, "-n", str(lines), "--no-pager", "-o", "cat"],
        timeout=15,
    )
    if code == 0 and out.strip() and "-- No entries --" not in out:
        emit("warn", "App output:")
        for line in out.splitlines()[-lines:]:
            emit("output", redact(line[: d.MAX_LINE]))


def _sandbox(user: str, paths: dict[str, str], spec: dict[str, Any]) -> list[str]:
    props = [*HARDENING, f"ReadWritePaths={paths['base']}", *_limits(spec)]
    cmd = [f"--uid={user}", f"--gid={user}"]
    for prop in props:
        cmd += ["-p", prop]
    return cmd


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _unit_port(path: str) -> int | None:
    try:
        with open(path) as handle:
            match = re.search(r"^# port (\d+)$", handle.read(), re.MULTILINE)
    except OSError:
        return None
    return int(match.group(1)) if match else None


def _check_port(spec: dict[str, Any], paths: dict[str, str], emit: d.Emit) -> None:
    port = spec["host_port"]
    code, out = d._run(
        ["docker", "ps", "--filter", f"publish={port}", "--format", "{{.Names}}"],
        timeout=15,
    )
    if code == 0 and out.split():
        raise d.Failed(
            f"Port {port} is already used by the container {out.split()[0]}. "
            "Pick another public port in the app's settings."
        )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("0.0.0.0", port))
        except OSError:
            if _unit_port(paths["unit"]) == port and _active(unit(spec["app"])):
                return  # the live release holds it; the restart frees it
            raise d.Failed(
                f"Port {port} is already in use on this server by another program. "
                "Pick another public port in the app's settings."
            ) from None
    emit("info", f"Port {port} is free")


def _write_unit(
    spec: dict[str, Any], user: str, paths: dict[str, str], release_id: str
) -> None:
    lines = [
        "# Managed by VPSPilot. Changes here are overwritten on deploy.",
        f"# port {spec['host_port']}",
        "[Unit]",
        f"Description=VPSPilot app {spec['app']}",
        "After=network-online.target",
        "Wants=network-online.target",
        "StartLimitIntervalSec=0",
        "",
        "[Service]",
        "Type=simple",
        f"User={user}",
        f"Group={user}",
        f"WorkingDirectory={paths['current']}",
        f"EnvironmentFile={paths['env']}",
        f"ExecStart=/bin/sh {paths['meta']}/{release_id}/start.sh",
        "Restart=always",
        "RestartSec=3",
        "TimeoutStopSec=20",
        "LimitNOFILE=65536",
        f"SyslogIdentifier=vp-{spec['app']}",
        f"ReadWritePaths={paths['base']}",
        *HARDENING,
        *_limits(spec),
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ]
    tmp = paths["unit"] + ".tmp"
    with open(tmp, "w") as handle:
        handle.write("\n".join(lines))
    os.chmod(tmp, 0o644)
    os.replace(tmp, paths["unit"])


def _point_current(paths: dict[str, str], release: str) -> None:
    tmp = paths["current"] + ".new"
    if os.path.lexists(tmp):
        os.unlink(tmp)
    os.symlink(release, tmp)
    os.replace(tmp, paths["current"])


def _allow_from_proxy(port: int, emit: d.Emit) -> None:
    """With ufw on, let the proxy container reach the app on the host."""
    ufw = shutil.which("ufw", path=SYSTEM_PATH)
    if not ufw or "Status: active" not in d._run([ufw, "status"], timeout=15)[1]:
        return
    code, out = d._run(
        ["docker", "network", "inspect", "-f", "{{.Id}}", d.NETWORK], timeout=15
    )
    if code != 0 or not re.fullmatch(r"[0-9a-f]{64}", out.strip()):
        return
    iface = f"br-{out.strip()[:12]}"
    d._run(
        [
            ufw,
            "allow",
            "in",
            "on",
            iface,
            "to",
            "any",
            "port",
            str(port),
            "proto",
            "tcp",
        ],
        timeout=30,
    )
    emit("info", f"Firewall: allowed the proxy to reach port {port}")


# ---------------------------------------------------------------------------
# Building a release
# ---------------------------------------------------------------------------


def _base_env(kind: str, release: str, home: str, tools: str) -> dict[str, str]:
    env = {
        "HOME": home,
        "LANG": "C.UTF-8",
        "HOST": "0.0.0.0",
        "HOSTNAME": "0.0.0.0",
    }
    if kind == "python":
        env.update(
            {
                "PATH": f"{release}/.venv/bin:{home}/.local/bin:{SYSTEM_PATH}",
                "VIRTUAL_ENV": f"{release}/.venv",
                "PYTHONUNBUFFERED": "1",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            }
        )
    else:
        env.update(
            {
                "PATH": f"{release}/node_modules/.bin:{home}/.local/bin:{tools}:{SYSTEM_PATH}",
                "NEXT_TELEMETRY_DISABLED": "1",
                "NUXT_TELEMETRY_DISABLED": "1",
                "npm_config_update_notifier": "false",
            }
        )
    return env


def _steps(plan: buildpacks.Plan, python: str) -> list[tuple[str, str]]:
    steps: list[tuple[str, str]] = []
    if plan.kind == "python":
        steps.append(("Creating a virtualenv", f"{python} -m venv .venv"))
        if plan.install:
            steps.append(("Installing dependencies", plan.install))
    else:
        if plan.manager in ("pnpm", "yarn"):
            steps.append(
                (
                    f"Enabling {plan.manager}",
                    'corepack enable --install-directory "$HOME/.local/bin" 2>/dev/null'
                    f' || npm install -g --prefix "$HOME/.local" {plan.manager}',
                )
            )
        if plan.serve_static:
            steps.append(
                ("Installing serve", 'npm install -g --prefix "$HOME/.local" serve@14')
            )
        if plan.install:
            steps.append(("Installing dependencies", plan.install))
    if plan.build:
        steps.append(("Building", plan.build))
    return steps


def _run_step(
    title: str,
    command: str,
    user: str,
    paths: dict[str, str],
    release: str,
    env_file: str,
    spec: dict[str, Any],
    emit: d.Emit,
) -> None:
    emit("step", title)
    # Root-owned and outside the release, which the build itself can write.
    script = os.path.join(paths["meta"], f"step-{spec['deployment_id']}.sh")
    with open(script, "w") as handle:
        handle.write(f"set -e\n{command}\n")
    os.chmod(script, 0o644)
    code, tail = d._stream(
        [
            "systemd-run",
            "--quiet",
            "--pipe",
            "--wait",
            "--collect",
            f"--unit=vp-{spec['app']}-build",
            *_sandbox(user, paths, spec),
            "-p",
            f"WorkingDirectory={release}",
            "-p",
            f"EnvironmentFile={env_file}",
            "-p",
            f"RuntimeMaxSec={d.BUILD_TIMEOUT}",
            "/bin/sh",
            script,
        ],
        emit,
        d.BUILD_TIMEOUT + 30,
        env={"PATH": SYSTEM_PATH},
    )
    os.unlink(script)
    if code != 0:
        raise d.Failed(f"{title} failed (exit {code})")


def _copy_source(src: str, release: str) -> None:
    def ignore(_dir: str, names: list[str]) -> set[str]:
        return {n for n in names if n in EXCLUDE}

    shutil.copytree(src, release, symlinks=True, ignore=ignore)


def _build_release(
    spec: dict[str, Any],
    paths: dict[str, str],
    user: str,
    uid: int,
    gid: int,
    emit: d.Emit,
) -> tuple[str, dict[str, Any]]:
    workdir = os.path.join(d.APPS_DIR, spec["app"])
    sha, message = d._fetch(spec, workdir, emit)
    context = d._inside(os.path.join(workdir, "src"), spec["context"])
    build_args = [
        k for k in spec["env"] if k not in spec["secret_keys"] and k != "PORT"
    ]
    try:
        plan = buildpacks.plan(
            context, spec["build_command"], spec["start_command"], build_args
        )
    except buildpacks.Unsupported as error:
        raise d.Failed(str(error)) from None
    if plan.kind not in ("node", "python"):
        raise d.Failed(
            f"Detected {plan.stack}: the systemd runtime runs Node.js and Python apps. "
            "Use the Docker runtime for this one."
        )
    emit("step", f"Detected {plan.stack}")
    python = tools = ""
    if plan.kind == "python":
        python = _python_bin(emit)
        code, out = d._run([python, "--version"], timeout=15)
        have = ".".join(out.split()[-1].split(".")[:2]) if code == 0 else "?"
        if have != plan.version:
            emit(
                "warn",
                f"The project asks for Python {plan.version}; this server has {have}",
            )
    else:
        tools = _node_bin(plan.version, emit)

    release = os.path.join(paths["releases"], spec["deployment_id"])
    shutil.rmtree(release, ignore_errors=True)
    _copy_source(context, release)
    _chown_tree(release, uid, gid)
    os.chmod(release, 0o750)

    env = {**_base_env(plan.kind, release, paths["home"], tools)}
    env.update({k: spec["env"][k] for k in build_args})
    build_env = os.path.join(workdir, f"build-{spec['deployment_id']}.env")
    _write_env(build_env, env)
    try:
        for title, command in _steps(plan, python):
            _run_step(title, command, user, paths, release, build_env, spec, emit)
    finally:
        os.unlink(build_env)

    meta = {
        "kind": plan.kind,
        "stack": plan.stack,
        "commit_sha": sha,
        "commit_message": message,
        "tools": tools,
        "start": plan.start,
    }
    _seal(paths, spec["deployment_id"], meta)
    return release, meta


def _seal(paths: dict[str, str], release_id: str, meta: dict[str, Any]) -> None:
    """Start script and metadata, root-owned, readable by the app user."""
    folder = os.path.join(paths["meta"], release_id)
    os.makedirs(folder, mode=0o755, exist_ok=True)
    for name, content in (
        ("start.sh", f"{meta['start']}\n"),
        ("release.json", json.dumps(meta)),
    ):
        path = os.path.join(folder, name)
        with open(path, "w") as handle:
            handle.write(content)
        os.chmod(path, 0o644)


def _load_release(paths: dict[str, str], release_id: str) -> tuple[str, dict[str, Any]]:
    release = os.path.join(paths["releases"], release_id)
    try:
        with open(os.path.join(paths["meta"], release_id, "release.json")) as handle:
            meta = json.load(handle)
        if not os.path.isdir(release):
            raise OSError
    except (OSError, ValueError):
        raise d.Failed(
            "That release is no longer on the server (only the last "
            f"{KEEP_RELEASES} are kept). Deploy the commit again instead."
        ) from None
    return release, meta


def _prune(paths: dict[str, str], keep: set[str]) -> None:
    try:
        entries = [
            os.path.join(paths["releases"], name)
            for name in os.listdir(paths["releases"])
            if d.HEX_RE.fullmatch(name)
        ]
    except OSError:
        return
    entries.sort(key=os.path.getmtime, reverse=True)
    for path in entries[KEEP_RELEASES:]:
        if os.path.realpath(path) not in keep:
            shutil.rmtree(path, ignore_errors=True)
            shutil.rmtree(
                os.path.join(paths["meta"], os.path.basename(path)), ignore_errors=True
            )


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


def deploy(spec: dict[str, Any], emit: d.Emit, redact: d.Redactor) -> dict[str, Any]:
    app = spec["app"]
    paths = _paths(app)
    for tool in ("systemctl", "systemd-run", "journalctl"):
        if shutil.which(tool, path=SYSTEM_PATH) is None:
            raise d.Failed("This server doesn't run systemd")
    _check_port(spec, paths, emit)
    user = user_for(app)
    os.makedirs(ROOT, mode=0o755, exist_ok=True)
    for key in ("base", "releases", "meta"):
        os.makedirs(paths[key], mode=0o755, exist_ok=True)
    uid, gid = _ensure_user(user, paths["home"])
    for key in ("home", "shared"):
        os.makedirs(paths[key], mode=0o750, exist_ok=True)
        os.chown(paths[key], uid, gid)
    os.makedirs(os.path.join(d.APPS_DIR, app), mode=0o700, exist_ok=True)

    source = spec["source"]
    release_id = spec["deployment_id"]
    if source["type"] == "release":
        release_id = source["release"]
        release, meta = _load_release(paths, release_id)
        emit(
            "step", f"Releasing {meta.get('stack')} from {source['release'][:8]} again"
        )
    else:
        try:
            release, meta = _build_release(spec, paths, user, uid, gid, emit)
        except BaseException:
            _discard(paths, release_id)
            raise
    os.utime(release)  # newest for pruning
    try:
        return _release(spec, paths, user, release, release_id, meta, emit, redact)
    except BaseException:
        if source["type"] != "release":
            _discard(paths, release_id)
        raise


def _discard(paths: dict[str, str], release_id: str) -> None:
    """Drop a release that never went live."""
    if os.path.realpath(paths["current"]) == os.path.join(
        paths["releases"], release_id
    ):
        return
    shutil.rmtree(os.path.join(paths["releases"], release_id), ignore_errors=True)
    shutil.rmtree(os.path.join(paths["meta"], release_id), ignore_errors=True)


def _release(
    spec: dict[str, Any],
    paths: dict[str, str],
    user: str,
    release: str,
    release_id: str,
    meta: dict[str, Any],
    emit: d.Emit,
    redact: d.Redactor,
) -> dict[str, Any]:
    app = spec["app"]
    name = unit(app)
    candidate = f"vp-{app}-candidate.service"

    runtime_env = _base_env(meta["kind"], release, paths["home"], meta.get("tools", ""))
    if meta["kind"] == "node":
        runtime_env["NODE_ENV"] = "production"
    runtime_env["VPSPILOT_SHARED_DIR"] = paths["shared"]
    runtime_env.update({k: v for k, v in spec["env"].items() if k != "PORT"})

    # 1. Candidate on a spare port; the live release keeps serving.
    emit("step", "Starting a candidate")
    d._run(["systemctl", "stop", candidate], timeout=30)
    d._run(["systemctl", "reset-failed", candidate], timeout=15)
    port = _free_port()
    cand_env = os.path.join(d.APPS_DIR, app, f"candidate-{spec['deployment_id']}.env")
    _write_env(cand_env, {**runtime_env, "PORT": str(port)})
    try:
        code, out = d._run(
            [
                "systemd-run",
                "--quiet",
                "--collect",
                f"--unit={candidate}",
                *_sandbox(user, paths, spec),
                "-p",
                f"WorkingDirectory={release}",
                "-p",
                f"EnvironmentFile={cand_env}",
                "-p",
                f"SyslogIdentifier=vp-{app}",
                "/bin/sh",
                os.path.join(paths["meta"], release_id, "start.sh"),
            ],
            timeout=30,
            env={"PATH": SYSTEM_PATH},
        )
        if code != 0:
            raise d.Failed(f"Couldn't start the app: {out[:300]}")
        emit(
            "step",
            f"Health check {spec['health_path']} (up to {spec['health_timeout']}s)",
        )
        healthy = d._healthy(
            candidate,
            port,
            spec["health_path"],
            spec["health_timeout"],
            emit,
            alive=lambda: _active(candidate),
            what="The app",
        )
        if not healthy:
            _journal(candidate, emit, redact)
            raise d.Failed(
                "The new version failed its health check (see above: it must listen on "
                "$PORT and answer the health check path with a 2xx or 3xx); "
                "the live version is unchanged"
            )
    finally:
        d._run(["systemctl", "stop", candidate], timeout=30)
        d._run(["systemctl", "reset-failed", candidate], timeout=15)
        os.unlink(cand_env)

    # 2. Switch `current` and restart; put the old release back on failure.
    emit("step", f"Releasing on port {spec['host_port']}")
    previous = (
        os.path.realpath(paths["current"]) if os.path.islink(paths["current"]) else None
    )
    old_env = paths["env"] + ".previous"
    if os.path.exists(paths["env"]):
        shutil.copy2(paths["env"], old_env)
    old_unit = paths["unit"] + ".previous"
    if os.path.exists(paths["unit"]):
        shutil.copy2(paths["unit"], old_unit)
    _write_env(paths["env"], {**runtime_env, "PORT": str(spec["host_port"])})
    _point_current(paths, release)
    _write_unit(spec, user, paths, release_id)
    d._run(["systemctl", "daemon-reload"], timeout=60)
    d._run(["systemctl", "enable", name], timeout=30)
    code, out = d._run(["systemctl", "restart", name], timeout=60)
    ok = code == 0 and d._healthy(
        name,
        spec["host_port"],
        spec["health_path"],
        min(spec["health_timeout"], 60),
        emit,
        alive=lambda: _active(name),
        what="The app",
    )
    if not ok:
        _journal(name, emit, redact)
        if previous and os.path.isdir(previous) and previous != release:
            emit("warn", "Restoring the previous release")
            _point_current(paths, previous)
            if os.path.exists(old_env):
                os.replace(old_env, paths["env"])
            if os.path.exists(old_unit):
                os.replace(old_unit, paths["unit"])
            d._run(["systemctl", "daemon-reload"], timeout=60)
            d._run(["systemctl", "restart", name], timeout=60)
            raise d.Failed(
                "The new version failed after release. The previous release was restored."
            )
        d._run(["systemctl", "disable", "--now", name], timeout=60)
        raise d.Failed("The new version failed after release. Nothing was released.")
    for path in (old_env, old_unit):
        if os.path.exists(path):
            os.unlink(path)
    _allow_from_proxy(spec["host_port"], emit)
    _prune(paths, {release})
    emit("step", f"Live on port {spec['host_port']}")
    return {
        "commit_sha": meta.get("commit_sha"),
        "commit_message": meta.get("commit_message"),
        "image_ref": f"release:{release_id}",
        "build_plan": f"{meta.get('stack')} · systemd",
    }


def remove(app: str, emit: d.Emit) -> None:
    paths = _paths(app)
    if not os.path.exists(paths["unit"]) and not os.path.isdir(paths["base"]):
        return
    if shutil.which("systemctl", path=SYSTEM_PATH):
        for name in (
            unit(app),
            f"vp-{app}-candidate.service",
            f"vp-{app}-build.service",
        ):
            d._run(["systemctl", "disable", "--now", name], timeout=60)
    for path in (paths["unit"], paths["env"]):
        if os.path.exists(path):
            os.unlink(path)
    d._run(["systemctl", "daemon-reload"], timeout=60)
    shutil.rmtree(paths["base"], ignore_errors=True)
    user = user_for(app)
    try:
        pwd.getpwnam(user)
        d._run(["userdel", user], timeout=30)
    except KeyError:
        pass
    emit("info", f"Removed the systemd service and releases of {app}")


def status(app: str) -> tuple[str, str | None, int]:
    """(state, started_at RFC 3339, restarts) like the Docker reader."""
    code, out = d._run(
        [
            "systemctl",
            "show",
            unit(app),
            "-p",
            "LoadState",
            "-p",
            "ActiveState",
            "-p",
            "NRestarts",
            "-p",
            "ExecMainStartTimestamp",
        ],
        timeout=15,
        env={"PATH": SYSTEM_PATH, "TZ": "UTC", "LC_ALL": "C"},
    )
    props = (
        dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        if code == 0
        else {}
    )
    if props.get("LoadState") != "loaded":
        return "missing", None, 0
    state = {
        "active": "running",
        "activating": "restarting",
        "reloading": "running",
        "deactivating": "exited",
    }.get(props.get("ActiveState", ""), "exited")
    started = None
    stamp = props.get("ExecMainStartTimestamp", "")
    try:
        started = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.strptime(stamp, "%a %Y-%m-%d %H:%M:%S UTC")
        )
    except ValueError:
        pass
    restarts = props.get("NRestarts", "0")
    return state, started, int(restarts) if restarts.isdigit() else 0


def logs(app: str, lines: int, since: str | None) -> list[dict[str, str]]:
    cmd = [
        "journalctl",
        "-u",
        unit(app),
        "-o",
        "json",
        "--no-pager",
        "-n",
        str(lines),
        "--output-fields=MESSAGE,PRIORITY",
    ]
    since_us = None
    if since:
        head, _, frac = since.rstrip("Z").partition(".")
        epoch = calendar.timegm(time.strptime(head, "%Y-%m-%dT%H:%M:%S"))
        since_us = int(epoch) * 1_000_000 + int((frac or "0").ljust(6, "0")[:6])
        cmd += ["--since", f"@{since_us // 1_000_000}"]
    code, out = d._run(cmd, timeout=30, env={"PATH": SYSTEM_PATH})
    entries = []
    for line in out.splitlines() if code == 0 else []:
        try:
            row = json.loads(line)
            stamp = int(row["__REALTIME_TIMESTAMP"])
        except (ValueError, KeyError, TypeError):
            continue
        if since_us is not None and stamp <= since_us:
            continue
        message = row.get("MESSAGE")
        if isinstance(message, list):  # non-UTF-8 output comes as bytes
            message = bytes(b for b in message if isinstance(b, int)).decode(
                "utf-8", "replace"
            )
        seconds, micros = divmod(stamp, 1_000_000)
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds))
        entries.append(
            {
                "t": f"{ts}.{micros:06d}Z",
                "s": "err"
                if str(row.get("PRIORITY", "6")) in ("0", "1", "2", "3")
                else "out",
                "m": str(message or "")[: d.MAX_LOG_LINE],
            }
        )
    return entries[-lines:]
