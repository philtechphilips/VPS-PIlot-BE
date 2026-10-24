"""Docker Compose deployments, constrained to what's safe on a shared host.

The repository's compose file is resolved by `docker compose config`, checked
and rewritten, then run as project vp-<app>:

- refused: privileged mode, added capabilities, devices, host networking or
  namespaces, security options, bind mounts outside the release, external
  volumes/networks (other apps' data), volume driver options;
- dropped with a warning: published ports and fixed container names (they
  would collide with other apps); VPSPilot publishes one service itself;
- added: the app's variables on the public service, which also joins the
  private `vpspilot` network as vp-<app> (for domains and databases),
  log rotation, a restart policy and per-release image tags.

Each release keeps its source copy and resolved file in
/var/lib/vpspilot-apps/<app>/releases/<id>, so a rollback runs that release
again exactly as it ran (without rebuilding).
"""

from __future__ import annotations

import json
import os
import shutil
from typing import Any

from vpspilot_agent import deploy as d

COMPOSE_NAMES = (
    "compose.yaml",
    "compose.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
)
KEEP_RELEASES = 5
MAX_SERVICES = 20
UP_TIMEOUT = 10 * 60

REFUSED = {
    "privileged": "privileged mode",
    "cap_add": "added capabilities",
    "devices": "devices",
    "device_cgroup_rules": "device rules",
    "pid": "the host PID namespace",
    "ipc": "a shared IPC namespace",
    "uts": "the host UTS namespace",
    "userns_mode": "user namespace changes",
    "security_opt": "security options",
    "cgroup": "cgroup changes",
    "cgroup_parent": "cgroup changes",
    "sysctls": "sysctls",
    "runtime": "a custom runtime",
    "volumes_from": "volumes from other containers",
    "gpus": "GPUs",
}


def project(app: str) -> str:
    return f"vp-{app}"


def _compose(app: str, *args: str) -> list[str]:
    return ["docker", "compose", "-p", project(app), *args]


def _env() -> dict[str, str]:
    env = d._git_env()
    env.update(d._builder_env())
    return env


def available() -> bool:
    return d._run(["docker", "compose", "version"], timeout=15)[0] == 0


def _inside(base: str, path: str, what: str) -> None:
    real = os.path.realpath(path)
    base = os.path.realpath(base)
    if real != base and not real.startswith(base + os.sep):
        raise d.Failed(f"{what} ({path}) is outside the repository")


def _find_file(src: str, rel: str | None) -> str:
    if rel:
        path = d._inside(src, rel)
        if not os.path.isfile(path):
            raise d.Failed(f"No {rel} in the repository")
        return path
    for name in COMPOSE_NAMES:
        path = os.path.join(src, name)
        if os.path.isfile(path):
            return path
    raise d.Failed("No compose.yaml or docker-compose.yml in the repository")


def _check(config: dict[str, Any], src: str, emit: d.Emit) -> None:
    services = config.get("services")
    if not isinstance(services, dict) or not services:
        raise d.Failed("The compose file has no services")
    if len(services) > MAX_SERVICES:
        raise d.Failed(f"At most {MAX_SERVICES} services per app")
    for kind in ("volumes", "networks", "configs", "secrets"):
        for name, item in (config.get(kind) or {}).items():
            item = item or {}
            if item.get("external"):
                raise d.Failed(f"External {kind[:-1]} {name} isn't allowed")
            if item.get("driver_opts"):
                raise d.Failed(f"Driver options on {kind[:-1]} {name} aren't allowed")
            if kind == "networks" and item.get("driver") not in (None, "bridge"):
                raise d.Failed(f"Network {name} must use the bridge driver")
            if item.get("file"):
                _inside(src, item["file"], f"{kind[:-1].title()} {name}")
    for name, svc in services.items():
        for key, label in REFUSED.items():
            if svc.get(key):
                raise d.Failed(f"Service {name} uses {label}, which isn't allowed")
        mode = str(svc.get("network_mode") or "")
        if mode and not mode.startswith("service:"):
            raise d.Failed(
                f"Service {name} uses network_mode {mode}, which isn't allowed"
            )
        reservations = ((svc.get("deploy") or {}).get("resources") or {}).get(
            "reservations"
        ) or {}
        if reservations.get("devices"):
            raise d.Failed(f"Service {name} reserves devices, which isn't allowed")
        for volume in svc.get("volumes") or []:
            if not isinstance(volume, dict):
                continue
            if volume.get("type") == "bind":
                source = str(volume.get("source") or "")
                if "docker.sock" in source:
                    raise d.Failed(f"Service {name} mounts the Docker socket")
                _inside(src, source, f"A bind mount in {name}")
        build = svc.get("build")
        if isinstance(build, dict):
            _inside(
                src, str(build.get("context") or src), f"The build context of {name}"
            )
            if (
                build.get("network") == "host"
                or build.get("ssh")
                or build.get("privileged")
            ):
                raise d.Failed(f"The build of {name} uses host access")
            for extra in (build.get("additional_contexts") or {}).values():
                if not str(extra).startswith(("docker-image://", "service:")):
                    _inside(src, str(extra), f"A build context of {name}")


def _rewrite(
    config: dict[str, Any], spec: dict[str, Any], tag: str, public: str, emit: d.Emit
) -> dict[str, Any]:
    app = spec["app"]
    config["name"] = project(app)
    for name, svc in config["services"].items():
        if svc.pop("ports", None):
            emit(
                "warn",
                f"Ignoring ports published by {name}; VPSPilot publishes {public}",
            )
        if svc.pop("container_name", None):
            emit("warn", f"Ignoring container_name on {name}")
        svc.setdefault("restart", "unless-stopped")
        svc.setdefault(
            "logging",
            {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}},
        )
        labels = svc.get("labels") or {}
        if isinstance(labels, list):
            labels = dict(
                item.split("=", 1) if "=" in item else (item, "") for item in labels
            )
        labels.update(
            {"vpspilot.app": app, "vpspilot.deployment": spec["deployment_id"]}
        )
        svc["labels"] = labels
        if svc.get("build"):
            # One image per release, so rollbacks don't rebuild.
            svc["image"] = f"{d.IMAGE_PREFIX}/{app}.{name.lower()}:{tag}"
            svc["build"]["labels"] = {
                **(svc["build"].get("labels") or {}),
                "vpspilot.app": app,
                "vpspilot.deployment": spec["deployment_id"],
            }
            svc.pop("pull_policy", None)
    svc = config["services"][public]
    environment = svc.get("environment") or {}
    if isinstance(environment, list):
        environment = dict(
            item.split("=", 1) if "=" in item else (item, None) for item in environment
        )
    environment.update(spec["env"])
    svc["environment"] = environment
    svc["ports"] = [
        {
            "target": spec["container_port"],
            "published": str(spec["host_port"]),
            "host_ip": "127.0.0.1" if spec.get("private_port") else "0.0.0.0",
            "protocol": "tcp",
            "mode": "host",
        }
    ]
    networks = svc.get("networks")
    if not svc.get("network_mode"):
        if not isinstance(networks, dict) or not networks:
            networks = {"default": None}
        networks[d.NETWORK] = {"aliases": [f"vp-{app}"]}
        svc["networks"] = networks
        config.setdefault("networks", {})
        config["networks"].setdefault("default", {"name": f"{project(app)}_default"})
        config["networks"][d.NETWORK] = {"name": d.NETWORK, "external": True}
    return config


def _resolve(
    spec: dict[str, Any], src: str, release: str, emit: d.Emit, sha: str
) -> tuple[dict[str, Any], str]:
    """Copy the checkout into the release, resolve and check the file."""
    app = spec["app"]
    os.makedirs(release, mode=0o700)
    code_dir = os.path.join(release, "src")
    shutil.copytree(src, code_dir, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    context = d._inside(code_dir, spec["context"])
    path = _find_file(context, spec.get("compose_file"))
    emit("step", f"Reading {os.path.relpath(path, code_dir)}")
    env_file = os.path.join(release, "interpolate.env")
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        for key, value in spec["env"].items():
            handle.write(f"{key}={value}\n")
    try:
        code, out = d._run(
            [
                *_compose(
                    app, "-f", path, "--project-directory", os.path.dirname(path)
                ),
                "--env-file",
                env_file,
                "config",
                "--format",
                "json",
            ],
            timeout=60,
            env=_env(),
        )
    finally:
        os.unlink(env_file)
    if code != 0:
        raise d.Failed(f"The compose file is invalid: {out.strip()[-400:]}")
    try:
        config = json.loads(out[out.find("{") :])
    except ValueError:
        raise d.Failed(
            "Couldn't read the resolved compose file (Docker Compose 2.17+ is needed)"
        ) from None
    _check(config, code_dir, emit)
    services = list(config["services"])
    public = spec.get("compose_service") or (
        services[0] if len(services) == 1 else None
    )
    if public not in config["services"]:
        raise d.Failed(
            "Pick which service receives traffic (services: "
            + ", ".join(services)
            + ")"
            if public is None
            else f"There's no service {public} (services: {', '.join(services)})"
        )
    tag = f"{sha[:12]}-{spec['deployment_id'][:6]}"
    return _rewrite(config, spec, tag, public, emit), public


def _save(release: str, config: dict[str, Any], meta: dict[str, Any]) -> str:
    path = os.path.join(release, "compose.json")
    # It holds interpolated values (secrets too): root-only, like Docker's
    # own container config.
    for name, data in (("compose.json", config), ("release.json", meta)):
        fd = os.open(
            os.path.join(release, name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle)
    return path


def _up(app: str, path: str, emit: d.Emit) -> tuple[int, list[str]]:
    return d._stream(
        _compose(app, "-f", path, "up", "-d", "--no-build", "--remove-orphans"),
        emit,
        UP_TIMEOUT,
        env=_env(),
    )


def _container(app: str, service: str) -> str:
    return f"{project(app)}-{service}-1"


def _prune(app: str, releases: str, keep: str) -> None:
    try:
        entries = [
            os.path.join(releases, n)
            for n in os.listdir(releases)
            if d.HEX_RE.fullmatch(n)
        ]
    except OSError:
        return
    entries.sort(key=os.path.getmtime, reverse=True)
    for path in entries[KEEP_RELEASES:]:
        if os.path.basename(path) == keep:
            continue
        release_id = os.path.basename(path)
        code, out = d._run(
            [
                "docker",
                "image",
                "ls",
                "-q",
                "--filter",
                f"label=vpspilot.app={app}",
                "--filter",
                f"label=vpspilot.deployment={release_id}",
            ],
            timeout=30,
        )
        for image in set(out.split()) if code == 0 else ():
            d._run(["docker", "image", "rm", "-f", image], timeout=60)
        shutil.rmtree(path, ignore_errors=True)


def deploy(spec: dict[str, Any], emit: d.Emit, redact: d.Redactor) -> dict[str, Any]:
    app = spec["app"]
    if not available():
        raise d.Failed("The Docker Compose plugin isn't installed on this server")
    workdir = os.path.join(d.APPS_DIR, app)
    releases = os.path.join(workdir, "releases")
    os.makedirs(releases, mode=0o700, exist_ok=True)
    if d._run(["docker", "network", "inspect", d.NETWORK], timeout=15)[0] != 0:
        d._run(["docker", "network", "create", d.NETWORK], timeout=30)
    current_file = os.path.join(workdir, "current")
    previous = None
    if os.path.isfile(current_file):
        with open(current_file) as handle:
            previous = handle.read().strip() or None

    source = spec["source"]
    if source["type"] == "release":
        release_id = source["release"]
        release = os.path.join(releases, release_id)
        if not os.path.isfile(os.path.join(release, "compose.json")):
            raise d.Failed(
                f"That release is no longer on the server (only the last {KEEP_RELEASES} "
                "are kept). Deploy the commit again instead."
            )
        emit("step", f"Releasing {release_id[:8]} again")
    else:
        release_id = spec["deployment_id"]
        release = os.path.join(releases, release_id)
        shutil.rmtree(release, ignore_errors=True)
    try:
        return _release(
            spec, workdir, releases, release, release_id, previous, emit, redact
        )
    except BaseException:
        if source["type"] != "release":
            _discard(app, release)
        raise


def _discard(app: str, release: str) -> None:
    """Drop a release that never went live, with the images it built."""
    release_id = os.path.basename(release)
    code, out = d._run(
        [
            "docker",
            "image",
            "ls",
            "-q",
            "--filter",
            f"label=vpspilot.app={app}",
            "--filter",
            f"label=vpspilot.deployment={release_id}",
        ],
        timeout=30,
    )
    for image in set(out.split()) if code == 0 else ():
        d._run(["docker", "image", "rm", "-f", image], timeout=60)
    shutil.rmtree(release, ignore_errors=True)


def _release(
    spec: dict[str, Any],
    workdir: str,
    releases: str,
    release: str,
    release_id: str,
    previous: str | None,
    emit: d.Emit,
    redact: d.Redactor,
) -> dict[str, Any]:
    app = spec["app"]
    current_file = os.path.join(workdir, "current")
    if spec["source"]["type"] == "release":
        with open(os.path.join(release, "release.json")) as handle:
            meta = json.load(handle)
    else:
        sha, message = d._fetch(spec, workdir, emit)
        config, public = _resolve(
            spec, os.path.join(workdir, "src"), release, emit, sha
        )
        meta = {
            "commit_sha": sha,
            "commit_message": message,
            "public": public,
            "services": len(config["services"]),
        }
        path = _save(release, config, meta)
        if any(svc.get("build") for svc in config["services"].values()):
            emit("step", "Building images")
            code, _ = d._stream(
                _compose(app, "-f", path, "build"), emit, d.BUILD_TIMEOUT, env=_env()
            )
            if code != 0:
                raise d.Failed("The image build failed")
        if spec.get("release_command"):
            # A one-off container of the public service (its dependencies,
            # such as a database, are started for it).
            d.run_release_command(
                _compose(
                    app,
                    "-f",
                    path,
                    "run",
                    "--rm",
                    public,
                    "sh",
                    "-c",
                    spec["release_command"],
                ),
                lambda level, line: emit(level, redact(line)),
                env=_env(),
            )
    os.utime(release)
    path = os.path.join(release, "compose.json")
    public = meta["public"]

    emit("step", f"Starting {meta['services']} service(s)")
    code, tail = _up(app, path, lambda level, line: emit(level, redact(line)))
    ok = code == 0
    if ok:
        emit(
            "step",
            f"Health check {spec['health_path']} on {public} (up to {spec['health_timeout']}s)",
        )
        ok = d._healthy(
            _container(app, public),
            spec["host_port"],
            spec["health_path"],
            spec["health_timeout"],
            emit,
        )
        if not ok:
            d._container_logs(_container(app, public), emit, redact)
    if not ok:
        reason = (
            d._docker_error(redact("\n".join(tail)))
            if code != 0
            else ("The new version failed its health check.")
        )
        old = previous and os.path.join(releases, previous, "compose.json")
        if old and previous != release_id and os.path.isfile(old):
            emit("warn", "Restoring the previous release")
            _up(app, old, emit)
            raise d.Failed(f"{reason} The previous release was restored.")
        d._run(
            _compose(app, "down", "--remove-orphans"), timeout=UP_TIMEOUT, env=_env()
        )
        raise d.Failed(f"{reason} Nothing was released.")
    with open(current_file, "w") as handle:
        handle.write(release_id)
    _prune(app, releases, release_id)
    emit("step", f"Live on port {spec['host_port']}")
    return {
        "commit_sha": meta.get("commit_sha"),
        "commit_message": meta.get("commit_message"),
        "image_ref": f"release:{release_id}",
        "build_plan": f"Compose · {meta['services']} service(s)",
        "public_service": public,
    }


def remove(app: str, emit: d.Emit) -> None:
    code, out = d._run(
        [
            "docker",
            "ps",
            "-a",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={project(app)}",
        ],
        timeout=15,
    )
    if code != 0 or not out.strip():
        return
    d._run(_compose(app, "down", "--remove-orphans"), timeout=UP_TIMEOUT, env=_env())
    code, out = d._run(
        [
            "docker",
            "volume",
            "ls",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={project(app)}",
        ],
        timeout=15,
    )
    if code == 0 and out.split():
        emit(
            "warn",
            "Kept its volumes (they may hold data): "
            + ", ".join(out.split())
            + ". Remove them with docker volume rm when you no longer need them.",
        )
    code, out = d._run(
        ["docker", "image", "ls", "-q", "--filter", f"label=vpspilot.app={app}"],
        timeout=30,
    )
    for image in set(out.split()) if code == 0 else ():
        d._run(["docker", "image", "rm", "-f", image], timeout=60)
    emit("info", f"Removed the Compose project {project(app)}")
