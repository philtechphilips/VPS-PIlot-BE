"""Docker deployments, run by the privileged helper (root).

One deployment: fetch the source (shallow Git checkout or image pull), build
an image tagged with the commit, start it as a *candidate* on a loopback
port, health-check it, and only then replace the live container. If the new
container fails after the swap, the previous one is put back.

Every input is validated again here, even though the control plane already
did: this module is the last line before root runs anything. Commands are
argument lists; nothing goes through a shell.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from vpspilot_agent.errors import Rejected

APPS_DIR = "/var/lib/vpspilot-apps"
IMAGE_PREFIX = "vpspilot"
KEEP_IMAGES = 5

APP_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")
HEX_RE = re.compile(r"^[0-9a-f]{32}$")
GIT_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._~/-]+$")
REF_RE = re.compile(r"^[A-Za-z0-9._/][A-Za-z0-9._/-]{0,199}$")
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/:@-]{0,299}$")
PATH_RE = re.compile(r"^[A-Za-z0-9._-][A-Za-z0-9._/-]{0,199}$")
HEALTH_RE = re.compile(r"^/[A-Za-z0-9._~/?=&%-]{0,199}$")
CPUS_RE = re.compile(r"^\d{1,2}(\.\d{1,2})?$")
MEMORY_RE = re.compile(r"^\d{1,6}[kmg]$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

GIT_TIMEOUT = 300
BUILD_TIMEOUT = 20 * 60
PULL_TIMEOUT = 10 * 60
DOCKER_TIMEOUT = 60
MAX_LINE = 1000
TAIL_LINES = 400

Emit = Callable[[str, str], None]


class Failed(Exception):
    pass


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _match(regex: re.Pattern[str], value: Any, what: str) -> str:
    if not isinstance(value, str) or not regex.match(value):
        raise Rejected(f"invalid {what}")
    if ".." in value and regex in (REF_RE, PATH_RE):
        raise Rejected(f"invalid {what}")
    return value


def _port(value: Any, low: int, what: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not low <= value <= 65535
    ):
        raise Rejected(f"invalid {what}")
    return value


def validate(args: dict[str, Any]) -> dict[str, Any]:
    source = args.get("source")
    if not isinstance(source, dict):
        raise Rejected("invalid source")
    if source.get("type") == "git":
        clean_source = {
            "type": "git",
            "url": _match(GIT_URL_RE, source.get("url"), "repository URL"),
            "ref": _match(REF_RE, source.get("ref"), "ref"),
        }
    elif source.get("type") == "image":
        clean_source = {
            "type": "image",
            "image": _match(IMAGE_RE, source.get("image"), "image"),
            "pull": bool(source.get("pull", True)),
        }
    else:
        raise Rejected("invalid source")
    env = args.get("env") or {}
    if not isinstance(env, dict) or len(env) > 101:
        raise Rejected("invalid env")
    for key, value in env.items():
        _match(ENV_KEY_RE, key, "variable name")
        if (
            not isinstance(value, str)
            or "\n" in value
            or "\r" in value
            or len(value) > 8192
        ):
            raise Rejected(f"invalid value for {key}")
    timeout = args.get("health_timeout", 60)
    if not isinstance(timeout, int) or not 5 <= timeout <= 600:
        raise Rejected("invalid health timeout")
    cpus, memory = args.get("cpus"), args.get("memory")
    return {
        "app": _match(APP_RE, args.get("app"), "app name"),
        "deployment_id": _match(HEX_RE, args.get("deployment_id"), "deployment id"),
        "source": clean_source,
        "dockerfile": _match(
            PATH_RE, args.get("dockerfile", "Dockerfile"), "Dockerfile path"
        ),
        "context": _match(PATH_RE, args.get("context", "."), "build context"),
        "container_port": _port(args.get("container_port"), 1, "container port"),
        "host_port": _port(args.get("host_port"), 1024, "host port"),
        "health_path": _match(HEALTH_RE, args.get("health_path", "/"), "health path"),
        "health_timeout": timeout,
        "cpus": _match(CPUS_RE, cpus, "CPU limit") if cpus is not None else None,
        "memory": _match(MEMORY_RE, memory, "memory limit")
        if memory is not None
        else None,
        "env": dict(env),
    }


# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------


class Redactor:
    """Masks env values so they never reach logs or the control plane."""

    def __init__(self, values: list[str]):
        self.values = sorted({v for v in values if len(v) >= 4}, key=len, reverse=True)

    def __call__(self, text: str) -> str:
        for value in self.values:
            text = text.replace(value, "••••••")
        return text


def _stream(
    cmd: list[str],
    emit: Emit,
    timeout: int,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> tuple[int, list[str]]:
    """Run a command, forwarding each output line. Returns (exit code, tail)."""
    tail: list[str] = []
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
    except OSError as error:
        emit("error", str(error))
        return 127, [str(error)]
    timer = threading.Timer(timeout, proc.kill)
    timer.start()
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip("\n")[:MAX_LINE]
            tail.append(line)
            del tail[:-TAIL_LINES]
            emit("output", line)
        code = proc.wait()
    finally:
        timer.cancel()
    if code < 0:
        emit("error", f"Timed out after {timeout}s")
        return 124, tail
    return code, tail


def _run(
    cmd: list[str], timeout: int = DOCKER_TIMEOUT, cwd: str | None = None, env=None
) -> tuple[int, str]:
    try:
        done = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
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
    return done.returncode, ((done.stdout or "") + (done.stderr or "")).strip()


def _git_env() -> dict[str, str]:
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        # Never wait for credentials: private repos fail fast instead.
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "GIT_CONFIG_NOSYSTEM": "1",
    }


def _inside(base: str, rel: str) -> str:
    """Resolve rel under base, refusing anything (incl. symlinks) that escapes."""
    base_real = os.path.realpath(base)
    path = os.path.realpath(os.path.join(base_real, rel))
    if path != base_real and not path.startswith(base_real + os.sep):
        raise Failed(f"{rel} points outside the repository")
    return path


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------


def _container_exists(name: str) -> bool:
    return _run(["docker", "container", "inspect", name], timeout=15)[0] == 0


def _running(name: str) -> bool:
    code, out = _run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name], timeout=15
    )
    return code == 0 and out.strip() == "true"


def _remove(name: str) -> None:
    _run(["docker", "rm", "-f", name], timeout=DOCKER_TIMEOUT)


def _run_args(
    spec: dict[str, Any], name: str, image: str, env_file: str, publish: str
) -> list[str]:
    cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "--env-file",
        env_file,
        "-p",
        publish,
        "--label",
        f"vpspilot.app={spec['app']}",
        "--label",
        f"vpspilot.deployment={spec['deployment_id']}",
        "--log-opt",
        "max-size=10m",
        "--log-opt",
        "max-file=3",
    ]
    if spec["cpus"]:
        cmd += ["--cpus", spec["cpus"]]
    if spec["memory"]:
        cmd += ["--memory", spec["memory"]]
    return [*cmd, image]


def _loopback_port(name: str, container_port: int) -> int | None:
    code, out = _run(["docker", "port", name, f"{container_port}/tcp"], timeout=15)
    if code != 0:
        return None
    for line in out.splitlines():
        host, _, port = line.strip().rpartition(":")
        if host in ("127.0.0.1", "0.0.0.0") and port.isdigit():
            return int(port)
    return None


def _healthy(name: str, port: int, path: str, timeout: int, emit: Emit) -> bool:
    url = f"http://127.0.0.1:{port}{path}"
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        if not _running(name):
            emit("error", "The container exited")
            return False
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                if response.status < 400:
                    emit(
                        "info",
                        f"Health check passed: {path} returned {response.status}",
                    )
                    return True
                last = f"HTTP {response.status}"
        except urllib.error.HTTPError as error:
            last = f"HTTP {error.code}"
            if error.code < 400:
                return True
        except (urllib.error.URLError, OSError) as error:
            last = str(getattr(error, "reason", error))
        time.sleep(2)
    emit("error", f"Health check failed after {timeout}s ({last or 'no response'})")
    return False


def _container_logs(name: str, emit: Emit, redact: Redactor) -> None:
    code, out = _run(["docker", "logs", "--tail", "40", name], timeout=15)
    if code == 0 and out:
        emit("warn", "Container logs:")
        for line in out.splitlines()[-40:]:
            emit("output", redact(line[:MAX_LINE]))


def _prune_images(app: str, keep_ref: str) -> None:
    code, out = _run(
        [
            "docker",
            "image",
            "ls",
            f"{IMAGE_PREFIX}/{app}",
            "--format",
            "{{.Repository}}:{{.Tag}}",
        ],
        timeout=30,
    )
    if code != 0:
        return
    # `docker image ls` lists newest first.
    refs = [r for r in out.splitlines() if r and not r.endswith(":<none>")]
    for ref in refs[KEEP_IMAGES:]:
        if ref != keep_ref:
            _run(["docker", "image", "rm", ref], timeout=60)


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


def _fetch(spec: dict[str, Any], workdir: str, emit: Emit) -> tuple[str, str]:
    source = spec["source"]
    src = os.path.join(workdir, "src")
    env = _git_env()
    if not os.path.isdir(os.path.join(src, ".git")):
        shutil.rmtree(src, ignore_errors=True)
        os.makedirs(src, mode=0o700)
        _run(["git", "init", "-q", src], env=env)
    git = [
        "git",
        "-C",
        src,
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
    ]
    _run([*git, "remote", "remove", "origin"], env=env)
    _run([*git, "remote", "add", "origin", source["url"]], env=env)
    emit("step", f"Fetching {source['ref']} from {source['url']}")
    code, tail = _stream(
        [*git, "fetch", "--depth", "1", "--no-tags", "origin", source["ref"]],
        emit,
        GIT_TIMEOUT,
        env=env,
    )
    if code != 0:
        raise Failed(f"Couldn't fetch {source['ref']}: {(tail or ['git failed'])[-1]}")
    for cmd in (["checkout", "-q", "--force", "FETCH_HEAD"], ["clean", "-q", "-ffdx"]):
        code, out = _run([*git, *cmd], env=env)
        if code != 0:
            raise Failed(out or "git checkout failed")
    code, out = _run([*git, "log", "-1", "--format=%H%n%s"], env=env)
    if code != 0:
        raise Failed("Couldn't read the commit")
    sha, _, message = out.partition("\n")
    emit("info", f"Checked out {sha[:12]} {message[:120]}")
    return sha.strip(), message.strip()


def _builder_env() -> dict[str, str]:
    # Distro docker packages often ship without buildx; fall back to the
    # classic builder rather than failing.
    if _run(["docker", "buildx", "version"], timeout=15)[0] == 0:
        return {"DOCKER_BUILDKIT": "1", "BUILDKIT_PROGRESS": "plain"}
    return {"DOCKER_BUILDKIT": "0"}


def _build(spec: dict[str, Any], workdir: str, sha: str, emit: Emit) -> str:
    src = os.path.join(workdir, "src")
    context = _inside(src, spec["context"])
    dockerfile = _inside(src, spec["dockerfile"])
    if not os.path.isfile(dockerfile):
        raise Failed(f"No {spec['dockerfile']} in the repository")
    image = f"{IMAGE_PREFIX}/{spec['app']}:{sha[:12]}"
    emit("step", f"Building {image}")
    code, tail = _stream(
        ["docker", "build", "-t", image, "-f", dockerfile, context],
        emit,
        BUILD_TIMEOUT,
        env={**_git_env(), **_builder_env()},
    )
    if code != 0:
        raise Failed("The image build failed")
    return image


def _pull(image: str, pull: bool, emit: Emit) -> None:
    if pull:
        emit("step", f"Pulling {image}")
        code, tail = _stream(["docker", "pull", image], emit, PULL_TIMEOUT)
        if code != 0:
            raise Failed(f"Couldn't pull {image}")
    elif _run(["docker", "image", "inspect", image], timeout=15)[0] != 0:
        raise Failed(f"{image} is no longer on the server")


def _write_env_file(workdir: str, deployment_id: str, env: dict[str, str]) -> str:
    path = os.path.join(workdir, f"env-{deployment_id}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        for key, value in env.items():
            handle.write(f"{key}={value}\n")
    return path


def deploy(args: dict[str, Any], emit: Emit) -> dict[str, Any]:
    """Run one deployment. Returns {"exit_code", "output", "result"}."""
    spec = validate(args)
    redact = Redactor(list(spec["env"].values()))

    def say(level: str, message: str) -> None:
        emit(level, redact(message))

    app = spec["app"]
    live = f"vp-{app}"
    candidate = f"vp-{app}-candidate"
    previous = f"vp-{app}-previous"
    workdir = os.path.join(APPS_DIR, app)
    os.makedirs(workdir, mode=0o700, exist_ok=True)
    os.chmod(APPS_DIR, 0o700)
    env_file = None
    sha = message = None
    try:
        if shutil.which("docker") is None:
            raise Failed("Docker isn't installed on this server")
        source = spec["source"]
        if source["type"] == "git":
            if shutil.which("git") is None:
                raise Failed("git isn't installed on this server")
            sha, message = _fetch(spec, workdir, say)
            image = _build(spec, workdir, sha, say)
        else:
            image = source["image"]
            _pull(image, source["pull"], say)

        env_file = _write_env_file(workdir, spec["deployment_id"], spec["env"])

        # 1. Candidate on a random loopback port: the live app is untouched.
        say("step", "Starting a candidate container")
        _remove(candidate)
        publish = f"127.0.0.1::{spec['container_port']}"
        code, out = _run(_run_args(spec, candidate, image, env_file, publish))
        if code != 0:
            raise Failed(f"Couldn't start the container: {redact(out)[-300:]}")
        port = _loopback_port(candidate, spec["container_port"])
        if port is None:
            _container_logs(candidate, say, redact)
            _remove(candidate)
            raise Failed("The container didn't start")
        say(
            "step",
            f"Health check {spec['health_path']} (up to {spec['health_timeout']}s)",
        )
        if not _healthy(
            candidate, port, spec["health_path"], spec["health_timeout"], say
        ):
            _container_logs(candidate, say, redact)
            _remove(candidate)
            raise Failed(
                "The new version failed its health check; the live version is unchanged"
            )
        _remove(candidate)

        # 2. Swap: keep the old container (stopped) until the new one is healthy.
        say("step", f"Releasing on port {spec['host_port']}")
        had_live = _container_exists(live)
        if had_live:
            _remove(previous)
            _run(["docker", "rename", live, previous])
            _run(["docker", "stop", "-t", "10", previous], timeout=30)
        publish = f"0.0.0.0:{spec['host_port']}:{spec['container_port']}"
        args_live = _run_args(spec, live, image, env_file, publish)
        args_live[2:2] = ["--restart", "unless-stopped"]
        code, out = _run(args_live)
        ok = code == 0 and _healthy(
            live,
            spec["host_port"],
            spec["health_path"],
            min(spec["health_timeout"], 60),
            say,
        )
        if not ok:
            if code != 0:
                say("error", redact(out)[-300:])
            _container_logs(live, say, redact)
            _remove(live)
            if had_live:
                say("warn", "Restoring the previous version")
                _run(["docker", "rename", previous, live])
                _run(["docker", "start", live])
            raise Failed(
                "The new version failed after release; the previous one was restored"
            )
        if had_live:
            _remove(previous)
        _prune_images(app, image)
        say("step", f"Live on port {spec['host_port']}")
        return {
            "exit_code": 0,
            "output": "",
            "result": {
                "commit_sha": sha,
                "commit_message": message,
                "image_ref": image,
            },
        }
    except Failed as error:
        say("error", str(error))
        return {
            "exit_code": 1,
            "output": "",
            "error": str(error),
            "result": {"commit_sha": sha, "commit_message": message},
        }
    finally:
        if env_file and os.path.exists(env_file):
            os.unlink(env_file)


def remove(args: dict[str, Any], emit: Emit) -> dict[str, Any]:
    app = _match(APP_RE, args.get("app"), "app name")
    if shutil.which("docker") is not None:
        code, out = _run(
            ["docker", "ps", "-a", "-q", "--filter", f"label=vpspilot.app={app}"],
            timeout=15,
        )
        for container in out.split() if code == 0 else []:
            _remove(container)
        for name in (f"vp-{app}", f"vp-{app}-candidate", f"vp-{app}-previous"):
            _remove(name)
        code, out = _run(
            [
                "docker",
                "image",
                "ls",
                f"{IMAGE_PREFIX}/{app}",
                "--format",
                "{{.Repository}}:{{.Tag}}",
            ],
            timeout=30,
        )
        for ref in out.split() if code == 0 else []:
            _run(["docker", "image", "rm", "-f", ref], timeout=60)
    shutil.rmtree(os.path.join(APPS_DIR, app), ignore_errors=True)
    emit("info", f"Removed {app}")
    return {"exit_code": 0, "output": f"Removed {app}"}


STREAMING: dict[str, Callable[[dict[str, Any], Emit], dict[str, Any]]] = {
    "app.deploy": deploy,
    "app.remove": remove,
}
