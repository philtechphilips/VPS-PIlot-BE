"""Build plans for repositories without a Dockerfile.

Looks at the checkout (package.json, requirements.txt, go.mod, ...) and
writes a Dockerfile for the stack it finds, so every app still goes through
the same build -> candidate -> health check -> release path.

Supported: Node.js (npm, pnpm, Yarn), Bun, Python (pip, Poetry, uv, Pipenv),
Go, Rust and static sites. Users can override the build and start commands.

Repository content is untrusted: files are read with size limits and only
inside the checkout, and anything copied from them into the Dockerfile is
matched against strict patterns. Commands go into JSON exec form
(["sh", "-c", "..."]), which Docker parses as JSON, never as raw text.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover - Ubuntu 22.04 ships 3.10
    tomllib = None  # type: ignore[assignment]

MAX_FILE = 1024 * 1024
NODE_DEFAULT = "22"
PYTHON_DEFAULT = "3.12"
GO_DEFAULT = "1.23"

SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
SAFE_MODULE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,200}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,100}$")

DOCKERIGNORE = (
    ".git\nnode_modules\n.venv\nvenv\n__pycache__\n*.pyc\ntarget\n.next/cache\n"
)


class Unsupported(Exception):
    """No plan could be made; the message tells the user what to do."""


@dataclass
class Plan:
    stack: str  # human label, e.g. "Next.js · pnpm · Node 22"
    dockerfile: str
    notes: list[str] = field(default_factory=list)
    # The same plan as shell steps, for native (systemd) releases.
    kind: str = ""  # node | bun | python | go | rust | static
    version: str = ""  # Node major or Python minor the project asks for
    manager: str = ""
    install: str | None = None
    build: str | None = None
    start: str = ""
    serve_static: bool = False


# ---------------------------------------------------------------------------
# Reading the checkout safely
# ---------------------------------------------------------------------------


class Repo:
    def __init__(self, root: str):
        self.root = os.path.realpath(root)

    def path(self, rel: str) -> str | None:
        path = os.path.realpath(os.path.join(self.root, rel))
        if path != self.root and not path.startswith(self.root + os.sep):
            return None  # a symlink pointing out of the checkout
        return path

    def exists(self, rel: str) -> bool:
        path = self.path(rel)
        return bool(path and os.path.exists(path))

    def isdir(self, rel: str) -> bool:
        path = self.path(rel)
        return bool(path and os.path.isdir(path))

    def read(self, rel: str) -> str | None:
        path = self.path(rel)
        if not path or not os.path.isfile(path) or os.path.getsize(path) > MAX_FILE:
            return None
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()

    def json(self, rel: str) -> dict | None:
        text = self.read(rel)
        try:
            data = json.loads(text) if text else None
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def toml(self, rel: str) -> dict | None:
        text = self.read(rel)
        if not text or tomllib is None:
            return None
        try:
            return tomllib.loads(text)
        except (ValueError, TypeError):
            return None

    def listdir(self, rel: str = ".") -> list[str]:
        path = self.path(rel)
        try:
            return sorted(os.listdir(path)) if path and os.path.isdir(path) else []
        except OSError:
            return []


# ---------------------------------------------------------------------------
# Dockerfile helpers
# ---------------------------------------------------------------------------


def _sh(command: str) -> str:
    """JSON exec form running a shell command (Docker parses this as JSON)."""
    return json.dumps(["sh", "-c", command])


def _args(build_args: list[str]) -> str:
    # Non-secret variables are available while building (e.g. NEXT_PUBLIC_*).
    return "".join(f"ARG {key}\n" for key in build_args)


def _version(raw: str | None, default: str, parts: int) -> str:
    """'>=18' -> default, '20.x' -> '20', 'v3.11.4' -> '3.11'."""
    if not raw:
        return default
    raw = raw.strip()
    if raw.startswith(">") or raw in ("*", "latest", "lts/*", "node"):
        return default
    match = re.search(r"\d+(?:\.\d+)*", raw)
    if not match:
        return default
    numbers = match.group(0).split(".")[:parts]
    return ".".join(numbers)


# ---------------------------------------------------------------------------
# Node.js and Bun
# ---------------------------------------------------------------------------


def _node_manager(repo: Repo, pkg: dict) -> str:
    declared = str(pkg.get("packageManager") or "")
    for name in ("bun", "pnpm", "yarn", "npm"):
        if declared.startswith(name + "@"):
            return name
    if repo.exists("bun.lockb") or repo.exists("bun.lock"):
        return "bun"
    if repo.exists("pnpm-lock.yaml"):
        return "pnpm"
    if repo.exists("yarn.lock"):
        return "yarn"
    return "npm"


def _node_framework(deps: dict) -> str | None:
    for dep, label in (
        ("next", "Next.js"),
        ("nuxt", "Nuxt"),
        ("@remix-run/node", "Remix"),
        ("@sveltejs/kit", "SvelteKit"),
        ("astro", "Astro"),
        ("@nestjs/core", "NestJS"),
        ("@angular/core", "Angular"),
        ("react-scripts", "Create React App"),
        ("vite", "Vite"),
        ("fastify", "Fastify"),
        ("hono", "Hono"),
        ("express", "Express"),
        ("koa", "Koa"),
    ):
        if dep in deps:
            return label
    return None


def _procfile_web(repo: Repo) -> str | None:
    text = repo.read("Procfile") or ""
    for line in text.splitlines():
        if line.startswith("web:"):
            command = line[4:].strip()
            return command if command and len(command) <= 500 else None
    return None


def _node(
    repo: Repo, build: str | None, start: str | None, build_args: list[str]
) -> Plan:
    pkg = repo.json("package.json")
    if pkg is None:
        raise Unsupported("package.json couldn't be read")
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    deps = {
        **(pkg.get("dependencies") or {}),
        **(pkg.get("devDependencies") or {}),
    }
    manager = _node_manager(repo, pkg)
    framework = _node_framework(deps)
    run = {"npm": "npm run", "pnpm": "pnpm run", "yarn": "yarn run", "bun": "bun run"}[
        manager
    ]

    if manager == "bun":
        base = "oven/bun:1"
        install = (
            "bun install --frozen-lockfile"
            if (repo.exists("bun.lockb") or repo.exists("bun.lock"))
            else "bun install"
        )
        version_label = "Bun"
    else:
        engines = pkg.get("engines") if isinstance(pkg.get("engines"), dict) else {}
        version = _version(
            str(
                engines.get("node")
                or repo.read(".nvmrc")
                or repo.read(".node-version")
                or ""
            ),
            NODE_DEFAULT,
            1,
        )
        if not version.isdigit() or int(version) < 18:
            version = NODE_DEFAULT
        base = f"node:{version}-bookworm-slim"
        version_label = f"Node {version}"
        install = {
            "npm": "npm ci"
            if repo.exists("package-lock.json") or repo.exists("npm-shrinkwrap.json")
            else "npm install",
            "pnpm": "pnpm install --frozen-lockfile"
            if repo.exists("pnpm-lock.yaml")
            else "pnpm install",
            "yarn": "yarn install --frozen-lockfile"
            if repo.exists("yarn.lock")
            else "yarn install",
        }[manager]
        if manager == "npm":
            install += " --include=dev"  # also overrides omit=dev in .npmrc

    # Builds need devDependencies (TypeScript, bundlers, husky for the
    # "prepare" script) even when the app's NODE_ENV is production, which
    # would make the package manager skip them. Git hooks are pointless here.
    install = f"HUSKY=0 NODE_ENV=development {install}"

    build_cmd = build or (f"{run} build" if "build" in scripts else None)

    serve_static = False
    if start:
        start_cmd = start
    elif _procfile_web(repo):
        start_cmd = _procfile_web(repo)
    elif "start" in scripts and framework not in (
        "Vite",
        "Create React App",
        "Astro",
        "Angular",
    ):
        start_cmd = f"{run} start"
    elif framework == "Nuxt":
        start_cmd = "node .output/server/index.mjs"
    elif framework == "SvelteKit":
        start_cmd = "node build"
    elif framework in ("Vite", "Create React App", "Astro", "Angular") and build_cmd:
        # A static build: serve the output directory.
        serve_static = True
        start_cmd = (
            'serve -s "$(for d in dist/*/browser dist build out; do [ -f "$d/index.html" ] && echo "$d" && break; done)"'
            ' -l "tcp://0.0.0.0:${PORT:-3000}"'
        )
    elif "start" in scripts:
        start_cmd = f"{run} start"
    else:
        main = pkg.get("main")
        if (
            isinstance(main, str)
            and SAFE_PATH.fullmatch(main)
            and ".." not in main
            and repo.exists(main)
        ):
            entry = main
        else:
            entry = next(
                (
                    f
                    for f in (
                        "server.js",
                        "index.js",
                        "app.js",
                        "main.js",
                        "server.mjs",
                        "index.mjs",
                    )
                    if repo.exists(f)
                ),
                None,
            )
        if entry is None:
            raise Unsupported(
                'Couldn\'t tell how to start this Node.js app: add a "start" script to package.json or set a start command.'
            )
        start_cmd = f"{'bun' if manager == 'bun' else 'node'} {entry}"

    lines = [
        f"FROM {base}",
        "WORKDIR /app",
        "ENV HOST=0.0.0.0 HOSTNAME=0.0.0.0 NEXT_TELEMETRY_DISABLED=1 NUXT_TELEMETRY_DISABLED=1",
    ]
    if manager in ("pnpm", "yarn"):
        lines.append("RUN corepack enable")
    if serve_static:
        lines.append(f"RUN {_sh('npm install -g serve@14')}")
    text = "\n".join(lines) + "\n" + _args(build_args)
    text += "COPY . .\n"
    text += f"RUN {_sh(install)}\n"
    if build_cmd:
        text += f"RUN {_sh(build_cmd)}\n"
    text += "ENV NODE_ENV=production\n"
    text += f"CMD {_sh(start_cmd)}\n"
    label = " · ".join(
        x
        for x in (framework, manager if manager != "bun" else None, version_label)
        if x
    )
    return Plan(
        stack=label,
        dockerfile=text,
        kind="bun" if manager == "bun" else "node",
        version=version_label.removeprefix("Node "),
        manager=manager,
        install=install,
        build=build_cmd,
        start=start_cmd,
        serve_static=serve_static,
    )


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def _py_object(repo: Repo, cls: str) -> tuple[str, str] | None:
    """Find `<var> = FastAPI(...)` / `Flask(...)`; returns (module, var)."""
    candidates = [
        "main.py", "app.py", "server.py", "api.py", "wsgi.py", "asgi.py",
        "app/main.py", "app/__init__.py", "app/app.py", "src/main.py", "src/app.py",
        "src/app/main.py", "api/main.py", "backend/main.py",
    ]  # fmt: skip
    pattern = re.compile(rf"^(\w+)\s*(?::\s*\w+\s*)?=\s*{cls}\(", re.MULTILINE)
    factory = re.compile(r"^def (create_app)\(", re.MULTILINE)
    for rel in candidates:
        text = repo.read(rel)
        if not text:
            continue
        module = rel[:-3].replace("/", ".")
        if module.endswith(".__init__"):
            module = module[: -len(".__init__")]
        match = pattern.search(text)
        if match and SAFE_MODULE.fullmatch(module):
            return module, match.group(1)
        if cls == "Flask" and factory.search(text) and SAFE_MODULE.fullmatch(module):
            return module, "create_app()"
    return None


def _django_wsgi(repo: Repo) -> str | None:
    for entry in repo.listdir("."):
        if repo.exists(f"{entry}/wsgi.py") and SAFE_MODULE.fullmatch(entry):
            return f"{entry}.wsgi"
    for parent in ("src", "app", "backend"):
        for entry in repo.listdir(parent):
            if repo.exists(f"{parent}/{entry}/wsgi.py") and SAFE_MODULE.fullmatch(
                entry
            ):
                return f"{parent}.{entry}.wsgi"
    return None


def _python(
    repo: Repo, build: str | None, start: str | None, build_args: list[str]
) -> Plan:
    pyproject = repo.toml("pyproject.toml") or {}
    manifest = " ".join(
        (repo.read(f) or "").lower()
        for f in (
            "requirements.txt",
            "pyproject.toml",
            "Pipfile",
            "setup.py",
            "setup.cfg",
        )
    )

    raw = (repo.read(".python-version") or "").strip() or (
        repo.read("runtime.txt") or ""
    ).strip()
    if not raw:
        raw = str((pyproject.get("project") or {}).get("requires-python") or "")
    version = _version(raw.replace("python-", ""), PYTHON_DEFAULT, 2)
    if not re.fullmatch(r"3\.(9|1[0-9])", version):
        version = PYTHON_DEFAULT

    venv = False
    if repo.exists("uv.lock"):
        manager, install, venv = (
            "uv",
            "pip install uv && uv sync --frozen --no-dev",
            True,
        )
    elif repo.exists("poetry.lock"):
        manager = "Poetry"
        install = "pip install poetry && poetry config virtualenvs.create false && poetry install --no-interaction --no-root --only main"
    elif repo.exists("requirements.txt"):
        manager, install = "pip", "pip install -r requirements.txt"
    elif repo.exists("Pipfile"):
        manager, install = (
            "Pipenv",
            "pip install pipenv && pipenv install --system --deploy",
        )
    elif repo.exists("pyproject.toml") or repo.exists("setup.py"):
        manager, install = "pip", "pip install ."
    else:
        manager, install = "pip", None

    def ensure(package: str) -> str:
        if package in manifest:
            return ""
        return f" && {'uv pip install --python .venv' if venv else 'pip install'} {package}"

    is_django = repo.exists("manage.py") and "django" in manifest
    framework = (
        "Django"
        if is_django
        else "FastAPI"
        if "fastapi" in manifest
        else "Flask"
        if "flask" in manifest
        else None
    )
    extra = ""
    if start:
        start_cmd = start
    elif _procfile_web(repo):
        start_cmd = _procfile_web(repo)
    elif is_django:
        wsgi = _django_wsgi(repo)
        if not wsgi:
            raise Unsupported("Found Django but no wsgi.py; set a start command.")
        start_cmd = f'gunicorn {wsgi}:application --bind "0.0.0.0:${{PORT:-8000}}"'
        extra = ensure("gunicorn")
    elif framework == "FastAPI":
        found = _py_object(repo, "FastAPI")
        if not found:
            raise Unsupported(
                "Found FastAPI but not the app object (looked for `app = FastAPI()` in main.py, app/main.py, ...); set a start command."
            )
        start_cmd = (
            f'uvicorn {found[0]}:{found[1]} --host 0.0.0.0 --port "${{PORT:-8000}}"'
        )
        extra = ensure("uvicorn")
    elif framework == "Flask":
        found = _py_object(repo, "Flask")
        if not found:
            raise Unsupported(
                "Found Flask but not the app object (looked for `app = Flask(__name__)`); set a start command."
            )
        target = (
            f'"{found[0]}:{found[1]}"'
            if found[1].endswith("()")
            else f"{found[0]}:{found[1]}"
        )
        start_cmd = f'gunicorn {target} --bind "0.0.0.0:${{PORT:-8000}}"'
        extra = ensure("gunicorn")
    else:
        entry = next(
            (f for f in ("main.py", "app.py", "server.py") if repo.exists(f)), None
        )
        if entry is None:
            raise Unsupported(
                "Couldn't tell how to start this Python app: add a Procfile (web: ...) or set a start command."
            )
        start_cmd = f"python {entry}"

    text = (
        f"FROM python:{version}-slim\n"
        "ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1\n"
        "WORKDIR /app\n" + _args(build_args) + "COPY . .\n"
    )
    if install or extra:
        text += f"RUN {_sh((install or 'true') + extra)}\n"
    if venv:
        text += "ENV PATH=/app/.venv/bin:$PATH\n"
    build_cmd = build
    if not build and is_django:
        # Like Heroku: collect static files at build time when configured.
        build_cmd = (
            'python manage.py collectstatic --noinput || echo "collectstatic skipped"'
        )
    if build_cmd:
        text += f"RUN {_sh(build_cmd)}\n"
    text += f"CMD {_sh(start_cmd)}\n"
    label = " · ".join(x for x in (framework, manager, f"Python {version}") if x)
    return Plan(
        stack=label,
        dockerfile=text,
        kind="python",
        version=version,
        manager=manager,
        install=((install or "true") + extra) if (install or extra) else None,
        build=build_cmd,
        start=start_cmd,
    )


# ---------------------------------------------------------------------------
# Go and Rust (compiled in one stage, run from a slim image)
# ---------------------------------------------------------------------------

RUNTIME_STAGE = (
    "FROM debian:bookworm-slim\n"
    "RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates "
    "&& rm -rf /var/lib/apt/lists/*\n"
    "WORKDIR /app\n"
)


def _go(
    repo: Repo, build: str | None, start: str | None, build_args: list[str]
) -> Plan:
    gomod = repo.read("go.mod") or ""
    match = re.search(r"^go\s+(\d+\.\d+)", gomod, re.MULTILINE)
    version = match.group(1) if match else GO_DEFAULT
    base = f"golang:{version}-bookworm"
    if build or start:
        # Custom commands: one stage with the toolchain available.
        text = f"FROM {base}\nWORKDIR /app\n{_args(build_args)}COPY . .\n"
        text += f"RUN {_sh(build or 'go build -o /usr/local/bin/app .')}\n"
        text += f"CMD {_sh(start or 'app')}\n"
        return Plan(stack=f"Go {version}", dockerfile=text, kind="go")

    def has_main(rel: str) -> bool:
        return any(
            f.endswith(".go")
            and re.search(
                r"^package main\b", repo.read(f"{rel}/{f}") or "", re.MULTILINE
            )
            for f in repo.listdir(rel)
        )

    if has_main("."):
        package = "."
    else:
        mains = [
            d
            for d in repo.listdir("cmd")
            if SAFE_NAME.fullmatch(d) and has_main(f"cmd/{d}")
        ]
        if len(mains) != 1:
            raise Unsupported(
                "Couldn't find a single main package (in the root or cmd/<name>); set a build and start command."
            )
        package = f"./cmd/{mains[0]}"
    text = (
        f"FROM {base} AS build\nWORKDIR /src\n{_args(build_args)}COPY . .\n"
        f"RUN {_sh(f'CGO_ENABLED=0 go build -trimpath -o /out/app {package}')}\n"
        + RUNTIME_STAGE
        # Keep the repo files (templates/, static/, ...) next to the binary.
        + "COPY --from=build /src /app\n"
        "COPY --from=build /out/app /usr/local/bin/app\n"
        'CMD ["app"]\n'
    )
    return Plan(stack=f"Go {version}", dockerfile=text, kind="go")


def _rust(
    repo: Repo, build: str | None, start: str | None, build_args: list[str]
) -> Plan:
    cargo = repo.toml("Cargo.toml") or {}
    name = str((cargo.get("package") or {}).get("name") or "")
    if not name:
        match = re.search(
            r'^\s*name\s*=\s*"([^"]+)"', repo.read("Cargo.toml") or "", re.MULTILINE
        )
        name = match.group(1) if match else ""
    if not SAFE_NAME.fullmatch(name):
        raise Unsupported(
            "Couldn't read the package name from Cargo.toml (workspaces need a Dockerfile)."
        )
    base = "rust:1-slim-bookworm"
    if build or start:
        text = f"FROM {base}\nWORKDIR /app\n{_args(build_args)}COPY . .\n"
        text += f"RUN {_sh(build or 'cargo build --release')}\n"
        text += f"CMD {_sh(start or f'./target/release/{name}')}\n"
        return Plan(stack="Rust", dockerfile=text, kind="rust")
    text = (
        f"FROM {base} AS build\nWORKDIR /src\n{_args(build_args)}COPY . .\n"
        f"RUN {_sh(f'cargo build --release && mkdir -p /out && cp target/release/{name} /out/app && rm -rf target')}\n"
        + RUNTIME_STAGE
        + "COPY --from=build /src /app\n"
        "COPY --from=build /out/app /usr/local/bin/app\n"
        'CMD ["app"]\n'
    )
    return Plan(stack="Rust", dockerfile=text, kind="rust")


# ---------------------------------------------------------------------------
# Static sites
# ---------------------------------------------------------------------------


def _static(
    repo: Repo, build: str | None, start: str | None, build_args: list[str]
) -> Plan:
    serve = 'httpd -f -v -p "${PORT:-8080}" -h /www'
    text = "FROM busybox:stable\nCOPY . /www\n"
    text += f"CMD {_sh(start or serve)}\n"
    return Plan(stack="Static site", dockerfile=text, kind="static")


# ---------------------------------------------------------------------------


def plan(
    root: str,
    build_command: str | None = None,
    start_command: str | None = None,
    build_args: list[str] | None = None,
) -> Plan:
    """Pick a stack for the checkout at `root` and write its Dockerfile."""
    repo = Repo(root)
    args = build_args or []
    if repo.exists("package.json"):
        return _node(repo, build_command, start_command, args)
    if any(
        repo.exists(f)
        for f in (
            "requirements.txt",
            "pyproject.toml",
            "Pipfile",
            "setup.py",
            "uv.lock",
            "poetry.lock",
        )
    ):
        return _python(repo, build_command, start_command, args)
    if repo.exists("go.mod"):
        return _go(repo, build_command, start_command, args)
    if repo.exists("Cargo.toml"):
        return _rust(repo, build_command, start_command, args)
    if repo.exists("index.html"):
        return _static(repo, build_command, start_command, args)
    if repo.exists("main.py") or repo.exists("app.py"):
        return _python(repo, build_command, start_command, args)
    found = ", ".join(repo.listdir(".")[:12]) or "nothing"
    raise Unsupported(
        "No Dockerfile, and this doesn't look like a Node.js, Bun, Python, Go, Rust or static "
        f"site project (found: {found}). Add a Dockerfile or deploy a container image."
    )


def write_dockerignore(root: str) -> None:
    """Keep .git and local dependencies out of the build context."""
    path = os.path.join(root, ".dockerignore")
    if not os.path.lexists(path):
        with open(path, "w") as handle:
            handle.write(DOCKERIGNORE)
