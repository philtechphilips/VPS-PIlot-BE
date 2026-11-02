"""What an app is made of, for vulnerability checks (privileged helper).

For each app this reads:
- the packages pinned in its lockfiles (npm, pnpm, Yarn, Bun, pip, uv,
  Poetry, Pipenv, Go, Cargo, Composer, Bundler), from the git checkout the
  last deploy built;
- the OS packages inside its running container (Debian, Ubuntu, Alpine);
- files committed to the repository that look like secrets.

Only names and versions leave the server; the control plane looks them up
in OSV.dev. The secret scan reports a file, a line and the kind of secret,
never the value.

Repository content is untrusted: files are read with size limits, only
inside the checkout (symlinks out of it are refused), and parsed with
regular expressions, never executed or imported.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import tarfile
from typing import Any

from vpspilot_agent import deploy as d
from vpspilot_agent.errors import Rejected

MAX_APPS = 200
MAX_LOCKFILE = 64 * 1024 * 1024
MAX_PACKAGES = 20000
MAX_OS_PACKAGES = 5000
MAX_SCAN_FILES = 5000
MAX_SCAN_FILE = 1024 * 1024
MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_SECRETS = 50
SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "vendor", "dist", "build", ".next",
    "target", "__pycache__", ".turbo", ".nuxt", ".output", "coverage",
}  # fmt: skip
NAME_RE = re.compile(r"^[@A-Za-z0-9][A-Za-z0-9@._/+~-]{0,213}$")
VERSION_RE = re.compile(r"^v?\d[0-9A-Za-z.+~:_-]{0,79}$")

# Lockfile name -> ecosystem, as OSV names them.
LOCKFILES = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "pnpm-lock.yaml": "npm",
    "yarn.lock": "npm",
    "bun.lock": "npm",
    "uv.lock": "PyPI",
    "poetry.lock": "PyPI",
    "Pipfile.lock": "PyPI",
    "requirements.txt": "PyPI",
    "go.mod": "Go",
    "Cargo.lock": "crates.io",
    "composer.lock": "Packagist",
    "Gemfile.lock": "RubyGems",
}


def _ok(name: str, version: str) -> bool:
    return bool(NAME_RE.match(name) and VERSION_RE.match(version))


# ---------------------------------------------------------------------------
# Lockfiles
# ---------------------------------------------------------------------------


def _npm_lock(text: str) -> list[tuple[str, str]]:
    data = json.loads(text)
    out: list[tuple[str, str]] = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2 and v3
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict) or entry.get("link"):
                continue
            name = entry.get("name") or key.rsplit("node_modules/", 1)[-1]
            out.append((str(name), str(entry.get("version") or "")))
        return out

    def walk(deps: Any, depth: int = 0) -> None:  # lockfile v1
        if not isinstance(deps, dict) or depth > 50:
            return
        for name, entry in deps.items():
            if isinstance(entry, dict):
                out.append((str(name), str(entry.get("version") or "")))
                walk(entry.get("dependencies"), depth + 1)

    walk(data.get("dependencies"))
    return out


def _pnpm_lock(text: str) -> list[tuple[str, str]]:
    match = re.search(r"""^lockfileVersion:\s*['"]?(\d+)""", text, re.MULTILINE)
    slash = bool(match and int(match.group(1)) < 6)  # v5: /name/1.2.3
    out = []
    inside = False
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line.startswith(" "):
            inside = line.rstrip() == "packages:"
            continue
        if not inside or not line.startswith("  ") or line.startswith("   "):
            continue
        key = line.strip().rstrip(":").strip("'\"").lstrip("/")
        key = key.split("(", 1)[0]  # peer dependency suffix
        if slash:
            name, _, version = key.rpartition("/")
            version = version.split("_", 1)[0]
        else:
            name, _, version = key.rpartition("@")
        out.append((name, version))
    return out


YARN_ENTRY = re.compile(r'^"?((?:@[^@"/\s]+/)?[^@"\s,]+)@', re.MULTILINE)


def _yarn_lock(text: str) -> list[tuple[str, str]]:
    out = []
    for block in re.split(r"\n\s*\n", text):
        lines = block.strip().splitlines()
        if not lines or lines[0].startswith("#") or lines[0].startswith("__metadata"):
            continue
        name = YARN_ENTRY.match(lines[0])
        version = re.search(r'^\s+version:?\s+"?([^"\s]+)"?', block, re.MULTILINE)
        if name and version:
            out.append((name.group(1), version.group(1)))
    return out


def _bun_lock(text: str) -> list[tuple[str, str]]:
    return [
        (m.group(1), m.group(2))
        for m in re.finditer(r'"((?:@[^@"/]+/)?[^@"/]+)@(\d[^"]*)"', text)
    ]


TOML_PACKAGE = re.compile(
    r'^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"',
    re.MULTILINE,
)


def _toml_packages(text: str) -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in TOML_PACKAGE.finditer(text)]


def _cargo_lock(text: str) -> list[tuple[str, str]]:
    out = []
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        version = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        registry = re.search(r'^source\s*=\s*"registry\+', block, re.MULTILINE)
        if name and version and registry:  # path and git crates aren't published
            out.append((name.group(1), version.group(1)))
    return out


def _pipfile_lock(text: str) -> list[tuple[str, str]]:
    data = json.loads(text)
    out = []
    for section in ("default", "develop"):
        for name, entry in (data.get(section) or {}).items():
            version = str((entry or {}).get("version") or "")
            if version.startswith("=="):
                out.append((name, version[2:]))
    return out


REQUIREMENT = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)"
)


def _requirements(text: str) -> list[tuple[str, str]]:
    return [
        (m.group(1), m.group(2)) for m in map(REQUIREMENT.match, text.splitlines()) if m
    ]


def _go_mod(text: str) -> list[tuple[str, str]]:
    out = []
    for m in re.finditer(
        r"^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}/\S+)\s+(v\d\S*)",
        text,
        re.MULTILINE,
    ):
        out.append((m.group(1), m.group(2)))
    return out


def _composer_lock(text: str) -> list[tuple[str, str]]:
    data = json.loads(text)
    return [
        (str(p.get("name") or ""), str(p.get("version") or "").lstrip("v"))
        for section in ("packages", "packages-dev")
        for p in (data.get(section) or [])
        if isinstance(p, dict)
    ]


def _gemfile_lock(text: str) -> list[tuple[str, str]]:
    return [
        (m.group(1), m.group(2))
        for m in re.finditer(
            r"^ {4}([A-Za-z0-9._-]+) \(([^)\s]+)\)$", text, re.MULTILINE
        )
    ]


PARSERS = {
    "package-lock.json": _npm_lock,
    "npm-shrinkwrap.json": _npm_lock,
    "pnpm-lock.yaml": _pnpm_lock,
    "yarn.lock": _yarn_lock,
    "bun.lock": _bun_lock,
    "uv.lock": _toml_packages,
    "poetry.lock": _toml_packages,
    "Pipfile.lock": _pipfile_lock,
    "requirements.txt": _requirements,
    "go.mod": _go_mod,
    "Cargo.lock": _cargo_lock,
    "composer.lock": _composer_lock,
    "Gemfile.lock": _gemfile_lock,
}


def _read(root: str, rel: str, limit: int) -> str | None:
    try:
        path = d._inside(root, rel)
    except d.Failed:
        return None
    if not os.path.isfile(path) or os.path.getsize(path) > limit:
        return None
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _lockfile_dirs(root: str, context: str) -> list[str]:
    """The repository root, the build context and folders one level down
    (monorepos keep a lockfile per service)."""
    dirs = [".", context]
    try:
        names = sorted(os.listdir(root))
    except OSError:
        names = []
    dirs += [
        n
        for n in names
        if n not in SKIP_DIRS
        and not n.startswith(".")
        and os.path.isdir(os.path.join(root, n))
    ][:30]
    seen: list[str] = []
    for rel in dirs:
        norm = os.path.normpath(rel)
        if norm not in seen:
            seen.append(norm)
    return seen


def lockfile_packages(
    root: str, context: str = "."
) -> tuple[list[list[str]], list[str]]:
    """([[ecosystem, name, version]], lockfiles read) for a checkout."""
    found: set[tuple[str, str, str]] = set()
    read: list[str] = []
    for folder in _lockfile_dirs(root, context):
        for filename, parse in PARSERS.items():
            rel = filename if folder == "." else f"{folder}/{filename}"
            text = _read(root, rel, MAX_LOCKFILE)
            if text is None:
                continue
            try:
                rows = parse(text)
            except (ValueError, TypeError, AttributeError):
                continue  # malformed: skip the file, not the app
            read.append(rel)
            ecosystem = LOCKFILES[filename]
            for name, version in rows:
                if _ok(name, version):
                    found.add((ecosystem, name, version))
            if len(found) > MAX_PACKAGES:
                break
    return [list(p) for p in sorted(found)][:MAX_PACKAGES], read


# ---------------------------------------------------------------------------
# OS packages inside a container
# ---------------------------------------------------------------------------


def _container_file(
    container: str, path: str, limit: int = 16 * 1024 * 1024
) -> str | None:
    """One file out of a container (running or not), without exec."""
    try:
        done = subprocess.run(
            ["docker", "cp", f"{container}:{path}", "-"],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0 or len(done.stdout) > limit + 4096:
        return None
    try:
        with tarfile.open(fileobj=io.BytesIO(done.stdout)) as tar:
            member = next((m for m in tar if m.isfile()), None)
            if member is None or member.size > limit:
                return None
            handle = tar.extractfile(member)
            return handle.read().decode("utf-8", errors="replace") if handle else None
    except (tarfile.TarError, OSError):
        return None


def _os_release(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key.strip()] = value.strip().strip("\"'")
    return out


def _dpkg(text: str) -> list[list[str]]:
    """Installed packages by source package and version (OSV's Debian and
    Ubuntu advisories are per source package)."""
    found = set()
    for para in text.split("\n\n"):
        fields = dict(re.findall(r"^([A-Za-z-]+):\s*(.*)$", para, re.MULTILINE))
        if "installed" not in fields.get("Status", "") or "Package" not in fields:
            continue
        name, version = fields["Package"], fields.get("Version", "")
        source = fields.get("Source")
        if source:
            m = re.match(r"^(\S+)(?:\s+\(([^)]+)\))?", source)
            if m:
                name, version = m.group(1), m.group(2) or version
        if _ok(name, version):
            found.add((name, version))
    return [list(p) for p in sorted(found)][:MAX_OS_PACKAGES]


def _apk(text: str) -> list[list[str]]:
    found = set()
    for block in text.split("\n\n"):
        fields = dict(re.findall(r"^([A-Za-z]):(.*)$", block, re.MULTILINE))
        name = fields.get("o") or fields.get("P")
        version = fields.get("V", "")
        if name and _ok(name, version):
            found.add((name, version))
    return [list(p) for p in sorted(found)][:MAX_OS_PACKAGES]


def os_packages(container: str) -> dict[str, Any] | None:
    """{"ecosystem", "id", "version", "packages"} for a container's distro."""
    release = _container_file(container, "/etc/os-release", 64 * 1024)
    if release is None:
        release = _container_file(container, "/usr/lib/os-release", 64 * 1024)
    if release is None:
        return None
    info = _os_release(release)
    distro, version = info.get("ID", ""), info.get("VERSION_ID", "")
    if distro == "debian" and re.fullmatch(r"\d{1,3}", version):
        ecosystem = f"Debian:{version}"
        status = _container_file(container, "/var/lib/dpkg/status")
        packages = _dpkg(status) if status else []
    elif distro == "ubuntu" and re.fullmatch(r"\d{2}\.\d{2}", version):
        lts = version.endswith(".04") and int(version[:2]) % 2 == 0
        ecosystem = f"Ubuntu:{version}" + (":LTS" if lts else "")
        status = _container_file(container, "/var/lib/dpkg/status")
        packages = _dpkg(status) if status else []
    elif distro == "alpine" and re.fullmatch(r"\d+\.\d+(\.\d+)?", version):
        ecosystem = "Alpine:v" + ".".join(version.split(".")[:2])
        installed = _container_file(container, "/lib/apk/db/installed")
        packages = _apk(installed) if installed else []
    else:
        return {
            "ecosystem": None,
            "id": distro[:20],
            "version": version[:20],
            "packages": [],
        }
    return {
        "ecosystem": ecosystem,
        "id": distro,
        "version": version,
        "packages": packages,
    }


# ---------------------------------------------------------------------------
# Committed secrets
# ---------------------------------------------------------------------------

SECRET_RULES = [
    ("Private key", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{80,})\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}")),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[0-9a-zA-Z]{24,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}T3BlbkFJ[A-Za-z0-9_-]{16,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b")),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b")),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
]  # fmt: skip
ENV_FILE = re.compile(r"(^|/)\.env(\.[A-Za-z0-9_-]+)?$")
ENV_EXAMPLE = re.compile(
    r"\.(example|sample|template|dist|defaults?|schema|test|ci)$", re.IGNORECASE
)
SECRET_KEY = re.compile(r"^[ \t]*(?:export[ \t]+)?([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|API_?KEY|ACCESS_?KEY|DATABASE_URL|DSN|CREDENTIALS?)[A-Z0-9_]*)[ \t]*=[ \t]*(\S.*)$", re.MULTILINE)  # fmt: skip
PLACEHOLDER = re.compile(r"^['\"]?(?:|x+|\*+|changeme|change-me|your[-_].*|<.*>|\$\{.*\}|\.\.\.|placeholder|example|secret|password|todo|none|null|false|true)['\"]?$", re.IGNORECASE)  # fmt: skip


def _tracked_files(root: str) -> list[str]:
    try:
        done = subprocess.run(
            ["git", "-C", root, "ls-files", "-z"],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if done.returncode != 0:
        return []
    files = [f for f in done.stdout.decode("utf-8", errors="replace").split("\0") if f]
    return [
        f
        for f in files
        if not any(part in SKIP_DIRS for part in f.split("/")[:-1])
        and not f.endswith((".min.js", ".map", ".lock", "lock.json", "lock.yaml"))
    ][:MAX_SCAN_FILES]


def secrets(root: str) -> list[dict[str, Any]]:
    """[{"path", "line", "rule"}] for committed files that look like secrets."""
    found: list[dict[str, Any]] = []
    budget = MAX_SCAN_BYTES
    for rel in _tracked_files(root):
        if len(found) >= MAX_SECRETS or budget <= 0:
            break
        try:
            path = d._inside(root, rel)
        except d.Failed:
            continue
        if os.path.islink(os.path.join(root, rel)) or not os.path.isfile(path):
            continue
        try:
            size = os.path.getsize(path)
            if size > MAX_SCAN_FILE:
                continue
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError:
            continue
        budget -= size
        if b"\0" in raw[:8192]:
            continue  # binary
        text = raw.decode("utf-8", errors="replace")
        if ENV_FILE.search(rel) and not ENV_EXAMPLE.search(rel):
            for m in SECRET_KEY.finditer(text):
                if not PLACEHOLDER.match(m.group(2).strip()):
                    line = text.count("\n", 0, m.start()) + 1
                    found.append(
                        {
                            "path": rel[:300],
                            "line": line,
                            "rule": f"Environment file ({m.group(1)[:60]})",
                        }
                    )
                    break
        for rule, pattern in SECRET_RULES:
            m = pattern.search(text)
            if m:
                line = text.count("\n", 0, m.start()) + 1
                found.append({"path": rel[:300], "line": line, "rule": rule})
    return found[:MAX_SECRETS]


def warn_secrets(root: str, emit: d.Emit) -> None:
    """During a deploy: point out committed secrets, without failing it."""
    try:
        hits = secrets(root)
    except Exception:  # noqa: BLE001 - a scan problem must never fail a deploy
        return
    for hit in hits[:10]:
        emit(
            "warn",
            f"Possible secret committed: {hit['path']}:{hit['line']} ({hit['rule']})",
        )
    if hits:
        emit(
            "warn",
            "Secrets in the repository can leak with it: move them to the app's environment variables and rotate them.",
        )


# ---------------------------------------------------------------------------
# The operation
# ---------------------------------------------------------------------------


def _app_spec(item: Any) -> dict[str, str]:
    if not isinstance(item, dict):
        raise Rejected("invalid app")
    runtime = item.get("runtime")
    if runtime not in d.RUNTIMES:
        raise Rejected("invalid runtime")
    spec = {
        "app": d._match(d.APP_RE, item.get("app"), "app name"),
        "runtime": runtime,
        "context": d._match(d.PATH_RE, item.get("context") or ".", "build context"),
        "service": "",
    }
    if runtime == "compose" and item.get("service"):
        spec["service"] = d._match(d.SERVICE_RE, item.get("service"), "service")
    return spec


def scan_app(spec: dict[str, str]) -> dict[str, Any]:
    app = spec["app"]
    out: dict[str, Any] = {
        "app": app,
        "packages": [],
        "lockfiles": [],
        "secrets": [],
        "os": None,
    }
    src = os.path.join(d.APPS_DIR, app, "src")
    if os.path.isdir(os.path.join(src, ".git")):
        out["packages"], out["lockfiles"] = lockfile_packages(src, spec["context"])
        out["secrets"] = secrets(src)
    if spec["runtime"] in ("docker", "compose") and shutil.which("docker"):
        container = (
            f"vp-{app}"
            if spec["runtime"] == "docker"
            else f"vp-{app}-{spec['service']}-1"
        )
        if spec["runtime"] == "docker" or spec["service"]:
            out["os"] = os_packages(container)
    return out


def audit_apps(args: dict[str, Any]) -> dict[str, Any]:
    items = args.get("apps")
    if not isinstance(items, list) or len(items) > MAX_APPS:
        raise Rejected("invalid apps")
    specs = [_app_spec(item) for item in items]
    results = []
    for spec in specs:
        try:
            results.append(scan_app(spec))
        except (OSError, ValueError) as error:
            results.append({"app": spec["app"], "error": str(error)[:200]})
    return {"exit_code": 0, "output": json.dumps({"apps": results})}


OPERATIONS = {"apps.audit": audit_apps}
