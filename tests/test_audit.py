"""The agent's app scan: lockfiles, OS packages and committed secrets."""

import json
import subprocess

import pytest
from vpspilot_agent import audit, executor

LOCKFILES = {
    "package-lock.json": json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "web"},
                "node_modules/next": {"version": "16.1.6"},
                "node_modules/@types/node": {"version": "20.19.34"},
                "node_modules/a/node_modules/b": {"version": "1.0.0"},
                "packages/ui": {"link": True},
            },
        }
    ),
    "pnpm-lock.yaml": """lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      next:
        specifier: 16.1.6
        version: 16.1.6(react@19.2.3)

packages:

  '@next/env@16.1.6':
    resolution: {integrity: sha512-a}

  next@16.1.6:
    resolution: {integrity: sha512-b}

snapshots:

  next@16.1.6(react@19.2.3):
    dependencies:
      '@next/env': 16.1.6
""",
    "yarn.lock": """# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.24.2"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.24.2.tgz"

lodash@^4.17.21:
  version "4.17.21"
""",
    "uv.lock": """version = 1

[[package]]
name = "fastapi"
version = "0.115.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "starlette"
version = "0.38.6"
""",
    "Pipfile.lock": json.dumps(
        {
            "default": {"django": {"version": "==4.2.1"}},
            "develop": {"pytest": {"version": "==8.0.0"}},
        }
    ),
    "requirements.txt": "django==4.2.1\nrequests[socks]==2.31.0 ; python_version > '3'\n# pinned\nflask>=2\n",
    "go.mod": "module example.com/x\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/text v0.3.0\n\tgithub.com/gin-gonic/gin v1.9.1 // indirect\n)\n",
    "Cargo.lock": """[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "my-local-crate"
version = "0.1.0"
""",
    "composer.lock": json.dumps(
        {"packages": [{"name": "laravel/framework", "version": "v10.0.0"}]}
    ),
    "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n      actionpack (= 7.0.4)\n",
}


def write(root, files):
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def test_lockfiles_of_every_ecosystem(tmp_path):
    write(tmp_path, LOCKFILES)
    packages, read = audit.lockfile_packages(str(tmp_path))
    found = {tuple(p) for p in packages}
    assert {
        ("npm", "next", "16.1.6"),
        ("npm", "@types/node", "20.19.34"),
        ("npm", "b", "1.0.0"),
        ("npm", "@next/env", "16.1.6"),
        ("npm", "@babel/code-frame", "7.24.2"),
        ("npm", "lodash", "4.17.21"),
        ("PyPI", "fastapi", "0.115.0"),
        ("PyPI", "starlette", "0.38.6"),
        ("PyPI", "django", "4.2.1"),
        ("PyPI", "pytest", "8.0.0"),
        ("PyPI", "requests", "2.31.0"),
        ("Go", "golang.org/x/text", "v0.3.0"),
        ("Go", "github.com/gin-gonic/gin", "v1.9.1"),
        ("crates.io", "serde", "1.0.200"),
        ("Packagist", "laravel/framework", "10.0.0"),
        ("RubyGems", "rails", "7.0.4"),
    } <= found
    assert not any(
        name in ("web", "ui", "my-local-crate", "flask") for _, name, _ in found
    )
    assert set(read) == set(LOCKFILES)


@pytest.mark.parametrize(
    ("lock", "expected"),
    [
        (
            "lockfileVersion: '6.0'\n\npackages:\n\n  /react@18.2.0:\n    resolution: {}\n\n  /@babel/core@7.24.0(supports-color@8.1.1):\n    resolution: {}\n",
            {("react", "18.2.0"), ("@babel/core", "7.24.0")},
        ),
        (
            "lockfileVersion: 5.4\n\npackages:\n\n  /react/18.2.0:\n    resolution: {}\n\n  /@babel/core/7.24.0_supports-color@8.1.1:\n    resolution: {}\n",
            {("react", "18.2.0"), ("@babel/core", "7.24.0")},
        ),
    ],
)
def test_older_pnpm_lockfiles(tmp_path, lock, expected):
    write(tmp_path, {"pnpm-lock.yaml": lock})
    packages, _ = audit.lockfile_packages(str(tmp_path))
    assert {(n, v) for _, n, v in packages} == expected


def test_yarn_berry_and_monorepo_folders(tmp_path):
    write(
        tmp_path,
        {
            "apps/web/yarn.lock": '__metadata:\n  version: 8\n\n"lodash@npm:^4.17.21":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n',
            "node_modules/x/package-lock.json": LOCKFILES["package-lock.json"],
        },
    )
    packages, read = audit.lockfile_packages(str(tmp_path), "apps/web")
    assert packages == [["npm", "lodash", "4.17.21"]]
    assert read == ["apps/web/yarn.lock"]  # node_modules is never read


def test_lockfiles_outside_the_checkout_are_refused(tmp_path):
    outside = tmp_path / "outside"
    write(outside, {"package-lock.json": LOCKFILES["package-lock.json"]})
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").symlink_to(outside / "package-lock.json")
    assert audit.lockfile_packages(str(repo)) == ([], [])


def test_broken_lockfiles_are_skipped(tmp_path):
    write(tmp_path, {"package-lock.json": "{not json", "uv.lock": LOCKFILES["uv.lock"]})
    packages, read = audit.lockfile_packages(str(tmp_path))
    assert read == ["uv.lock"] and len(packages) == 2


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"  # split so this file isn't flagged itself
PRIVATE_KEY = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nabc\n"


def git_repo(root, files, untracked=None):
    write(root, files)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    if untracked:
        write(root, untracked)


def test_committed_secrets_are_found_without_their_values(tmp_path):
    git_repo(
        tmp_path,
        {
            ".env.production": "NODE_ENV=production\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCY\n",
            ".env": "SECRET_KEY=\nPASSWORD=changeme\nDATABASE_URL=${DATABASE_URL}\n",
            ".env.example": "API_KEY=sk_live_example_but_in_an_example_file\n",
            "src/config.js": f'export const key = "{AWS_KEY}";\n',
            "README.md": "Set API_KEY in your environment.\n",
            "node_modules/pkg/id_rsa": PRIVATE_KEY,
        },
        untracked={"notes/key.pem": PRIVATE_KEY},
    )
    hits = audit.secrets(str(tmp_path))
    found = {(h["path"], h["rule"]) for h in hits}
    assert found == {
        (".env.production", "Environment file (AWS_SECRET_ACCESS_KEY)"),
        ("src/config.js", "AWS access key"),
    }
    assert next(h["line"] for h in hits if h["path"] == ".env.production") == 2
    dumped = json.dumps(hits)
    assert AWS_KEY not in dumped and "wJalrXUtnFEMIK7MDENGbPxRfiCY" not in dumped


def test_deploys_warn_about_committed_secrets(tmp_path):
    git_repo(tmp_path, {"deploy/key.pem": PRIVATE_KEY})
    events = []
    audit.warn_secrets(str(tmp_path), lambda level, msg: events.append((level, msg)))
    assert events[0] == (
        "warn",
        "Possible secret committed: deploy/key.pem:1 (Private key)",
    )
    assert "rotate them" in events[-1][1]


# ---------------------------------------------------------------------------
# OS packages
# ---------------------------------------------------------------------------

DPKG = """Package: libssl3
Status: install ok installed
Source: openssl (3.0.11-1~deb12u2)
Version: 3.0.11-1~deb12u2

Package: zlib1g
Status: install ok installed
Source: zlib
Version: 1:1.2.13.dfsg-1

Package: old-thing
Status: deinstall ok config-files
Version: 1.0
"""
APK = "P:musl\nV:1.2.4-r2\no:musl\n\nP:libcrypto3\nV:3.1.4-r1\no:openssl\n"


def test_dpkg_and_apk_by_source_package():
    assert audit._dpkg(DPKG) == [
        ["openssl", "3.0.11-1~deb12u2"],
        ["zlib", "1:1.2.13.dfsg-1"],
    ]
    assert audit._apk(APK) == [["musl", "1.2.4-r2"], ["openssl", "3.1.4-r1"]]


@pytest.mark.parametrize(
    ("release", "files", "ecosystem"),
    [
        ('ID=debian\nVERSION_ID="12"\n', {"/var/lib/dpkg/status": DPKG}, "Debian:12"),
        (
            'ID=ubuntu\nVERSION_ID="24.04"\n',
            {"/var/lib/dpkg/status": DPKG},
            "Ubuntu:24.04:LTS",
        ),
        (
            'ID=ubuntu\nVERSION_ID="23.10"\n',
            {"/var/lib/dpkg/status": DPKG},
            "Ubuntu:23.10",
        ),
        (
            "ID=alpine\nVERSION_ID=3.20.3\n",
            {"/lib/apk/db/installed": APK},
            "Alpine:v3.20",
        ),
    ],
)
def test_container_distro(monkeypatch, release, files, ecosystem):
    files = {"/etc/os-release": release, **files}
    monkeypatch.setattr(
        audit, "_container_file", lambda c, path, limit=0: files.get(path)
    )
    found = audit.os_packages("vp-shop")
    assert found["ecosystem"] == ecosystem and found["packages"]


def test_unknown_distros_report_no_packages(monkeypatch):
    monkeypatch.setattr(
        audit,
        "_container_file",
        lambda c, path, limit=0: "ID=wolfi\n" if path == "/etc/os-release" else None,
    )
    assert audit.os_packages("vp-shop") == {
        "ecosystem": None,
        "id": "wolfi",
        "version": "",
        "packages": [],
    }


# ---------------------------------------------------------------------------
# The operation and the executor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "item",
    [
        {"app": "../etc", "runtime": "docker"},
        {"app": "shop", "runtime": "kubernetes"},
        {"app": "shop", "runtime": "docker", "context": "../../root"},
        {"app": "shop", "runtime": "compose", "service": "web; rm -rf /"},
    ],
)
def test_arguments_are_validated(item):
    with pytest.raises(audit.Rejected):
        audit.audit_apps({"apps": [item]})


def test_scan_reads_the_checkout_and_the_container(tmp_path, monkeypatch):
    src = tmp_path / "shop" / "src"
    git_repo(src, {"package-lock.json": LOCKFILES["package-lock.json"]})
    monkeypatch.setattr(audit.d, "APPS_DIR", str(tmp_path))
    monkeypatch.setattr(audit.shutil, "which", lambda name: "/usr/bin/docker")
    seen = []
    monkeypatch.setattr(
        audit,
        "os_packages",
        lambda c: seen.append(c) or {"ecosystem": "Debian:12", "packages": []},
    )
    out = json.loads(
        audit.audit_apps({"apps": [{"app": "shop", "runtime": "docker"}]})["output"]
    )
    row = out["apps"][0]
    assert ["npm", "next", "16.1.6"] in row["packages"] and row["lockfiles"] == [
        "package-lock.json"
    ]
    assert seen == ["vp-shop"] and row["os"]["ecosystem"] == "Debian:12"


class RecordingClient:
    def __init__(self):
        self.calls = []

    def post(self, path, body):
        self.calls.append((path, body))
        return {}


def test_executor_sends_each_apps_packages_separately():
    client = RecordingClient()
    output = {
        "apps": [
            {
                "app": "shop",
                "packages": [["npm", "next", "16.1.6"]],
                "os": {"packages": [["openssl", "3"]]},
            },
            {"app": "blog", "error": "Permission denied"},
        ]
    }

    def fake_call(op, args, timeout=None, on_event=None):
        assert op == "apps.audit" and timeout == executor.AUDIT_TIMEOUT
        return {"ok": True, "exit_code": 0, "output": json.dumps(output)}

    job = {
        "id": "j1",
        "type": "apps.audit",
        "version": 1,
        "payload": {"apps": [{"app": "shop", "runtime": "docker"}]},
    }
    assert executor.run_job(client, job, call=fake_call) == "succeeded"
    sent = [b for p, b in client.calls if p == "/agent/v1/app-packages"]
    assert sent == [{"job_id": "j1", **output["apps"][0]}]
    path, body = client.calls[-1]
    assert path == "/agent/v1/jobs/j1/complete"
    assert body["output"] == "Scanned 1 app: 2 packages\nblog: Permission denied"
