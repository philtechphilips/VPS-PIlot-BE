"""Preview deployments: a copy of the app for each pull request.

When an app has a preview domain, GitHub's pull_request events create an app
<name>-pr-<n> on the same server, built from the pull request's branch and
served at pr-<n>.<preview domain> (one wildcard DNS record covers them all).
It's redeployed on every push to the pull request and removed when it closes.

Only pull requests from the repository itself get a preview: one from a fork
would run someone else's code with the app's secrets.
"""

import re
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.apps import service as apps
from app.apps.models import Application
from app.audit import service as audit

MAX_PREVIEWS = 10
BRANCH_RE = re.compile(r"^[A-Za-z0-9._/][A-Za-z0-9._/-]{0,199}$")
COPIED = (
    "runtime", "server_id", "source_type", "repo_url", "github_installation_id",
    "github_repo_id", "github_repo_full_name", "dockerfile", "build_context",
    "build_command", "start_command", "release_command", "compose_file",
    "compose_service", "container_port", "health_path", "health_timeout_seconds",
    "cpu_limit", "memory_limit",
)  # fmt: skip


def preview_name(app: Application, number: int) -> str:
    suffix = f"-pr-{number}"
    return f"{app.name[: 40 - len(suffix)].rstrip('-')}{suffix}"


def list_for(db: Session, app: Application) -> list[Application]:
    return list(
        db.scalars(
            select(Application)
            .where(Application.preview_of == app.id)
            .order_by(Application.preview_pr.desc())
        )
    )


def _env(app: Application) -> list[dict[str, Any]]:
    """The app's variables with the preview overrides on top (both encrypted)."""
    overrides = {e["key"]: e for e in app.preview_env or []}
    return [e for e in app.env or [] if e["key"] not in overrides] + list(
        overrides.values()
    )


def _record(db: Session, app: Application, result: str, detail: str) -> None:
    audit.record(
        db,
        action="app.preview",
        result=result,
        actor="github",
        actor_label="GitHub pull request",
        target_type="application",
        target_id=app.id,
        target_label=app.name,
        detail=detail[:300],
    )


def _open(db: Session, parent: Application, number: int, branch: str, sha: str) -> None:
    from app.domains import service as domains

    preview = db.scalar(
        select(Application).where(
            Application.preview_of == parent.id, Application.preview_pr == number
        )
    )
    label = f"Preview of pull request #{number}"
    if preview is None:
        count = db.scalar(
            select(func.count())
            .select_from(Application)
            .where(Application.preview_of == parent.id)
        )
        if count >= MAX_PREVIEWS:
            _record(
                db, parent, "rejected", f"#{number}: already {MAX_PREVIEWS} previews"
            )
            return
        server = db.get(apps.Server, parent.server_id)
        preview = Application(
            id=apps.new_id(),
            name=preview_name(parent, number),
            branch=branch,
            host_port=apps._next_host_port(db, server),
            private_port=True,
            auto_deploy=False,  # pull_request events deploy it
            env=_env(parent),
            preview_of=parent.id,
            preview_pr=number,
            **{field: getattr(parent, field) for field in COPIED},
        )
        if db.scalar(select(Application).where(Application.name == preview.name)):
            _record(db, parent, "rejected", f"#{number}: {preview.name} is taken")
            return
        db.add(preview)
        db.commit()
        try:
            domains.create(
                db,
                {
                    "hostname": f"pr-{number}.{parent.preview_domain}",
                    "application_id": preview.id,
                    "tls_mode": "auto",
                    "redirect_www": False,
                },
                "github",
                label,
            )
        except domains.DomainError as error:
            _record(db, parent, "failure", f"#{number}: {error.detail}")
    else:
        preview.branch = branch
        preview.env = _env(parent)
    apps.deploy(db, preview, "github", label, trigger="push", ref=sha)


def _close(db: Session, parent: Application, number: int) -> None:
    preview = db.scalar(
        select(Application).where(
            Application.preview_of == parent.id, Application.preview_pr == number
        )
    )
    if preview is not None:
        apps.remove_app(db, preview, "github", f"Pull request #{number} closed")


def handle(db: Session, payload: dict[str, Any]) -> int:
    """GitHub pull_request webhook. Returns how many apps it touched."""
    action = payload.get("action")
    pr = payload.get("pull_request") or {}
    repo = payload.get("repository") or {}
    number = payload.get("number") or pr.get("number")
    head = pr.get("head") or {}
    sha = str(head.get("sha") or "")
    branch = str(head.get("ref") or "")
    if (
        action not in ("opened", "reopened", "synchronize", "closed")
        or not isinstance(number, int)
        or not repo.get("id")
    ):
        return 0
    parents = list(
        db.scalars(
            select(Application).where(
                Application.github_repo_id == int(repo["id"]),
                Application.preview_domain.is_not(None),
                Application.preview_of.is_(None),
            )
        )
    )
    touched = 0
    for parent in parents:
        if action == "closed":
            _close(db, parent, number)
            touched += 1
            continue
        same_repo = (head.get("repo") or {}).get("id") == repo["id"]
        if not same_repo:
            _record(db, parent, "rejected", f"#{number} comes from a fork: no preview")
            continue
        if (
            not re.match(r"^[0-9a-f]{40}$", sha)
            or not BRANCH_RE.match(branch)
            or ".." in branch
        ):
            continue
        try:
            _open(db, parent, number, branch, sha)
            touched += 1
        except apps.AppError as error:
            _record(db, parent, "failure", f"#{number}: {error.detail}")
    return touched
