"""GitHub integration through a GitHub App that each VPSPilot install creates
for itself (the "app manifest" flow), so no shared OAuth app is needed.

1. connect: the browser posts a manifest to GitHub, GitHub creates the app
   and redirects back with a code we exchange for the app's credentials.
2. install: the user installs the app on their account/org and picks repos.
3. repos and branches are listed with short-lived installation tokens.
4. deploys of a linked repo get a read-only token for that single repo,
   minted per deployment and handed only to the agent running it.
5. pushes arrive as signed webhooks and deploy apps with auto-deploy on.
"""

import hashlib
import hmac
import re
import secrets
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

import jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import decrypt_secret, encrypt_secret, new_id
from app.github import client
from app.github.models import GitHubApp, GitHubInstallation

PURPOSE = "github"
STATE_TTL = 15 * 60
ORG_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
MAX_REPO_PAGES = 10


class GitHubIntegrationError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> datetime:
    return datetime.now(UTC)


def _call(*args, **kwargs) -> Any:
    try:
        return client.request(*args, **kwargs)
    except client.GitHubError as error:
        status = 502 if error.status >= 500 else 400
        if error.status in (401, 403, 404):
            status = 409
        raise GitHubIntegrationError(status, f"GitHub said: {error.message}") from None


# ---------------------------------------------------------------------------
# Connecting: app manifest flow
# ---------------------------------------------------------------------------


def get_app(db: Session) -> GitHubApp | None:
    return db.scalar(select(GitHubApp).limit(1))


def _state(user_id: str | int) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "purpose": "github-manifest",
            "sub": str(user_id),
            "iat": now,
            "exp": now + STATE_TTL,
        },
        settings.secret_key,
        algorithm="HS256",
    )


def _check_state(state: str, user_id: str | int) -> None:
    try:
        claims = jwt.decode(state, settings.secret_key, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise GitHubIntegrationError(
            400, "This GitHub link expired; start again"
        ) from None
    if claims.get("purpose") != "github-manifest" or claims.get("sub") != str(user_id):
        raise GitHubIntegrationError(400, "This GitHub link isn't yours; start again")


def manifest(db: Session, user_id: str, organization: str | None) -> dict[str, Any]:
    """What the browser posts to GitHub to create the app."""
    if get_app(db):
        raise GitHubIntegrationError(409, "GitHub is already connected")
    if organization and not ORG_RE.match(organization):
        raise GitHubIntegrationError(422, "That isn't a valid organization name")
    front = settings.frontend_url.rstrip("/")
    page = f"{front}/dashboard/settings/github"
    webhook = settings.webhook_base_url
    body: dict[str, Any] = {
        # App names are unique across GitHub, so add a short random suffix.
        "name": f"VPSPilot {secrets.token_hex(3)}",
        "url": front,
        "redirect_url": page,
        "setup_url": page,
        "setup_on_update": True,
        "public": False,
        # Read code and metadata only: enough to list, clone and get pushes.
        "default_permissions": {"contents": "read", "metadata": "read"},
        "default_events": ["push"] if webhook else [],
    }
    if webhook:
        body["hook_attributes"] = {
            "url": f"{webhook}/api/v1/github/webhook",
            "active": True,
        }
    state = _state(user_id)
    base = (
        f"{client.WEB}/organizations/{organization}/settings/apps/new"
        if organization
        else f"{client.WEB}/settings/apps/new"
    )
    return {
        "post_url": f"{base}?{urlencode({'state': state})}",
        "manifest": body,
        "webhooks": bool(webhook),
    }


def complete_manifest(
    db: Session, code: str, state: str, user_id: str, actor_label: str
) -> GitHubApp:
    _check_state(state, user_id)
    if get_app(db):
        raise GitHubIntegrationError(409, "GitHub is already connected")
    if not re.match(r"^[A-Za-z0-9_-]{1,100}$", code):
        raise GitHubIntegrationError(400, "Invalid code from GitHub")
    data = _call("POST", f"/app-manifests/{code}/conversions")
    owner = data.get("owner") or {}
    hook = data.get("webhook_secret")
    app = GitHubApp(
        id=new_id(),
        app_id=int(data["id"]),
        slug=str(data["slug"])[:100],
        name=str(data["name"])[:100],
        owner_login=str(owner.get("login") or "")[:100],
        owner_type=str(owner.get("type") or "User")[:16],
        html_url=str(data["html_url"])[:300],
        client_id=str(data["client_id"])[:100],
        client_secret=encrypt_secret(data["client_secret"], PURPOSE),
        private_key=encrypt_secret(data["pem"], PURPOSE),
        webhook_secret=encrypt_secret(hook, PURPOSE) if hook else None,
        webhook_url=(
            f"{settings.webhook_base_url}/api/v1/github/webhook"
            if hook and settings.webhook_base_url
            else None
        ),
        created_by=actor_label[:64],
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def install_url(app: GitHubApp) -> str:
    return f"{client.WEB}/apps/{app.slug}/installations/new"


def disconnect(db: Session) -> GitHubApp | None:
    app = get_app(db)
    if app:
        db.delete(app)
        db.commit()
        _tokens.clear()
    return app


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


def app_jwt(app: GitHubApp) -> str:
    now = int(time.time())
    return jwt.encode(
        {"iat": now - 60, "exp": now + 540, "iss": str(app.app_id)},
        decrypt_secret(app.private_key, PURPOSE),
        algorithm="RS256",
    )


# installation id -> (token, expires at); never persisted.
_tokens: dict[int, tuple[str, float]] = {}


def installation_token(app: GitHubApp, installation_id: int) -> str:
    cached = _tokens.get(installation_id)
    if cached and cached[1] - time.time() > 300:
        return cached[0]
    data = _call(
        "POST",
        f"/app/installations/{installation_id}/access_tokens",
        token=app_jwt(app),
    )
    _tokens[installation_id] = (data["token"], time.time() + 3000)
    return data["token"]


def repo_token(db: Session, installation_id: int, repo_id: int) -> str | None:
    """A read-only token for one repository, for one deployment."""
    app = get_app(db)
    if app is None:
        return None
    data = _call(
        "POST",
        f"/app/installations/{installation_id}/access_tokens",
        token=app_jwt(app),
        json={"repository_ids": [repo_id], "permissions": {"contents": "read"}},
    )
    return data["token"]


# ---------------------------------------------------------------------------
# Installations and repositories
# ---------------------------------------------------------------------------


def _require_app(db: Session) -> GitHubApp:
    app = get_app(db)
    if app is None:
        raise GitHubIntegrationError(409, "Connect GitHub first")
    return app


def _upsert_installation(db: Session, app: GitHubApp, data: dict) -> GitHubInstallation:
    account = data.get("account") or {}
    inst = db.get(GitHubInstallation, int(data["id"]))
    if inst is None:
        inst = GitHubInstallation(id=int(data["id"]), github_app_id=app.id)
        db.add(inst)
    inst.account_login = str(account.get("login") or "")[:100]
    inst.account_type = str(account.get("type") or "User")[:16]
    inst.account_avatar_url = (account.get("avatar_url") or None) and str(
        account["avatar_url"]
    )[:300]
    inst.repository_selection = str(data.get("repository_selection") or "all")[:16]
    inst.suspended_at = _now() if data.get("suspended_at") else None
    return inst


def register_installation(db: Session, installation_id: int) -> GitHubInstallation:
    """Called when GitHub redirects back after installing. The id comes from
    the browser, so it is checked with GitHub (it must belong to our app)."""
    app = _require_app(db)
    data = _call("GET", f"/app/installations/{installation_id}", token=app_jwt(app))
    inst = _upsert_installation(db, app, data)
    db.commit()
    return inst


def sync_installations(db: Session) -> list[GitHubInstallation]:
    app = _require_app(db)
    found = _call(
        "GET", "/app/installations", token=app_jwt(app), params={"per_page": 100}
    )
    seen = set()
    for data in found or []:
        seen.add(_upsert_installation(db, app, data).id)
    for inst in db.scalars(select(GitHubInstallation)):
        if inst.id not in seen:
            db.delete(inst)
            _tokens.pop(inst.id, None)
    db.commit()
    return list(
        db.scalars(
            select(GitHubInstallation).order_by(GitHubInstallation.account_login)
        )
    )


def installations(db: Session) -> list[GitHubInstallation]:
    return list(
        db.scalars(
            select(GitHubInstallation).order_by(GitHubInstallation.account_login)
        )
    )


def _repo_out(data: dict, installation_id: int) -> dict[str, Any]:
    return {
        "id": int(data["id"]),
        "installation_id": installation_id,
        "full_name": data["full_name"],
        "name": data["name"],
        "owner": (data.get("owner") or {}).get("login"),
        "private": bool(data.get("private")),
        "default_branch": data.get("default_branch") or "main",
        "html_url": data["html_url"],
        "clone_url": f"{client.WEB}/{data['full_name']}",
        "description": (data.get("description") or "")[:200] or None,
        "language": data.get("language"),
        "pushed_at": data.get("pushed_at"),
    }


def list_repositories(db: Session) -> list[dict[str, Any]]:
    app = _require_app(db)
    repos: list[dict[str, Any]] = []
    for inst in installations(db):
        if inst.suspended_at:
            continue
        token = installation_token(app, inst.id)
        for page in range(1, MAX_REPO_PAGES + 1):
            data = _call(
                "GET",
                "/installation/repositories",
                token=token,
                params={"per_page": 100, "page": page},
            )
            batch = data.get("repositories") or []
            repos += [_repo_out(r, inst.id) for r in batch]
            if len(batch) < 100:
                break
    repos.sort(key=lambda r: r["pushed_at"] or "", reverse=True)
    return repos


def get_repository(db: Session, installation_id: int, repo_id: int) -> dict[str, Any]:
    """Check the installation can see this repo; returns its details."""
    app = _require_app(db)
    if db.get(GitHubInstallation, installation_id) is None:
        raise GitHubIntegrationError(404, "That GitHub installation isn't connected")
    data = _call(
        "GET",
        f"/repositories/{repo_id}",
        token=installation_token(app, installation_id),
    )
    return _repo_out(data, installation_id)


def list_branches(db: Session, installation_id: int, repo_id: int) -> list[str]:
    repo = get_repository(db, installation_id, repo_id)
    app = _require_app(db)
    data = _call(
        "GET",
        f"/repos/{repo['full_name']}/branches",
        token=installation_token(app, installation_id),
        params={"per_page": 100},
    )
    names = [b["name"] for b in data or []]
    # Default branch first.
    return sorted(names, key=lambda n: (n != repo["default_branch"], n))


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------


def verify_signature(db: Session, body: bytes, signature: str | None) -> GitHubApp:
    app = get_app(db)
    if app is None or not app.webhook_secret or not signature:
        raise GitHubIntegrationError(401, "Unsigned or unexpected webhook")
    secret = decrypt_secret(app.webhook_secret, PURPOSE).encode()
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise GitHubIntegrationError(401, "Bad webhook signature")
    return app


def handle_installation_event(
    db: Session, app: GitHubApp, action: str, data: dict
) -> None:
    inst_id = int(data["id"])
    if action == "deleted":
        inst = db.get(GitHubInstallation, inst_id)
        if inst:
            db.delete(inst)
        _tokens.pop(inst_id, None)
    else:
        inst = _upsert_installation(db, app, data)
        if action == "suspend":
            inst.suspended_at = _now()
        elif action == "unsuspend":
            inst.suspended_at = None
    db.commit()
