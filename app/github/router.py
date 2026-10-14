import json
import logging
from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, StringConstraints

from app.audit import service as audit
from app.auth.dependencies import AdminUser
from app.core.database import DbSession
from app.github import service
from app.github.models import GitHubApp, GitHubInstallation

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/github", tags=["GitHub"])


def _raise(error: service.GitHubIntegrationError) -> NoReturn:
    raise HTTPException(status_code=error.status_code, detail=error.detail)


class ManifestRequest(BaseModel):
    organization: (
        Annotated[str, StringConstraints(strip_whitespace=True, max_length=39)] | None
    ) = None


class ManifestComplete(BaseModel):
    code: Annotated[str, StringConstraints(max_length=100)]
    state: Annotated[str, StringConstraints(max_length=1000)]


class InstallationIn(BaseModel):
    installation_id: Annotated[int, Field(gt=0)]


def _installation(inst: GitHubInstallation) -> dict[str, Any]:
    return {
        "id": inst.id,
        "account_login": inst.account_login,
        "account_type": inst.account_type,
        "account_avatar_url": inst.account_avatar_url,
        "repository_selection": inst.repository_selection,
        "suspended": inst.suspended_at is not None,
    }


def _status(db, app: GitHubApp | None) -> dict[str, Any]:
    if app is None:
        return {
            "connected": False,
            "webhooks_available": service._webhook_base(db) is not None,
            "app": None,
            "installations": [],
        }
    return {
        "connected": True,
        "webhooks_available": app.webhook_url is not None,
        "app": {
            "name": app.name,
            "slug": app.slug,
            "owner_login": app.owner_login,
            "owner_type": app.owner_type,
            "html_url": app.html_url,
            "install_url": service.install_url(app),
            "webhook_url": app.webhook_url,
            "created_at": app.created_at,
        },
        "installations": [_installation(i) for i in service.installations(db)],
    }


@router.get("/status")
def github_status(db: DbSession, _: AdminUser, refresh: bool = False):
    app = service.get_app(db)
    if app and refresh:
        try:
            service.sync_installations(db)
        except service.GitHubIntegrationError as error:
            _raise(error)
    return _status(db, app)


@router.post("/manifest")
def create_manifest(body: ManifestRequest, db: DbSession, user: AdminUser):
    """Start connecting: the browser posts `manifest` to `post_url`."""
    try:
        return service.manifest(db, user.id, body.organization or None)
    except service.GitHubIntegrationError as error:
        _raise(error)


@router.post("/manifest/complete")
def complete_manifest(
    body: ManifestComplete, request: Request, db: DbSession, user: AdminUser
):
    actor, label = audit.user_actor(user)
    try:
        app = service.complete_manifest(db, body.code, body.state, user.id, label)
    except service.GitHubIntegrationError as error:
        _raise(error)
    audit.record(
        db,
        action="github.connect",
        result="success",
        actor=actor,
        actor_label=label,
        target_type="github_app",
        target_id=str(app.app_id),
        target_label=app.name,
        detail=f"owner {app.owner_login}",
        request=request,
    )
    return _status(db, app)


@router.post("/installations")
def add_installation(
    body: InstallationIn, request: Request, db: DbSession, user: AdminUser
):
    try:
        inst = service.register_installation(db, body.installation_id)
    except service.GitHubIntegrationError as error:
        _raise(error)
    actor, label = audit.user_actor(user)
    audit.record(
        db,
        action="github.install",
        result="success",
        actor=actor,
        actor_label=label,
        target_type="github_installation",
        target_id=str(inst.id),
        target_label=inst.account_login,
        request=request,
    )
    return _status(db, service.get_app(db))


@router.delete("/app", status_code=status.HTTP_204_NO_CONTENT)
def disconnect(request: Request, db: DbSession, user: AdminUser):
    app = service.disconnect(db)
    if app:
        actor, label = audit.user_actor(user)
        audit.record(
            db,
            action="github.disconnect",
            result="success",
            actor=actor,
            actor_label=label,
            target_type="github_app",
            target_id=str(app.app_id),
            target_label=app.name,
            request=request,
        )


@router.get("/repositories")
def repositories(db: DbSession, _: AdminUser):
    try:
        return service.list_repositories(db)
    except service.GitHubIntegrationError as error:
        _raise(error)


@router.get("/repositories/{installation_id}/{repo_id}/branches")
def branches(installation_id: int, repo_id: int, db: DbSession, _: AdminUser):
    try:
        return service.list_branches(db, installation_id, repo_id)
    except service.GitHubIntegrationError as error:
        _raise(error)


@router.post("/webhook", status_code=status.HTTP_202_ACCEPTED, include_in_schema=False)
async def webhook(
    request: Request,
    db: DbSession,
    x_github_event: Annotated[str | None, Header()] = None,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
):
    """GitHub deliveries, verified with the app's webhook secret."""
    body = await request.body()
    if len(body) > 5 * 1024 * 1024:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Too large")
    try:
        app = service.verify_signature(db, body, x_hub_signature_256)
    except service.GitHubIntegrationError as error:
        _raise(error)
    try:
        payload = json.loads(body)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid JSON") from None

    if x_github_event == "push":
        from app.apps import service as apps

        queued = apps.deploy_from_push(db, payload, request)
        return {"deployments": queued}
    if x_github_event == "installation" and isinstance(
        payload.get("installation"), dict
    ):
        service.handle_installation_event(
            db, app, str(payload.get("action")), payload["installation"]
        )
    return {"ok": True}
