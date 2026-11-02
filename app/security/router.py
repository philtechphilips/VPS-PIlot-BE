"""Security: findings per app, a fleet overview, scans and ignores."""

from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select

from app.agent_version import AGENT_VERSION
from app.apps.models import Application
from app.audit import service as audit
from app.auth.dependencies import AdminUser, ReaderUser
from app.core.database import DbSession
from app.security import service
from app.security.models import AppFinding, AppScan
from app.servers.models import Server

router = APIRouter(prefix="/api/v1/security", tags=["Security"])


def _finding(f: AppFinding) -> dict[str, Any]:
    return {
        "id": f.id,
        "kind": f.kind,
        "severity": f.severity,
        "title": f.title,
        "ecosystem": f.ecosystem,
        "package": f.package,
        "version": f.version,
        "fixed": f.fixed,
        "advisory": f.advisory,
        "aliases": f.aliases or [],
        "path": f.path,
        "eol_at": f.eol_at,
        "first_seen_at": f.first_seen_at,
        "ignored_at": f.ignored_at,
        "ignored_by": f.ignored_by,
    }


def _scan(scan: AppScan | None) -> dict[str, Any] | None:
    if scan is None:
        return None
    return {
        "scanned_at": scan.scanned_at,
        "checked_at": scan.checked_at,
        "check_error": scan.check_error,
        "lockfiles": scan.lockfiles or [],
        "packages": len(scan.packages or []),
        "os": f"{scan.os_id.capitalize()} {scan.os_version}".strip()
        if scan.os_id
        else None,
        "os_packages": len(scan.os_packages or []),
    }


def _app(db, app_id: str) -> Application:
    app = db.get(Application, app_id)
    if app is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Application not found")
    return app


@router.get("/apps/{app_id}")
def app_security(app_id: str, db: DbSession, _: ReaderUser):
    app = _app(db, app_id)
    rows = service.findings(db, app.id)
    server = db.get(Server, app.server_id)
    return {
        "lookups": service.lookups_enabled(db),
        "agent_ready": bool(
            server and service.jobs._agent_at_least(server, service.NEEDS_AGENT)
        ),
        "auto_rebuild": app.auto_rebuild,
        "scan": _scan(db.get(AppScan, app.id)),
        "counts": service.counts(rows),
        "findings": [_finding(f) for f in rows],
    }


@router.post("/apps/{app_id}/scan", status_code=status.HTTP_202_ACCEPTED)
def scan_app(app_id: str, request: Request, db: DbSession, user: AdminUser):
    app = _app(db, app_id)
    server = db.get(Server, app.server_id)
    if server is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "The app's server is gone")
    if not service.jobs._agent_at_least(server, service.NEEDS_AGENT):
        version = ".".join(map(str, service.NEEDS_AGENT))
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{server.name}'s agent can't scan apps yet. Upgrade it to {version} "
            "or later by re-running its install command.",
        )
    job = service.request_scan(db, server, [app], *audit.user_actor(user))
    if job is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Couldn't queue the scan")
    audit.record(
        db,
        action="security.scan",
        result="accepted",
        actor=audit.user_actor(user)[0],
        actor_label=user.email,
        target_type="application",
        target_id=app.id,
        target_label=app.name,
        request=request,
    )
    return {"job_id": job.id}


class IgnoreIn(BaseModel):
    ignored: bool


@router.post("/findings/{finding_id}/ignore")
def ignore_finding(
    finding_id: str, body: IgnoreIn, request: Request, db: DbSession, user: AdminUser
):
    finding = db.get(AppFinding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    service.set_ignored(db, finding, body.ignored, user.email)
    audit.record(
        db,
        action="security.ignore" if body.ignored else "security.unignore",
        result="success",
        actor=audit.user_actor(user)[0],
        actor_label=user.email,
        target_type="application",
        target_id=finding.application_id,
        target_label=finding.package or finding.path or finding.title,
        detail=finding.advisory or finding.title,
        request=request,
    )
    return _finding(finding)


class RebuildIn(BaseModel):
    enabled: bool


@router.put("/apps/{app_id}/auto-rebuild")
def set_auto_rebuild(
    app_id: str, body: RebuildIn, request: Request, db: DbSession, user: AdminUser
):
    app = _app(db, app_id)
    app.auto_rebuild = body.enabled
    db.commit()
    audit.record(
        db,
        action="app.auto_rebuild",
        result="success",
        actor=audit.user_actor(user)[0],
        actor_label=user.email,
        target_type="application",
        target_id=app.id,
        target_label=app.name,
        detail="on" if body.enabled else "off",
        request=request,
    )
    return {"auto_rebuild": app.auto_rebuild}


def _version(value: str | None) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in (value or "0").split(".")[:3])
    except ValueError:
        return (0,)


@router.get("/overview")
def overview(db: DbSession, _: ReaderUser):
    apps = list(db.scalars(select(Application).order_by(Application.name)))
    servers = {s.id: s for s in db.scalars(select(Server))}
    scans = {s.application_id: s for s in db.scalars(select(AppScan))}
    by_app: dict[str, list[AppFinding]] = {}
    for f in db.scalars(select(AppFinding)):
        by_app.setdefault(f.application_id, []).append(f)
    rows = []
    for app in apps:
        found = by_app.get(app.id, [])
        open_ = [f for f in found if f.ignored_at is None]
        scan = scans.get(app.id)
        rows.append(
            {
                "id": app.id,
                "name": app.name,
                "server": servers[app.server_id].name
                if app.server_id in servers
                else None,
                "deployed": app.current_deployment_id is not None,
                "scanned_at": scan.scanned_at if scan else None,
                "checked_at": scan.checked_at if scan else None,
                "check_error": scan.check_error if scan else None,
                "counts": service.counts(found),
                "fixable": sum(
                    1
                    for f in open_
                    if f.kind in ("dependency", "os") and f.fixed is not None
                ),
                "secrets": sum(1 for f in open_ if f.kind == "secret"),
                "eol": [f.title for f in open_ if f.kind == "eol"],
                "auto_rebuild": app.auto_rebuild,
            }
        )
    agents = [
        {"id": s.id, "name": s.name, "version": s.agent_version}
        for s in servers.values()
        if s.enrolled_at is not None
        and s.revoked_at is None
        and _version(s.agent_version) < _version(AGENT_VERSION)
    ]
    events = [
        {
            "id": e.id,
            "action": e.action.removeprefix("security."),
            "actor": e.actor_label,
            "target": e.target_label,
            "detail": e.detail,
            "ip": e.ip_address,
            "at": e.created_at,
        }
        for e in audit.list_entries(db, limit=20, action_prefix="security.")
        if e.action not in ("security.scan", "security.ignore", "security.unignore")
    ]
    return {
        "lookups": service.lookups_enabled(db),
        "latest_agent": AGENT_VERSION,
        "apps": rows,
        "outdated_agents": agents,
        "events": events,
    }
