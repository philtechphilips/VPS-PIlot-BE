"""Vulnerability checks for the apps VPSPilot runs.

1. The agent reads an app's lockfiles, its container's OS packages and its
   repository for committed secrets (job apps.audit, after every deploy and
   once for apps never scanned) and sends the lists here.
2. They're checked against OSV.dev, and the runtime and distro against
   end-of-life dates; problems become findings. Stored lists are checked
   again every day, so newly published advisories show up without a deploy.
3. Alert rules (monitoring) turn findings into notifications.

Only package names and versions go to OSV.dev; it can be turned off in the
platform settings, which leaves the secret scan (it never leaves the
server).
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.apps.models import Application, Deployment
from app.core.database import SessionLocal
from app.core.security import new_id
from app.jobs import service as jobs
from app.jobs.models import Job
from app.security import eol, osv
from app.security.models import AppFinding, AppScan
from app.servers.models import Server

logger = logging.getLogger(__name__)

NEEDS_AGENT = jobs.NEEDS_AGENT["apps.audit"]
RECHECK = timedelta(hours=24)
FIRST_SCAN_PAUSE = timedelta(hours=1)  # per server, between first-scan jobs
CHECKS_PER_TICK = 5
EOL_WARNING = timedelta(days=120)
REBUILD_EVERY = timedelta(days=7)
SEVERITY_ORDER = {s: i for i, s in enumerate(osv.SEVERITIES)}

_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="security")
_running: set[str] = set()


def _background(fn, *args) -> None:
    """OSV lookups take seconds; they run off the request and alert loop.
    Tests replace this to run inline."""
    _pool.submit(fn, *args)


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def lookups_enabled(db: Session) -> bool:
    from app.platform import service as platform

    return bool(platform.get(db).vuln_checks)


# ---------------------------------------------------------------------------
# Scans (agent)
# ---------------------------------------------------------------------------


def _audit_item(app: Application) -> dict[str, str]:
    return {
        "app": app.name,
        "runtime": app.runtime,
        "context": app.build_context or ".",
        "service": app.compose_service or "",
    }


def request_scan(
    db: Session,
    server: Server,
    apps: list[Application],
    actor: str = "system",
    label: str = "VPSPilot",
) -> Job | None:
    """Queue apps.audit for these apps. None when the agent is too old."""
    if not apps or not jobs._agent_at_least(server, NEEDS_AGENT):
        return None
    try:
        job, _ = jobs.create(
            db,
            server,
            "apps.audit",
            {"apps": [_audit_item(a) for a in apps]},
            actor,
            label,
            audited=False,
        )
    except jobs.JobError as error:
        logger.info("scan for %s not queued: %s", server.name, error.detail)
        return None
    return job


def store_scan(db: Session, server: Server, report: dict[str, Any]) -> AppScan | None:
    """An agent's scan of one app. The app must be on that agent's server."""
    app = db.scalar(
        select(Application).where(
            Application.name == report["app"], Application.server_id == server.id
        )
    )
    if app is None:
        return None
    scan = db.get(AppScan, app.id) or AppScan(application_id=app.id)
    os_info = report.get("os") or {}
    scan.scanned_at = _now()
    scan.checked_at = None
    scan.packages = report.get("packages") or []
    scan.lockfiles = report.get("lockfiles") or []
    scan.os_ecosystem = os_info.get("ecosystem")
    scan.os_id = os_info.get("id")
    scan.os_version = os_info.get("version")
    scan.os_packages = os_info.get("packages") or []
    scan.secrets = report.get("secrets") or []
    db.add(scan)
    db.commit()
    _queue_check(app.id)
    return scan


def _queue_check(app_id: str) -> None:
    if app_id in _running:
        return
    _running.add(app_id)
    _background(_check_in_session, app_id)


def _check_in_session(app_id: str) -> None:
    try:
        with SessionLocal() as db:
            check_app(db, app_id)
    except Exception:  # noqa: BLE001 - one app must not stop the others
        logger.exception("security check for %s failed", app_id)
    finally:
        _running.discard(app_id)


# ---------------------------------------------------------------------------
# Checks (OSV.dev and end-of-life data)
# ---------------------------------------------------------------------------


def _vulnerable(
    db: Session, kind: str, packages: list[tuple[str, str, str]]
) -> list[dict[str, Any]]:
    """Findings for packages with advisories. OS packages count only when a
    fixed version exists: distros list many issues they won't fix."""
    if not packages:
        return []
    hits = osv.query(packages)
    wanted = {v["id"]: v.get("modified") for row in hits for v in row}
    details = osv.advisories(db, wanted)
    out = []
    for (ecosystem, name, version), row in zip(packages, hits, strict=True):
        seen: set[str] = set()
        # GitHub's ids first: they carry a rating; other ids are often aliases.
        for vuln in sorted(
            row, key=lambda v: (not v["id"].startswith("GHSA-"), v["id"])
        ):
            advisory = details.get(vuln["id"])
            if advisory is None or vuln["id"] in seen:
                continue
            seen.update([vuln["id"], *(advisory.get("aliases") or [])])
            fixed = osv.fixed_version(advisory, ecosystem, name, version)
            if kind == "os" and fixed is None:
                continue
            out.append(
                {
                    "kind": kind,
                    "key": f"{kind}:{ecosystem}:{name}:{version}:{vuln['id']}",
                    "severity": osv.severity(advisory),
                    "title": advisory.get("summary") or vuln["id"],
                    "ecosystem": ecosystem,
                    "package": name,
                    "version": version,
                    "fixed": fixed,
                    "advisory": vuln["id"],
                    "aliases": (advisory.get("aliases") or [])[:10],
                }
            )
    return out


def _eol_findings(db: Session, app: Application, scan: AppScan) -> list[dict[str, Any]]:
    deployment = (
        db.get(Deployment, app.current_deployment_id)
        if app.current_deployment_id
        else None
    )
    targets = eol.runtimes_from_plan(
        (deployment.spec or {}).get("build_plan") if deployment else None
    )
    distro = eol.os_cycle(scan.os_id, scan.os_version)
    if distro:
        targets.append(distro)
    out = []
    today = _now()
    for product, cycle in targets:
        ends = eol.end_of_life(db, product, cycle)
        if ends is None:
            continue
        ends_at = datetime(ends.year, ends.month, ends.day, tzinfo=UTC)
        if ends_at - today > EOL_WARNING:
            continue
        name = eol.label(product, cycle)
        past = ends_at <= today
        when = ends.strftime("%-d %b %Y")
        out.append(
            {
                "kind": "eol",
                "key": f"eol:{product}:{cycle}",
                "severity": "high" if past else "low",
                "title": f"{name} stopped getting security fixes on {when}"
                if past
                else f"{name} stops getting security fixes on {when}",
                "package": name,
                "version": cycle,
                "eol_at": ends_at,
            }
        )
    return out


def _secret_findings(scan: AppScan) -> list[dict[str, Any]]:
    return [
        {
            "kind": "secret",
            "key": f"secret:{s.get('path')}:{s.get('rule')}",
            "severity": "high",
            "title": f"{s.get('rule')} committed to the repository",
            "path": f"{s.get('path')}:{s.get('line')}",
        }
        for s in scan.secrets or []
    ]


def check_app(db: Session, app_id: str) -> None:
    app = db.get(Application, app_id)
    scan = db.get(AppScan, app_id)
    if app is None or scan is None:
        return
    found = _secret_findings(scan)
    error = None
    if lookups_enabled(db):
        try:
            deps = [tuple(p) for p in scan.packages or [] if len(p) == 3]
            found += _vulnerable(db, "dependency", deps)  # type: ignore[arg-type]
            if scan.os_ecosystem:
                os_packages = [
                    (scan.os_ecosystem, p[0], p[1])
                    for p in scan.os_packages or []
                    if len(p) == 2
                ]
                found += _vulnerable(db, "os", os_packages)
            found += _eol_findings(db, app, scan)
        except osv.OsvError as failure:
            error = str(failure)[:300]
    if error:
        # Keep the last good findings rather than clearing them on an outage.
        scan.check_error = error
        db.commit()
        return
    _replace_findings(db, app_id, found)
    scan.checked_at, scan.check_error = _now(), None
    db.commit()


def _replace_findings(db: Session, app_id: str, found: list[dict[str, Any]]) -> None:
    old = {
        f.key: f
        for f in db.scalars(
            select(AppFinding).where(AppFinding.application_id == app_id)
        )
    }
    db.execute(delete(AppFinding).where(AppFinding.application_id == app_id))
    now = _now()
    unique = {f["key"]: f for f in found}
    for key, data in unique.items():
        before = old.get(key)
        db.add(
            AppFinding(
                id=new_id(),
                application_id=app_id,
                key=key[:300],
                kind=data["kind"],
                severity=data["severity"],
                title=str(data["title"])[:300],
                ecosystem=data.get("ecosystem"),
                package=(data.get("package") or "")[:214] or None,
                version=(data.get("version") or "")[:80] or None,
                fixed=(data.get("fixed") or "")[:80] or None,
                advisory=(data.get("advisory") or "")[:80] or None,
                aliases=data.get("aliases") or [],
                path=(data.get("path") or "")[:300] or None,
                eol_at=data.get("eol_at"),
                first_seen_at=before.first_seen_at if before else now,
                ignored_at=before.ignored_at if before else None,
                ignored_by=before.ignored_by if before else None,
            )
        )


# ---------------------------------------------------------------------------
# Scheduling (alert loop) and deploy hook
# ---------------------------------------------------------------------------


def run_due(db: Session) -> None:
    """Re-check stored scans daily; scan apps that never were."""
    now = _now()
    if lookups_enabled(db):
        stale = db.scalars(
            select(AppScan.application_id).where(
                (AppScan.checked_at.is_(None)) | (AppScan.checked_at < now - RECHECK)
            )
        ).all()
        for app_id in [a for a in stale if a not in _running][:CHECKS_PER_TICK]:
            _queue_check(app_id)
    scanned = set(db.scalars(select(AppScan.application_id)))
    waiting: dict[str, list[Application]] = {}
    for app in db.scalars(
        select(Application).where(Application.current_deployment_id.is_not(None))
    ):
        if app.id not in scanned:
            waiting.setdefault(app.server_id, []).append(app)
    for server_id, apps in waiting.items():
        server = db.get(Server, server_id)
        if server is None or not jobs._agent_at_least(server, NEEDS_AGENT):
            continue
        recent = db.scalar(
            select(Job.id).where(
                Job.server_id == server_id,
                Job.type == "apps.audit",
                Job.created_at > now - FIRST_SCAN_PAUSE,
            )
        )
        if recent is None:
            request_scan(db, server, apps)


def after_deploy(db: Session, job: Job) -> None:
    """Scan what was just released."""
    if job.type != "app.deploy" or job.status != "succeeded":
        return
    deployment = db.scalar(select(Deployment).where(Deployment.job_id == job.id))
    app = db.get(Application, deployment.application_id) if deployment else None
    server = db.get(Server, job.server_id)
    if app is not None and server is not None:
        request_scan(db, server, [app])


jobs.after_finished.append(after_deploy)


def rebuild_due(db: Session) -> None:
    """Apps with weekly rebuilds on: redeploy the live version once a week,
    so base images and OS packages pick up their security fixes."""
    from app.apps import service as apps_service

    now = _now()
    for app in db.scalars(
        select(Application).where(
            Application.auto_rebuild.is_(True),
            Application.current_deployment_id.is_not(None),
        )
    ):
        latest = db.scalar(
            select(Deployment)
            .where(Deployment.application_id == app.id)
            .order_by(Deployment.created_at.desc())
            .limit(1)
        )
        if latest is None or latest.status in ("queued", "running"):
            continue
        if now - _aware(latest.created_at) < REBUILD_EVERY:
            continue
        live = db.get(Deployment, app.current_deployment_id)
        ref = (live.commit_sha if app.source_type == "git" else None) if live else None
        try:
            apps_service.deploy(
                db, app, "system", "Weekly rebuild", trigger="rebuild", ref=ref
            )
        except Exception as error:  # noqa: BLE001 - try the others, again next week
            logger.warning("weekly rebuild of %s not started: %s", app.name, error)


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def findings(db: Session, app_id: str) -> list[AppFinding]:
    rows = list(
        db.scalars(select(AppFinding).where(AppFinding.application_id == app_id))
    )
    return sorted(
        rows,
        key=lambda f: (
            f.ignored_at is not None,
            SEVERITY_ORDER.get(f.severity, 9),
            f.fixed is None,
            f.package or "",
            f.title,
        ),
    )


def counts(rows: list[AppFinding]) -> dict[str, int]:
    out = {s: 0 for s in osv.SEVERITIES}
    for f in rows:
        if f.ignored_at is None:
            out[f.severity] = out.get(f.severity, 0) + 1
    return out


def set_ignored(
    db: Session, finding: AppFinding, ignored: bool, label: str
) -> AppFinding:
    finding.ignored_at = _now() if ignored else None
    finding.ignored_by = label[:64] if ignored else None
    db.commit()
    return finding


# ---------------------------------------------------------------------------
# Scanner noise (App logging errors)
# ---------------------------------------------------------------------------

# Error lines that internet-wide scanners cause, left out of the App logging
# errors count only while the app is safe from what they probe for.
# - No packages: the line itself says the probe was refused. nginx logs
#   "access forbidden by rule" when a deny rule blocked the request (/.git,
#   /.env...); an exposed file would be served without any error line.
# - Packages: the live deployment must use one of them and its last check
#   against OSV.dev must have found no advisory for any, even an ignored one.
#   Next.js logs "Server Reference ID did not match" for the fake Server
#   Action ids of React2Shell scans (CVE-2025-55182).
SCANNER_NOISE: tuple[tuple[str, frozenset[str]], ...] = (
    ("access forbidden by rule", frozenset()),
    (
        "server reference id did not match",
        frozenset({"next", "react-server-dom-webpack", "react-server-dom-turbopack"}),
    ),
)


def scanner_noise(db: Session, apps: list[Application]) -> dict[str, list[str]]:
    """Per app id, the scanner error lines it's safe from (see SCANNER_NOISE)."""
    ids = [a.id for a in apps]
    scans: dict[str, AppScan] = {}
    if ids and lookups_enabled(db):
        scans = {
            s.application_id: s
            for s in db.scalars(select(AppScan).where(AppScan.application_id.in_(ids)))
        }
    live = {
        d.id: d
        for d in db.scalars(
            select(Deployment).where(
                Deployment.id.in_(
                    [a.current_deployment_id for a in apps if a.id in scans]
                )
            )
        )
    }
    advised: dict[str, set[str]] = {}
    for app_id, package in db.execute(
        select(AppFinding.application_id, AppFinding.package).where(
            AppFinding.application_id.in_(list(scans)), AppFinding.kind == "dependency"
        )
    ):
        advised.setdefault(app_id, set()).add(package)
    out: dict[str, list[str]] = {}
    for app in apps:
        scan, deployment = scans.get(app.id), live.get(app.current_deployment_id or "")
        used: set[str] = set()
        # checked_at is cleared by every new scan, so it covers these packages;
        # the scan must also be of what's live, not of the version before.
        if (
            scan is not None
            and scan.checked_at is not None
            and deployment is not None
            and deployment.finished_at is not None
            and _aware(scan.scanned_at) >= _aware(deployment.finished_at)
        ):
            used = {p[1] for p in scan.packages or [] if len(p) == 3 and p[0] == "npm"}
        out[app.id] = [
            text
            for text, packages in SCANNER_NOISE
            if not packages
            or (packages & used and not packages & advised.get(app.id, set()))
        ]
    return out
