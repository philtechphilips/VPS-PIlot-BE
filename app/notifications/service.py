"""In-app notifications and email alerts for deployments."""

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.email import EmailDeliveryError
from app.core.security import new_id
from app.notifications import emails
from app.notifications.models import Notification, NotificationSettings
from app.users.models import Role, User

logger = logging.getLogger(__name__)

RETENTION_DAYS = 90
_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="notify")


def _background(fn, *args) -> None:
    """Emails go out off the request path (the agent is waiting on it).
    Tests replace this to run inline."""
    _pool.submit(fn, *args)


def _now() -> datetime:
    return datetime.now(UTC)


def get_settings(db: Session, user_id: int) -> NotificationSettings:
    prefs = db.get(NotificationSettings, user_id)
    if prefs is None:
        prefs = NotificationSettings(
            user_id=user_id,
            email_deploy_success=True,
            email_deploy_failure=True,
            email_alerts=True,
        )
        db.add(prefs)
        db.flush()
    return prefs


def update_settings(
    db: Session, user_id: int, data: dict[str, bool]
) -> NotificationSettings:
    prefs = get_settings(db, user_id)
    for key in ("email_deploy_success", "email_deploy_failure", "email_alerts"):
        if key in data and data[key] is not None:
            setattr(prefs, key, bool(data[key]))
    db.commit()
    return prefs


def _recipients(db: Session) -> list[User]:
    return list(db.scalars(select(User).where(User.role == Role.ADMIN)))


def notify(
    db: Session,
    kind: str,
    level: str,
    title: str,
    body: str | None = None,
    link: str | None = None,
) -> list[User]:
    """Add an inbox item for every admin. Committed with the caller's session."""
    users = _recipients(db)
    for user in users:
        db.add(
            Notification(
                id=new_id(),
                user_id=user.id,
                kind=kind,
                level=level,
                title=title[:200],
                body=(body or "")[:500] or None,
                link=link,
                created_at=_now(),
            )
        )
    db.execute(
        delete(Notification).where(
            Notification.created_at < _now() - timedelta(days=RETENTION_DAYS)
        )
    )
    return users


def _send(to: str, data: dict[str, Any]) -> None:
    try:
        emails.send_deployment_email(to, data)
    except EmailDeliveryError as error:
        logger.warning("Deployment email to %s not sent: %s", to, error)
    except Exception:  # noqa: BLE001 - never let an email kill the worker
        logger.exception("Deployment email to %s failed", to)


def _duration(start: datetime | None, end: datetime | None) -> str:
    if not start or not end:
        return ""
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    seconds = max(0, int((end - start).total_seconds()))
    return f"{seconds // 60}m {seconds % 60}s" if seconds >= 60 else f"{seconds}s"


def deployment_finished(db: Session, deployment, app, server) -> None:
    """Called when a deployment succeeds or fails (not when canceled)."""
    ok = deployment.status == "succeeded"
    sha = (deployment.commit_sha or "")[:7]
    link = f"/dashboard/deployments/{deployment.id}"
    if ok:
        title = f"{app.name} deployed to {server.name if server else 'its server'}"
        body = (
            f"{sha} {deployment.commit_message or ''}".strip() or deployment.image_ref
        )
    else:
        title = f"{app.name} deployment failed"
        body = deployment.error
    users = notify(
        db,
        "deployment.succeeded" if ok else "deployment.failed",
        "ok" if ok else "err",
        title,
        body,
        link,
    )

    ip = (server.ip_addresses or [None])[0] if server else None
    data = {
        "status": deployment.status,
        "app": app.name,
        "server": server.name if server else "",
        "address": f"http://{ip}:{app.host_port}" if ip else "",
        "source": (
            f"{app.github_repo_full_name or app.repo_url} @ {deployment.requested_ref}"
            if app.source_type == "git" and deployment.trigger != "rollback"
            else deployment.image_ref or deployment.requested_ref or ""
        ),
        "commit_sha": deployment.commit_sha,
        "commit_message": deployment.commit_message,
        "build_plan": (deployment.spec or {}).get("build_plan"),
        "duration": _duration(deployment.created_at, deployment.finished_at),
        "created_by": deployment.created_by,
        "error": deployment.error,
        "had_previous": bool(
            app.current_deployment_id and app.current_deployment_id != deployment.id
        ),
        "url": f"{settings.frontend_url.rstrip('/')}{link}",
    }
    from app.notifications import channels

    channels.dispatch(
        db,
        "deployment.succeeded" if ok else "deployment.failed",
        {
            "title": title,
            "detail": body,
            "app": app.name,
            "server": data["server"],
            "commit_sha": deployment.commit_sha,
            "deployment_id": deployment.id,
            "url": data["url"],
        },
    )
    for user in users:
        prefs = get_settings(db, user.id)
        if (ok and prefs.email_deploy_success) or (
            not ok and prefs.email_deploy_failure
        ):
            _background(_send, user.email, data)


def list_for(
    db: Session, user_id: int, limit: int = 30
) -> tuple[list[Notification], int]:
    items = list(
        db.scalars(
            select(Notification)
            .where(Notification.user_id == user_id)
            .order_by(Notification.created_at.desc(), Notification.id)
            .limit(limit)
        )
    )
    unread = db.scalar(
        select(func.count())
        .select_from(Notification)
        .where(Notification.user_id == user_id, Notification.read_at.is_(None))
    )
    return items, unread or 0


def mark_read(db: Session, user_id: int, ids: list[str] | None) -> None:
    query = update(Notification).where(
        Notification.user_id == user_id, Notification.read_at.is_(None)
    )
    if ids is not None:
        query = query.where(Notification.id.in_(ids))
    db.execute(query.values(read_at=_now()))
    db.commit()


def _send_alert(to: str, data: dict[str, Any]) -> None:
    try:
        emails.send_alert_email(to, data)
    except EmailDeliveryError as error:
        logger.warning("Alert email to %s not sent: %s", to, error)
    except Exception:  # noqa: BLE001
        logger.exception("Alert email to %s failed", to)


def alert_changed(
    db: Session,
    *,
    firing: bool,
    severity: str,
    title: str,
    detail: str | None,
    email: bool,
    started_at: datetime,
) -> None:
    """An alert fired or resolved: inbox for every admin, email if wanted."""
    level = (
        (
            "err"
            if severity == "critical"
            else "warn"
            if severity == "warning"
            else "info"
        )
        if firing
        else "ok"
    )
    users = notify(
        db,
        "alert.firing" if firing else "alert.resolved",
        level,
        title if firing else f"Resolved: {title}",
        detail,
        "/dashboard/monitoring",
    )
    from app.notifications import channels

    channels.dispatch(
        db,
        "alert.firing" if firing else "alert.resolved",
        {
            "title": title if firing else f"Resolved: {title}",
            "detail": detail,
            "severity": severity,
            "started_at": started_at,
            "url": f"{settings.frontend_url.rstrip('/')}/dashboard/monitoring",
        },
    )
    if not email:
        return
    data = {
        "firing": firing,
        "severity": severity,
        "title": title,
        "detail": detail or "",
        "duration": _duration(started_at, _now()),
        "url": f"{settings.frontend_url.rstrip('/')}/dashboard/monitoring",
    }
    for user in users:
        if get_settings(db, user.id).email_alerts:
            _background(_send_alert, user.email, data)
