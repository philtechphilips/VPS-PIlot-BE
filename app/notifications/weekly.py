"""The weekly report: Monday 08:00 in the chosen timezone, a summary of the
last seven days. Sent to the inbox, by email to admins who keep it on, and
to alert channels subscribed to report.weekly (e.g. Telegram).
"""

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.core import cron

SEND_HOUR = 8


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def build(db: Session, now: datetime | None = None) -> dict[str, Any]:
    """Sections of (heading, lines) for the week before `now`."""
    from app.apps.models import AppErrorMetric, Application, Deployment
    from app.backups.models import BackupRun
    from app.domains.models import Domain, UptimeCheck
    from app.monitoring.models import Alert
    from app.servers.models import MetricRollup, MetricSample, Server

    now = now or datetime.now(UTC)
    since = now - timedelta(days=7)
    sections: list[tuple[str, list[str]]] = []

    rows = db.execute(
        select(
            UptimeCheck.domain_id,
            func.count(),
            func.sum(case((UptimeCheck.ok, 1), else_=0)),
        )
        .where(UptimeCheck.ts >= since)
        .group_by(UptimeCheck.domain_id)
    ).all()
    uptime = []
    for domain_id, total, up in rows:
        domain = db.get(Domain, domain_id)
        if domain is not None and total:
            uptime.append((100 * (up or 0) / total, domain.hostname))
    if uptime:
        uptime.sort()
        sections.append(("Uptime", [f"{host}: {pct:.2f}%" for pct, host in uptime[:8]]))

    deploys = Counter(
        status
        for (status,) in db.execute(
            select(Deployment.status).where(Deployment.created_at >= since)
        )
    )
    if deploys:
        line = (
            f"{sum(deploys.values())} deploys: {deploys.get('succeeded', 0)} succeeded"
        )
        if deploys.get("failed"):
            line += f", {deploys['failed']} failed"
        sections.append(("Deploys", [line]))

    fired = Counter(
        f"{title}: {label}"
        for title, label in db.execute(
            select(Alert.title, Alert.target_label).where(
                Alert.fired_at.is_not(None), Alert.fired_at >= since
            )
        )
    )
    sections.append(
        (
            "Alerts",
            [f"{n}× {what}" for what, n in fired.most_common(6)]
            or ["None fired. A quiet week."],
        )
    )

    errors = db.execute(
        select(AppErrorMetric.application_id, func.sum(AppErrorMetric.errors))
        .where(AppErrorMetric.minute >= since)
        .group_by(AppErrorMetric.application_id)
        .order_by(func.sum(AppErrorMetric.errors).desc())
        .limit(6)
    ).all()
    if errors:
        lines = []
        for app_id, count in errors:
            app = db.get(Application, app_id)
            lines.append(f"{app.name if app else 'an app'}: {count} error lines")
        sections.append(("App errors", lines))

    backups = Counter(
        status
        for (status,) in db.execute(
            select(BackupRun.status).where(BackupRun.created_at >= since)
        )
    )
    if backups:
        line = f"{backups.get('succeeded', 0)} succeeded"
        if backups.get("failed"):
            line += f", {backups['failed']} failed"
        sections.append(("Backups", [line]))

    servers = list(
        db.scalars(
            select(Server).where(
                Server.enrolled_at.is_not(None), Server.revoked_at.is_(None)
            )
        )
    )
    disk_lines, update_lines = [], []
    for server in servers:
        latest = db.scalar(
            select(MetricSample.disk_percent)
            .where(MetricSample.server_id == server.id)
            .order_by(MetricSample.ts.desc())
            .limit(1)
        )
        before = db.scalar(
            select(MetricRollup.disk_percent)
            .where(MetricRollup.server_id == server.id, MetricRollup.hour <= since)
            .order_by(MetricRollup.hour.desc())
            .limit(1)
        )
        if latest is not None:
            change = (
                f" ({latest - before:+.0f} pts this week)" if before is not None else ""
            )
            disk_lines.append(f"{server.name}: {latest:.0f}% used{change}")
        updates = (server.inventory or {}).get("updates") or {}
        if updates.get("security") or updates.get("reboot_required"):
            parts = []
            if updates.get("security"):
                parts.append(f"{updates['security']} security updates pending")
            if updates.get("reboot_required"):
                parts.append("reboot needed")
            update_lines.append(f"{server.name}: {', '.join(parts)}")
    if disk_lines:
        sections.append(("Disk", disk_lines))
    if update_lines:
        sections.append(("Updates", update_lines))

    start = (now - timedelta(days=7)).strftime("%b %d")
    return {
        "title": f"Your week on VPSPilot ({start} to {now.strftime('%b %d')})",
        "sections": sections,
    }


def as_text(report: dict[str, Any]) -> str:
    return "\n\n".join(
        f"{heading}\n" + "\n".join(f"• {line}" for line in lines)
        for heading, lines in report["sections"]
    )


def send(db: Session, now: datetime | None = None) -> dict[str, Any]:
    from app.core.config import settings
    from app.notifications import channels
    from app.notifications import service as notifications

    report = build(db, now)
    text = as_text(report)
    url = f"{settings.frontend_url.rstrip('/')}/dashboard"
    users = notifications.notify(
        db, "report.weekly", "info", report["title"], text, "/dashboard"
    )
    channels.dispatch(
        db, "report.weekly", {"title": report["title"], "detail": text, "url": url}
    )
    for user in users:
        if notifications.get_settings(db, user.id).email_weekly:
            notifications._background(
                notifications._send_report, user.email, report, url
            )
    db.commit()
    return report


def run_due(db: Session, now: datetime | None = None) -> bool:
    """Called by the background loop: send once a week, Monday morning."""
    from app.platform import service as platform

    row = platform.get(db)
    if not row.weekly_report:
        return False
    now = now or datetime.now(UTC)
    zone = cron.timezone(row.report_timezone or "UTC")
    local = now.astimezone(zone)
    monday = (local - timedelta(days=local.weekday())).replace(
        hour=SEND_HOUR, minute=0, second=0, microsecond=0
    )
    if local < monday:
        monday -= timedelta(days=7)
    if row.weekly_report_at is None:
        # Just turned on (or a fresh install): start with next Monday.
        row.weekly_report_at = now
        db.commit()
        return False
    if _aware(row.weekly_report_at) >= monday.astimezone(UTC):
        return False
    row.weekly_report_at = now
    db.commit()
    send(db, now)
    return True
