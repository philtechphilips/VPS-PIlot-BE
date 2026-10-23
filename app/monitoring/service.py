"""Alert rules and their evaluation.

Every ~30 s (see worker.py) each enabled rule is checked against its
targets. Metric rules average the samples over the rule's window, so a
single spike never alerts, and resolve only below threshold minus a small
hysteresis, so values hovering at the edge don't flap. Agent-offline uses
the heartbeat age; app-down uses the agent's container inventory and must
hold for the rule's duration. App-errors counts the error lines the agent
found in each app's logs. One open incident per rule and target.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.apps.models import Application
from app.core.config import settings
from app.core.security import new_id
from app.monitoring.models import Alert, AlertRule, MaintenanceWindow
from app.servers.models import MetricSample, Server

logger = logging.getLogger(__name__)

OPEN = ("pending", "firing", "acknowledged")
HYSTERESIS = 3.0  # percentage points below the threshold to resolve
INVENTORY_FRESH = timedelta(minutes=3)
# An app-errors alert resolves after this many windows without errors, so an
# app failing every few minutes stays one incident instead of many.
ERRORS_QUIET_WINDOWS = 3


@dataclass(frozen=True)
class Kind:
    label: str
    target: str  # server | application
    metric: str | None = None  # MetricSample column for percent rules
    threshold: float | None = None
    duration: int = 5
    severity: str = "warning"
    enabled: bool = True
    # What the threshold means: percent (metric rules and error rate), count
    # (error lines), days (certificates) or hours (backups).
    unit: str = "percent"


KINDS: dict[str, Kind] = {
    "agent_offline": Kind("Agent offline", "server", duration=5, severity="critical"),
    "cpu_high": Kind("CPU sustained high", "server", "cpu_percent", 90, 15),
    "memory_high": Kind("Memory pressure", "server", "memory_percent", 90, 10),
    "disk_high": Kind("Disk almost full", "server", "disk_percent", 85, 30),
    "inode_high": Kind("Inodes almost exhausted", "server", "inode_percent", 85, 30),
    "swap_high": Kind(
        "Heavy swapping", "server", "swap_percent", 80, 15, "info", False
    ),
    "app_down": Kind(
        "Application down", "application", duration=2, severity="critical"
    ),
    # threshold = pending security updates, for longer than the duration
    # (3 days: unattended-upgrades usually installs them overnight)
    "updates_pending": Kind(
        "Security updates pending", "server", threshold=1, duration=4320, unit="count"
    ),
    # threshold = error lines logged within the rule's duration
    "app_errors": Kind(
        "App logging errors", "application", threshold=1, duration=5, unit="count"
    ),
    # threshold = % of requests through the app's domains answered with 5xx
    "error_rate": Kind("High error rate", "application", threshold=5, duration=5),
    # Failing uptime checks for the rule's duration (see domains.uptime)
    "site_down": Kind("Site down", "domain", duration=2, severity="critical"),
    # threshold = days of validity left (Let's Encrypt domains only)
    "tls_expiring": Kind(
        "Certificate expiring", "domain", threshold=14, duration=0, unit="days"
    ),
    # threshold = hours since the last good backup (databases with a schedule)
    "backup_stale": Kind(
        "Backups stale or failing", "database", threshold=36, duration=0, unit="hours"
    ),
}


class RuleError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def ensure_default_rules(db: Session) -> None:
    """Create the built-in rules once (they can be edited or disabled)."""
    if db.scalar(select(func.count()).select_from(AlertRule)):
        return
    for kind, spec in KINDS.items():
        db.add(
            AlertRule(
                id=new_id(),
                kind=kind,
                name=spec.label,
                threshold=spec.threshold,
                duration_minutes=spec.duration,
                severity=spec.severity,
                enabled=spec.enabled,
                notify_email=True,
            )
        )
    db.commit()


def list_rules(db: Session) -> list[AlertRule]:
    ensure_default_rules(db)
    return list(
        db.scalars(select(AlertRule).order_by(AlertRule.created_at, AlertRule.name))
    )


def _check_threshold(spec: Kind, value: float | None) -> None:
    """Percentages stay under 100; days (certificates) and hours (backups)
    can be larger."""
    if value is None:
        return
    if spec.threshold is None:
        raise RuleError(422, "This rule has no threshold")
    if spec.unit == "percent" and not 0 < value < 100:
        raise RuleError(422, "A percentage threshold must be between 0 and 100")
    if spec.unit != "percent" and value < 1:
        raise RuleError(422, "The threshold must be at least 1")


def create_rule(db: Session, data: dict[str, Any]) -> AlertRule:
    spec = KINDS.get(data["kind"])
    if spec is None:
        raise RuleError(422, "Unknown rule type")
    _check_threshold(spec, data.get("threshold"))
    if spec.threshold is not None and data.get("threshold") is None:
        raise RuleError(422, "This rule needs a threshold")
    if data.get("server_id") and spec.target != "server":
        raise RuleError(422, "This rule applies to applications, not one server")
    if data.get("server_id") and db.get(Server, data["server_id"]) is None:
        raise RuleError(404, "Server not found")
    if data.get("application_id"):
        if spec.target != "application" and data["kind"] != "site_down":
            raise RuleError(422, "Only app rules can be limited to one app")
        if db.get(Application, data["application_id"]) is None:
            raise RuleError(404, "Application not found")
    rule = AlertRule(
        id=new_id(),
        kind=data["kind"],
        name=(data.get("name") or spec.label)[:100],
        threshold=data.get("threshold") if spec.threshold is not None else None,
        duration_minutes=data.get("duration_minutes") or spec.duration,
        severity=data.get("severity") or spec.severity,
        enabled=data.get("enabled", True),
        notify_email=data.get("notify_email", True),
        server_id=data.get("server_id"),
        application_id=data.get("application_id"),
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


def update_rule(db: Session, rule: AlertRule, data: dict[str, Any]) -> AlertRule:
    spec = KINDS[rule.kind]
    _check_threshold(spec, data.get("threshold"))
    for field in ("name", "duration_minutes", "severity", "enabled", "notify_email"):
        if data.get(field) is not None:
            setattr(rule, field, data[field])
    if (
        "threshold" in data
        and data["threshold"] is not None
        and spec.threshold is not None
    ):
        rule.threshold = data["threshold"]
    if not rule.enabled:
        # Disabling a rule closes its incidents quietly.
        for alert in _open_alerts(db, rule.id):
            alert.state, alert.resolved_at = "resolved", _now()
    db.commit()
    db.refresh(rule)
    return rule


# ---------------------------------------------------------------------------
# Conditions
# ---------------------------------------------------------------------------


@dataclass
class Check:
    # True: condition holds, False: clearly fine, None: not enough data
    breached: bool | None
    value: float | None = None
    detail: str | None = None


def _check_offline(rule: AlertRule, server: Server, now: datetime) -> Check:
    seen = server.last_heartbeat_at or server.enrolled_at
    if seen is None:
        return Check(None)
    minutes = (now - _aware(seen)).total_seconds() / 60
    if minutes > rule.duration_minutes:
        return Check(True, round(minutes, 1), f"No heartbeat for {int(minutes)} min")
    return Check(False, round(minutes, 1))


def _check_metric(db: Session, rule: AlertRule, server: Server, now: datetime) -> Check:
    column = getattr(MetricSample, KINDS[rule.kind].metric)  # type: ignore[arg-type]
    since = now - timedelta(minutes=rule.duration_minutes)
    avg, count = db.execute(
        select(func.avg(column), func.count(column)).where(
            MetricSample.server_id == server.id, MetricSample.ts >= since
        )
    ).one()
    expected = rule.duration_minutes * 60 / max(settings.agent_metrics_seconds, 1)
    if avg is None or count < max(2, expected * 0.5):
        return Check(None)  # too few samples (e.g. agent offline): don't guess
    avg = float(avg)
    label = KINDS[rule.kind].label.split()[0]
    detail = (
        f"{label} averaged {avg:.0f}% over {rule.duration_minutes} min "
        f"(limit {rule.threshold:.0f}%)"
    )
    if avg > rule.threshold:
        return Check(True, round(avg, 1), detail)
    if avg <= rule.threshold - HYSTERESIS:
        return Check(False, round(avg, 1), detail)
    return Check(None, round(avg, 1), detail)


def _scheduled_databases(db: Session) -> list[tuple[str, str, Any]]:
    """Targets of the backup rule: databases and apps with a schedule."""
    from app.backups.models import BackupPolicy
    from app.databases.models import DatabaseInstance

    out = []
    for policy in db.scalars(
        select(BackupPolicy).where(BackupPolicy.enabled.is_(True))
    ):
        if policy.application_id:
            app = db.get(Application, policy.application_id)
            if app is not None:
                out.append((app.id, f"{app.name} (files)", policy))
            continue
        instance = db.get(DatabaseInstance, policy.instance_id)
        if instance is not None:
            out.append((instance.id, instance.name, policy))
    return out


def _check_backups(db: Session, rule: AlertRule, policy, now: datetime) -> Check:
    from app.backups.models import BackupRun

    owner = (
        BackupRun.application_id == policy.application_id
        if policy.application_id
        else BackupRun.instance_id == policy.instance_id
    )
    latest = db.scalar(
        select(BackupRun)
        .where(
            owner,
            BackupRun.status.in_(("succeeded", "failed")),
        )
        .order_by(BackupRun.created_at.desc())
        .limit(1)
    )
    good = db.scalar(
        select(BackupRun.finished_at)
        .where(owner, BackupRun.status == "succeeded")
        .order_by(BackupRun.created_at.desc())
        .limit(1)
    )
    if latest is not None and latest.status == "failed":
        return Check(
            True, None, f"The last backup failed: {latest.error or 'unknown error'}"
        )
    if good is None:
        age = (now - _aware(policy.created_at)).total_seconds() / 3600
        if age > rule.threshold:
            return Check(
                True,
                None,
                f"No successful backup yet ({int(age)} h since the schedule started)",
            )
        return Check(None)
    hours = (now - _aware(good)).total_seconds() / 3600
    detail = f"Last good backup {int(hours)} h ago (limit {rule.threshold:.0f} h)"
    return Check(hours > rule.threshold, round(hours, 1), detail)


def _check_site(db: Session, rule: AlertRule, domain, now: datetime) -> Check:
    from app.domains.models import UptimeCheck

    latest = db.scalar(
        select(UptimeCheck)
        .where(UptimeCheck.domain_id == domain.id)
        .order_by(UptimeCheck.ts.desc())
        .limit(1)
    )
    if latest is None or now - _aware(latest.ts) > timedelta(minutes=5):
        return Check(None)  # not checked lately (control plane just started)
    if latest.ok:
        return Check(False, latest.ms, f"Up again ({latest.status_code})")
    last_ok = db.scalar(
        select(func.max(UptimeCheck.ts)).where(
            UptimeCheck.domain_id == domain.id, UptimeCheck.ok.is_(True)
        )
    )
    first_fail = db.scalar(
        select(func.min(UptimeCheck.ts)).where(
            UptimeCheck.domain_id == domain.id,
            UptimeCheck.ok.is_(False),
            *([UptimeCheck.ts > last_ok] if last_ok else []),
        )
    )
    minutes = (now - _aware(first_fail)).total_seconds() / 60
    reason = latest.error or f"HTTP {latest.status_code}"
    detail = f"{reason} for {max(1, round(minutes))} min"
    if minutes >= rule.duration_minutes:
        return Check(True, None, detail)
    return Check(None, None, detail)


def _check_certificate(rule: AlertRule, domain, now: datetime) -> Check:
    if domain.cert_expires_at is None:
        return Check(None)
    days = (_aware(domain.cert_expires_at) - now).total_seconds() / 86400
    issuer = domain.cert_issuer or "unknown issuer"
    detail = f"Certificate expires in {max(0, int(days))} days ({issuer})"
    if days < rule.threshold:
        return Check(True, round(days, 1), detail)
    return Check(False, round(days, 1), detail)


def _check_errors(
    db: Session, rule: AlertRule, app: Application, now: datetime
) -> Check:
    from app.apps import service as apps

    window = timedelta(minutes=max(rule.duration_minutes, 1))
    count, latest = apps.recent_errors(db, app.id, now - window)
    if count >= rule.threshold:
        lines = "error line" if count == 1 else "error lines"
        detail = f"{count} {lines} in {rule.duration_minutes} min"
        if latest:
            detail += f". Latest: {latest[:200]}"
        return Check(True, float(count), detail)
    quiet, _ = apps.recent_errors(db, app.id, now - window * ERRORS_QUIET_WINDOWS)
    if quiet == 0:
        return Check(False, 0.0, "No errors logged")
    return Check(None, float(count))


ERROR_RATE_MIN_REQUESTS = 20  # fewer requests in the window: too few to judge


def _check_error_rate(
    db: Session, rule: AlertRule, app: Application, now: datetime
) -> Check:
    from app.apps.models import RequestMetric

    since = (now - timedelta(minutes=max(rule.duration_minutes, 1))).replace(
        second=0, microsecond=0
    )
    requests, errors = db.execute(
        select(
            func.coalesce(func.sum(RequestMetric.requests), 0),
            func.coalesce(func.sum(RequestMetric.s5xx), 0),
        ).where(RequestMetric.application_id == app.id, RequestMetric.minute >= since)
    ).one()
    if requests < ERROR_RATE_MIN_REQUESTS:
        return Check(False if not errors else None)
    rate = 100 * errors / requests
    detail = (
        f"{rate:.1f}% of {requests} requests failed with 5xx in "
        f"{rule.duration_minutes} min (limit {rule.threshold:g}%)"
    )
    if rate > rule.threshold:
        return Check(True, round(rate, 2), detail)
    if rate <= max(rule.threshold - HYSTERESIS, rule.threshold / 2):
        return Check(False, round(rate, 2), detail)
    return Check(None, round(rate, 2), detail)


def _check_updates(rule: AlertRule, server: Server, now: datetime) -> Check:
    updates = (server.inventory or {}).get("updates")
    if not updates or server.inventory_at is None:
        return Check(None)  # older agent, or not apt-based
    count = int(updates.get("security") or 0)
    detail = (
        f"{count} security update{'s' if count != 1 else ''} pending "
        f"({updates.get('total', count)} in all)"
        + ("; a reboot is required" if updates.get("reboot_required") else "")
    )
    return Check(count >= rule.threshold, float(count), detail)


def _check_app(app: Application, server: Server | None, now: datetime) -> Check:
    if server is None or app.current_deployment_id is None:
        return Check(None)  # never released: nothing should be running yet
    if (
        server.inventory_at is None
        or now - _aware(server.inventory_at) > INVENTORY_FRESH
    ):
        return Check(None)  # server offline: the offline rule covers it
    inventory = server.inventory or {}
    if app.runtime == "systemd":
        unit = next(
            (
                s
                for s in inventory.get("services") or []
                if s.get("name") == f"vp-{app.name}.service"
            ),
            None,
        )
        if unit is None:
            return Check(True, None, "The app's systemd service is missing")
        if unit.get("active") != "active":
            return Check(
                True, None, f"Service is {unit.get('active')} ({unit.get('sub')})"
            )
        return Check(False)
    name = f"vp-{app.name}"
    if app.runtime == "compose":
        name = f"vp-{app.name}-{app.compose_service}-1"
    containers = inventory.get("containers") or []
    container = next((c for c in containers if c.get("name") == name), None)
    if container is None:
        return Check(True, None, "The app's container is missing")
    if str(container.get("state")) != "running":
        return Check(
            True,
            None,
            f"Container is {container.get('state')}: "
            f"{container.get('status') or ''}".strip(),
        )
    return Check(False)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _open_alerts(db: Session, rule_id: str) -> list[Alert]:
    return list(
        db.scalars(select(Alert).where(Alert.rule_id == rule_id, Alert.state.in_(OPEN)))
    )


@dataclass
class Paused:
    """What active maintenance windows cover."""

    everything: bool = False
    servers: frozenset[str] = frozenset()
    apps: frozenset[str] = frozenset()

    def covers(self, target: Any) -> bool:
        if self.everything:
            return True
        server = getattr(target, "server_id", None)
        app = getattr(target, "application_id", None)
        if isinstance(target, Server):
            server = target.id
        elif isinstance(target, Application):
            app = target.id
        return (server in self.servers) or (app in self.apps)


def _paused(db: Session, now: datetime) -> Paused:
    windows = list(
        db.scalars(
            select(MaintenanceWindow).where(
                MaintenanceWindow.starts_at <= now, MaintenanceWindow.ends_at > now
            )
        )
    )
    return Paused(
        everything=any(not w.server_id and not w.application_id for w in windows),
        servers=frozenset(w.server_id for w in windows if w.server_id),
        apps=frozenset(w.application_id for w in windows if w.application_id),
    )


def _scope(db: Session, target: Any) -> Any:
    """Something with server_id/application_id for a rule target (database
    backup policies carry neither)."""
    from app.backups.models import BackupPolicy
    from app.databases.models import DatabaseInstance

    if isinstance(target, BackupPolicy):
        if target.application_id:
            return db.get(Application, target.application_id)
        return db.get(DatabaseInstance, target.instance_id)
    return target


def evaluate(db: Session, now: datetime | None = None) -> dict[str, int]:
    """Check every enabled rule once. Returns counts of transitions."""
    from app.notifications import service as notifications

    now = now or _now()
    ensure_default_rules(db)
    counts = {"fired": 0, "resolved": 0}
    servers = list(
        db.scalars(
            select(Server).where(
                Server.enrolled_at.is_not(None), Server.revoked_at.is_(None)
            )
        )
    )
    by_id = {s.id: s for s in servers}
    apps = list(db.scalars(select(Application)))
    from app.domains.models import Domain

    certs = list(db.scalars(select(Domain).where(Domain.tls_mode == "auto")))
    paused = _paused(db, now)

    for rule in db.scalars(select(AlertRule).where(AlertRule.enabled.is_(True))):
        spec = KINDS.get(rule.kind)
        if spec is None:
            continue
        open_by_target = {a.target_id: a for a in _open_alerts(db, rule.id)}
        if rule.kind == "site_down":
            from app.domains import uptime

            targets = [(d.id, d.hostname, d) for d, _ in uptime.watched(db)]
        elif spec.target == "domain":
            targets = [(d.id, d.hostname, d) for d in certs]
        elif spec.target == "database":
            targets = _scheduled_databases(db)
        elif spec.target == "server":
            targets = [
                (s.id, s.name, s)
                for s in servers
                if not rule.server_id or s.id == rule.server_id
            ]
        else:
            targets = [
                (
                    a.id,
                    f"{a.name} on {by_id[a.server_id].name}"
                    if a.server_id in by_id
                    else a.name,
                    a,
                )
                for a in apps
            ]
        if rule.application_id:
            # A rule for one app: its own record, or its domains.
            targets = [
                t
                for t in targets
                if t[0] == rule.application_id
                or getattr(t[2], "application_id", None) == rule.application_id
            ]
        seen = set()
        for target_id, label, target in targets:
            seen.add(target_id)
            if rule.kind == "agent_offline":
                check = _check_offline(rule, target, now)
            elif rule.kind == "tls_expiring":
                check = _check_certificate(rule, target, now)
            elif rule.kind == "updates_pending":
                check = _check_updates(rule, target, now)
            elif rule.kind == "site_down":
                check = _check_site(db, rule, target, now)
            elif rule.kind == "backup_stale":
                check = _check_backups(db, rule, target, now)
            elif rule.kind == "app_errors":
                check = _check_errors(db, rule, target, now)
            elif rule.kind == "error_rate":
                check = _check_error_rate(db, rule, target, now)
            elif spec.metric:
                check = _check_metric(db, rule, target, now)
            else:
                check = _check_app(target, by_id.get(target.server_id), now)
            alert = open_by_target.get(target_id)
            quiet = paused.covers(_scope(db, target))
            if check.breached is True:
                if alert is None and quiet:
                    continue  # maintenance: don't open incidents
                if alert is None:
                    # Offline and metric rules already waited out their window.
                    wait = rule.kind in ("app_down", "updates_pending")
                    alert = Alert(
                        id=new_id(),
                        rule_id=rule.id,
                        # App file backups share the backup rule but link to the app.
                        target_type="application"
                        if getattr(target, "application_id", None)
                        else spec.target,
                        target_id=target_id,
                        target_label=label[:120],
                        severity=rule.severity,
                        title=rule.name,
                        state="pending" if wait else "firing",
                        started_at=now,
                        fired_at=None if wait else now,
                        updated_at=now,
                    )
                    db.add(alert)
                    if not wait:
                        counts["fired"] += 1
                        _announce(db, notifications, rule, alert, check, True, now)
                elif alert.state == "pending" and now - _aware(
                    alert.started_at
                ) >= timedelta(minutes=rule.duration_minutes):
                    if quiet:
                        continue  # fires once the maintenance window is over
                    alert.state, alert.fired_at = "firing", now
                    counts["fired"] += 1
                    _announce(db, notifications, rule, alert, check, True, now)
                alert.value, alert.detail, alert.updated_at = (
                    check.value,
                    (check.detail or "")[:300] or None,
                    now,
                )
            elif check.breached is False and alert is not None:
                if alert.state == "pending":
                    db.delete(alert)
                else:
                    alert.state, alert.resolved_at, alert.updated_at = (
                        "resolved",
                        now,
                        now,
                    )
                    alert.value = check.value
                    counts["resolved"] += 1
                    if not quiet:
                        _announce(db, notifications, rule, alert, check, False, now)
        # Targets that no longer exist (server or app removed).
        for target_id, alert in open_by_target.items():
            if target_id not in seen:
                alert.state, alert.resolved_at, alert.updated_at = "resolved", now, now
    db.commit()
    return counts


def _announce(
    db,
    notifications,
    rule: AlertRule,
    alert: Alert,
    check: Check,
    firing: bool,
    now: datetime,
) -> None:
    if alert.snoozed_until and _aware(alert.snoozed_until) > now:
        return  # snoozed: the incident is still tracked, just quiet
    notifications.alert_changed(
        db,
        firing=firing,
        severity=rule.severity,
        title=f"{rule.name}: {alert.target_label}",
        detail=check.detail,
        email=rule.notify_email,
        started_at=alert.started_at,
    )


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------


def list_alerts(db: Session, state: str = "open", limit: int = 100) -> list[Alert]:
    query = select(Alert).where(Alert.state != "pending")
    if state == "open":
        query = query.where(Alert.state.in_(("firing", "acknowledged")))
    elif state == "resolved":
        query = query.where(Alert.state == "resolved")
    return list(
        db.scalars(query.order_by(Alert.started_at.desc(), Alert.id).limit(limit))
    )


def snooze(db: Session, alert: Alert, minutes: int | None) -> Alert:
    """Hold back this incident's notifications (None: wake it up again)."""
    if alert.state not in ("firing", "acknowledged", "pending"):
        raise RuleError(409, "Only open alerts can be snoozed")
    alert.snoozed_until = _now() + timedelta(minutes=minutes) if minutes else None
    alert.updated_at = _now()
    db.commit()
    return alert


def list_maintenance(db: Session) -> list[MaintenanceWindow]:
    """Current and upcoming windows."""
    return list(
        db.scalars(
            select(MaintenanceWindow)
            .where(MaintenanceWindow.ends_at > _now())
            .order_by(MaintenanceWindow.starts_at)
        )
    )


def start_maintenance(
    db: Session, data: dict[str, Any], label: str
) -> MaintenanceWindow:
    if data.get("server_id") and data.get("application_id"):
        raise RuleError(422, "Pick a server or an app, not both")
    if data.get("server_id") and db.get(Server, data["server_id"]) is None:
        raise RuleError(404, "Server not found")
    if (
        data.get("application_id")
        and db.get(Application, data["application_id"]) is None
    ):
        raise RuleError(404, "Application not found")
    starts = data.get("starts_at") or _now()
    window = MaintenanceWindow(
        id=new_id(),
        server_id=data.get("server_id"),
        application_id=data.get("application_id"),
        starts_at=starts,
        ends_at=_aware(starts) + timedelta(minutes=data["minutes"]),
        reason=(data.get("reason") or "")[:200] or None,
        created_by=label[:64],
    )
    db.add(window)
    db.commit()
    db.refresh(window)
    return window


def end_maintenance(db: Session, window: MaintenanceWindow) -> None:
    window.ends_at = _now()
    db.commit()


def acknowledge(db: Session, alert: Alert, label: str) -> Alert:
    if alert.state != "firing":
        raise RuleError(409, "Only firing alerts can be acknowledged")
    alert.state, alert.acknowledged_at, alert.acknowledged_by = (
        "acknowledged",
        _now(),
        label[:64],
    )
    alert.updated_at = _now()
    db.commit()
    return alert
