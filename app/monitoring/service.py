"""Alert rules and their evaluation.

Every ~30 s (see worker.py) each enabled rule is checked against its
targets. Metric rules average the samples over the rule's window, so a
single spike never alerts, and resolve only below threshold minus a small
hysteresis, so values hovering at the edge don't flap. Agent-offline uses
the heartbeat age; app-down uses the agent's container inventory and must
hold for the rule's duration. One open incident per rule and target.
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
from app.monitoring.models import Alert, AlertRule
from app.servers.models import MetricSample, Server

logger = logging.getLogger(__name__)

OPEN = ("pending", "firing", "acknowledged")
HYSTERESIS = 3.0  # percentage points below the threshold to resolve
INVENTORY_FRESH = timedelta(minutes=3)


@dataclass(frozen=True)
class Kind:
    label: str
    target: str  # server | application
    metric: str | None = None  # MetricSample column for percent rules
    threshold: float | None = None
    duration: int = 5
    severity: str = "warning"
    enabled: bool = True


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
    # threshold = days of validity left (Let's Encrypt domains only)
    "tls_expiring": Kind("Certificate expiring", "domain", threshold=14, duration=0),
    # threshold = hours since the last good backup (databases with a schedule)
    "backup_stale": Kind(
        "Backups stale or failing", "database", threshold=36, duration=0
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


def create_rule(db: Session, data: dict[str, Any]) -> AlertRule:
    spec = KINDS.get(data["kind"])
    if spec is None:
        raise RuleError(422, "Unknown rule type")
    if spec.threshold is not None and data.get("threshold") is None:
        raise RuleError(422, "This rule needs a threshold")
    if data.get("server_id") and spec.target != "server":
        raise RuleError(422, "This rule applies to applications, not one server")
    if data.get("server_id") and db.get(Server, data["server_id"]) is None:
        raise RuleError(404, "Server not found")
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
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


def update_rule(db: Session, rule: AlertRule, data: dict[str, Any]) -> AlertRule:
    spec = KINDS[rule.kind]
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
    from app.backups.models import BackupPolicy
    from app.databases.models import DatabaseInstance

    out = []
    for policy in db.scalars(
        select(BackupPolicy).where(BackupPolicy.enabled.is_(True))
    ):
        instance = db.get(DatabaseInstance, policy.instance_id)
        if instance is not None:
            out.append((instance.id, instance.name, policy))
    return out


def _check_backups(db: Session, rule: AlertRule, policy, now: datetime) -> Check:
    from app.backups.models import BackupRun

    latest = db.scalar(
        select(BackupRun)
        .where(
            BackupRun.instance_id == policy.instance_id,
            BackupRun.status.in_(("succeeded", "failed")),
        )
        .order_by(BackupRun.created_at.desc())
        .limit(1)
    )
    good = db.scalar(
        select(BackupRun.finished_at)
        .where(
            BackupRun.instance_id == policy.instance_id, BackupRun.status == "succeeded"
        )
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


def _check_certificate(rule: AlertRule, domain, now: datetime) -> Check:
    if domain.cert_expires_at is None:
        return Check(None)
    days = (_aware(domain.cert_expires_at) - now).total_seconds() / 86400
    issuer = domain.cert_issuer or "unknown issuer"
    detail = f"Certificate expires in {max(0, int(days))} days ({issuer})"
    if days < rule.threshold:
        return Check(True, round(days, 1), detail)
    return Check(False, round(days, 1), detail)


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

    for rule in db.scalars(select(AlertRule).where(AlertRule.enabled.is_(True))):
        spec = KINDS.get(rule.kind)
        if spec is None:
            continue
        open_by_target = {a.target_id: a for a in _open_alerts(db, rule.id)}
        if spec.target == "domain":
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
        seen = set()
        for target_id, label, target in targets:
            seen.add(target_id)
            if rule.kind == "agent_offline":
                check = _check_offline(rule, target, now)
            elif rule.kind == "tls_expiring":
                check = _check_certificate(rule, target, now)
            elif rule.kind == "backup_stale":
                check = _check_backups(db, rule, target, now)
            elif spec.metric:
                check = _check_metric(db, rule, target, now)
            else:
                check = _check_app(target, by_id.get(target.server_id), now)
            alert = open_by_target.get(target_id)
            if check.breached is True:
                if alert is None:
                    # Offline and metric rules already waited out their window.
                    wait = rule.kind == "app_down"
                    alert = Alert(
                        id=new_id(),
                        rule_id=rule.id,
                        target_type=spec.target,
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
                        _announce(db, notifications, rule, alert, check, firing=True)
                elif alert.state == "pending" and now - _aware(
                    alert.started_at
                ) >= timedelta(minutes=rule.duration_minutes):
                    alert.state, alert.fired_at = "firing", now
                    counts["fired"] += 1
                    _announce(db, notifications, rule, alert, check, firing=True)
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
                    _announce(db, notifications, rule, alert, check, firing=False)
        # Targets that no longer exist (server or app removed).
        for target_id, alert in open_by_target.items():
            if target_id not in seen:
                alert.state, alert.resolved_at, alert.updated_at = "resolved", now, now
    db.commit()
    return counts


def _announce(
    db, notifications, rule: AlertRule, alert: Alert, check: Check, firing: bool
) -> None:
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
