from datetime import UTC, datetime
from typing import Annotated, Literal, NoReturn

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.apps.models import Application
from app.audit import service as audit
from app.auth.dependencies import AdminUser
from app.core.database import DbSession
from app.monitoring import service
from app.monitoring.models import Alert, AlertRule, MaintenanceWindow
from app.servers import service as servers
from app.servers.models import Server

router = APIRouter(prefix="/api/v1/monitoring", tags=["Monitoring"])

Severity = Literal["critical", "warning", "info"]


def _raise(error: service.RuleError) -> NoReturn:
    raise HTTPException(status_code=error.status_code, detail=error.detail)


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: str
    name: str
    threshold: float | None
    duration_minutes: int
    severity: str
    enabled: bool
    notify_email: bool
    server_id: str | None
    application_id: str | None = None
    target: str = "server"
    metric: bool = False


class RuleCreate(BaseModel):
    kind: Literal[tuple(service.KINDS)]  # type: ignore[valid-type]
    name: (
        Annotated[str, StringConstraints(strip_whitespace=True, max_length=100)] | None
    ) = None
    threshold: Annotated[float, Field(gt=0, le=10_000)] | None = None
    duration_minutes: Annotated[int, Field(ge=1, le=10_080)] | None = None
    severity: Severity | None = None
    notify_email: bool = True
    server_id: Annotated[str, StringConstraints(max_length=32)] | None = None
    application_id: Annotated[str, StringConstraints(max_length=32)] | None = None


class RuleUpdate(BaseModel):
    name: (
        Annotated[
            str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)
        ]
        | None
    ) = None
    threshold: Annotated[float, Field(gt=0, le=10_000)] | None = None
    duration_minutes: Annotated[int, Field(ge=1, le=10_080)] | None = None
    severity: Severity | None = None
    enabled: bool | None = None
    notify_email: bool | None = None


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_id: str
    target_type: str
    target_id: str
    target_label: str
    severity: str
    title: str
    detail: str | None
    value: float | None
    state: str
    started_at: datetime
    fired_at: datetime | None
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    resolved_at: datetime | None
    snoozed_until: datetime | None = None


def _rule_out(rule: AlertRule) -> RuleOut:
    spec = service.KINDS[rule.kind]
    return RuleOut.model_validate(rule).model_copy(
        update={"target": spec.target, "metric": spec.threshold is not None}
    )


def _get_rule(db, rule_id: str) -> AlertRule:
    rule = db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    return rule


@router.get("/fleet")
def fleet(
    db: DbSession, _: AdminUser, range: Literal["1h", "24h", "7d", "30d", "90d"] = "1h"
):  # noqa: A002
    """Per-server metric series for the fleet charts, plus a summary."""
    rows = []
    for server in (
        db.query(Server)
        .filter(Server.enrolled_at.is_not(None), Server.revoked_at.is_(None))
        .order_by(Server.name)
    ):
        rows.append(
            {
                "id": server.id,
                "name": server.name,
                "status": servers.status_of(server),
                "points": servers.metric_series(db, server.id, range, points=60),
            }
        )
    open_alerts = service.list_alerts(db, "open")
    return {
        "servers": rows,
        "firing": sum(1 for a in open_alerts if a.state == "firing"),
        "acknowledged": sum(1 for a in open_alerts if a.state == "acknowledged"),
    }


@router.get("/alerts", response_model=list[AlertOut])
def alerts(
    db: DbSession,
    _: AdminUser,
    state: Literal["open", "resolved", "all"] = "open",
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
):
    now = datetime.now(UTC)
    out = []
    for alert in service.list_alerts(db, state, limit):
        row = AlertOut.model_validate(alert)
        until = row.snoozed_until
        if until and (until if until.tzinfo else until.replace(tzinfo=UTC)) <= now:
            row = row.model_copy(update={"snoozed_until": None})  # snooze is over
        out.append(row)
    return out


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge(alert_id: str, request: Request, db: DbSession, user: AdminUser):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    actor, label = audit.user_actor(user)
    try:
        alert = service.acknowledge(db, alert, label)
    except service.RuleError as error:
        _raise(error)
    audit.record(
        db,
        action="alert.acknowledge",
        result="success",
        actor=actor,
        actor_label=label,
        target_type=alert.target_type,
        target_id=alert.target_id,
        target_label=alert.target_label,
        detail=alert.title,
        request=request,
    )
    return alert


class SnoozeIn(BaseModel):
    # None wakes the alert up again.
    minutes: Annotated[int, Field(ge=5, le=10_080)] | None


@router.post("/alerts/{alert_id}/snooze", response_model=AlertOut)
def snooze(
    alert_id: str, body: SnoozeIn, request: Request, db: DbSession, user: AdminUser
):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    try:
        alert = service.snooze(db, alert, body.minutes)
    except service.RuleError as error:
        _raise(error)
    actor, label = audit.user_actor(user)
    audit.record(
        db,
        action="alert.snooze",
        result="success",
        actor=actor,
        actor_label=label,
        target_type=alert.target_type,
        target_id=alert.target_id,
        target_label=alert.target_label,
        detail=f"{body.minutes} min" if body.minutes else "woken up",
        request=request,
    )
    return alert


class MaintenanceIn(BaseModel):
    server_id: Annotated[str, StringConstraints(max_length=32)] | None = None
    application_id: Annotated[str, StringConstraints(max_length=32)] | None = None
    minutes: Annotated[int, Field(ge=5, le=10_080)]
    starts_at: datetime | None = None
    reason: (
        Annotated[str, StringConstraints(strip_whitespace=True, max_length=200)] | None
    ) = None


def _window_out(db, w: MaintenanceWindow) -> dict:
    server = db.get(Server, w.server_id) if w.server_id else None
    app = db.get(Application, w.application_id) if w.application_id else None
    return {
        "id": w.id,
        "server_id": w.server_id,
        "application_id": w.application_id,
        "scope": app.name if app else server.name if server else "Everything",
        "starts_at": w.starts_at,
        "ends_at": w.ends_at,
        "reason": w.reason,
        "created_by": w.created_by,
    }


@router.get("/maintenance")
def maintenance(db: DbSession, _: AdminUser):
    """Maintenance windows that are on now or coming up."""
    return [_window_out(db, w) for w in service.list_maintenance(db)]


@router.post("/maintenance", status_code=status.HTTP_201_CREATED)
def start_maintenance(
    body: MaintenanceIn, request: Request, db: DbSession, user: AdminUser
):
    actor, label = audit.user_actor(user)
    try:
        window = service.start_maintenance(db, body.model_dump(), label)
    except service.RuleError as error:
        _raise(error)
    out = _window_out(db, window)
    audit.record(
        db,
        action="maintenance.start",
        result="success",
        actor=actor,
        actor_label=label,
        target_type="maintenance",
        target_id=window.id,
        target_label=out["scope"],
        detail=f"{body.minutes} min" + (f": {body.reason}" if body.reason else ""),
        request=request,
    )
    return out


@router.delete("/maintenance/{window_id}", status_code=status.HTTP_204_NO_CONTENT)
def end_maintenance(window_id: str, request: Request, db: DbSession, user: AdminUser):
    window = db.get(MaintenanceWindow, window_id)
    if window is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Maintenance window not found")
    service.end_maintenance(db, window)
    actor, label = audit.user_actor(user)
    audit.record(
        db,
        action="maintenance.end",
        result="success",
        actor=actor,
        actor_label=label,
        target_type="maintenance",
        target_id=window.id,
        target_label=_window_out(db, window)["scope"],
        request=request,
    )


@router.post("/evaluate")
def evaluate_now(db: DbSession, _: AdminUser):
    """Check all rules now instead of waiting for the next tick."""
    return service.evaluate(db)


@router.get("/rules", response_model=list[RuleOut])
def rules(db: DbSession, _: AdminUser):
    return [_rule_out(r) for r in service.list_rules(db)]


def _audit_rule(
    db, user, request, action: str, rule: AlertRule, detail: str | None = None
) -> None:
    actor, label = audit.user_actor(user)
    audit.record(
        db,
        action=action,
        result="success",
        actor=actor,
        actor_label=label,
        target_type="alert_rule",
        target_id=rule.id,
        target_label=rule.name,
        detail=detail,
        request=request,
    )


@router.post("/rules", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(body: RuleCreate, request: Request, db: DbSession, user: AdminUser):
    try:
        rule = service.create_rule(db, body.model_dump())
    except service.RuleError as error:
        _raise(error)
    _audit_rule(db, user, request, "alert_rule.create", rule)
    return _rule_out(rule)


@router.patch("/rules/{rule_id}", response_model=RuleOut)
def update_rule(
    rule_id: str, body: RuleUpdate, request: Request, db: DbSession, user: AdminUser
):
    data = body.model_dump(exclude_unset=True)
    try:
        rule = service.update_rule(db, _get_rule(db, rule_id), data)
    except service.RuleError as error:
        _raise(error)
    _audit_rule(
        db,
        user,
        request,
        "alert_rule.update",
        rule,
        "changed " + ", ".join(sorted(data)),
    )
    return _rule_out(rule)


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(rule_id: str, request: Request, db: DbSession, user: AdminUser):
    rule = _get_rule(db, rule_id)
    _audit_rule(db, user, request, "alert_rule.delete", rule)
    db.delete(rule)
    db.commit()
