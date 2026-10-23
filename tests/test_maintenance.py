"""Snoozing alerts, maintenance windows and rules for one app."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.monitoring import service as monitoring
from app.monitoring.models import Alert, AlertRule
from app.notifications.models import Notification
from tests.test_apps import APPS, git_app
from tests.test_servers import enrolled_agent

MON = "/api/v1/monitoring"


def _errors(client, agent, app_name, now, count=3):
    minute = int(now.timestamp()) // 60 * 60
    row = {"app": app_name, "minute": minute, "errors": count, "sample": "TypeError: x"}
    client.post("/agent/v1/app-errors", json={"rows": [row]}, headers=agent)


def _notes(db) -> int:
    return len(
        db.scalars(
            select(Notification).where(Notification.kind == "alert.firing")
        ).all()
    )


def test_maintenance_keeps_alerts_from_opening(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    window = client.post(
        f"{MON}/maintenance",
        json={"server_id": server_id, "minutes": 60, "reason": "moving the database"},
        headers=admin_headers,
    )
    assert window.status_code == 201 and window.json()["scope"] == "web-1"
    listed = client.get(f"{MON}/maintenance", headers=admin_headers).json()
    assert [w["reason"] for w in listed] == ["moving the database"]

    now = datetime.now(UTC)
    _errors(client, agent, "shop", now)
    monitoring.evaluate(db, now)
    rule = db.scalars(select(AlertRule).where(AlertRule.kind == "app_errors")).one()
    assert db.scalars(select(Alert).where(Alert.rule_id == rule.id)).first() is None

    # Over: the problem is still there, so it alerts now.
    client.delete(f"{MON}/maintenance/{window.json()['id']}", headers=admin_headers)
    assert client.get(f"{MON}/maintenance", headers=admin_headers).json() == []
    monitoring.evaluate(db, now + timedelta(seconds=1))
    alert = db.scalars(select(Alert).where(Alert.rule_id == rule.id)).one()
    assert alert.state == "firing" and alert.target_id == app["id"]

    both = client.post(
        f"{MON}/maintenance",
        json={"server_id": server_id, "application_id": app["id"], "minutes": 10},
        headers=admin_headers,
    )
    assert both.status_code == 422


def test_snoozed_alerts_stay_quiet(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    client.post(APPS, json=git_app(server_id), headers=admin_headers)
    now = datetime.now(UTC)
    _errors(client, agent, "shop", now)
    monitoring.evaluate(db, now)
    rule = db.scalars(select(AlertRule).where(AlertRule.kind == "app_errors")).one()
    alert = db.scalars(select(Alert).where(Alert.rule_id == rule.id)).one()
    snoozed = client.post(
        f"{MON}/alerts/{alert.id}/snooze", json={"minutes": 60}, headers=admin_headers
    )
    assert snoozed.status_code == 200 and snoozed.json()["snoozed_until"]

    # Quiet long enough to resolve: no "Resolved" message while snoozed.
    assert monitoring.evaluate(db, now + timedelta(minutes=16))["resolved"] >= 1
    db.refresh(alert)
    assert alert.state == "resolved"
    titles = [n.title for n in db.scalars(select(Notification))]
    assert not any(t.startswith("Resolved: App logging errors") for t in titles)


def test_rules_for_one_app(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    shop = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    client.post(APPS, json=git_app(server_id, name="blog"), headers=admin_headers)
    monitoring.ensure_default_rules(db)
    for rule in db.scalars(select(AlertRule).where(AlertRule.kind == "app_errors")):
        rule.enabled = False
    db.commit()
    made = client.post(
        f"{MON}/rules",
        json={"kind": "app_errors", "threshold": 1, "application_id": shop["id"]},
        headers=admin_headers,
    )
    assert made.status_code == 201 and made.json()["application_id"] == shop["id"]
    bad = client.post(
        f"{MON}/rules",
        json={"kind": "cpu_high", "threshold": 90, "application_id": shop["id"]},
        headers=admin_headers,
    )
    assert bad.status_code == 422

    now = datetime.now(UTC)
    _errors(client, agent, "blog", now)
    _errors(client, agent, "shop", now)
    monitoring.evaluate(db, now)
    alerts = db.scalars(select(Alert).where(Alert.rule_id == made.json()["id"])).all()
    assert [a.target_id for a in alerts] == [shop["id"]]
