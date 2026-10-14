from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.apps.models import Application
from app.monitoring import service
from app.monitoring.models import Alert, AlertRule
from app.servers.models import MetricSample, Server
from tests.test_apps import APPS, complete, git_app
from tests.test_jobs import claim
from tests.test_servers import enrolled_agent

MON = "/api/v1/monitoring"
NOW = datetime.now(UTC)


def heartbeat_at(db: Session, server_id: str, when: datetime) -> None:
    server = db.get(Server, server_id)
    server.last_heartbeat_at = when
    db.commit()


def samples(
    db: Session, server_id: str, minutes: int, every_s: int = 15, end=NOW, **values
):
    base = dict(
        cpu_percent=10,
        memory_percent=20,
        swap_percent=0,
        disk_percent=30,
        inode_percent=5,
        memory_used=1,
        disk_used=1,
        load_1=0,
        load_5=0,
        load_15=0,
        net_rx_bps=0,
        net_tx_bps=0,
    )
    base.update(values)
    for i in range(minutes * 60 // every_s):
        db.add(
            MetricSample(
                server_id=server_id, ts=end - timedelta(seconds=i * every_s), **base
            )
        )
    db.commit()


def open_alerts(client, headers):
    return client.get(f"{MON}/alerts", headers=headers).json()


def test_default_rules(client, admin_headers):
    rules = client.get(f"{MON}/rules", headers=admin_headers).json()
    kinds = {r["kind"]: r for r in rules}
    assert set(kinds) == set(service.KINDS)
    assert kinds["agent_offline"]["severity"] == "critical"
    assert kinds["swap_high"]["enabled"] is False
    assert kinds["cpu_high"]["threshold"] == 90 and kinds["cpu_high"]["metric"] is True


def test_agent_offline_fires_once_and_resolves(
    client, admin_headers, db: Session, outbox
):
    server_id, _ = enrolled_agent(client, admin_headers)
    heartbeat_at(db, server_id, NOW - timedelta(minutes=12))
    assert service.evaluate(db, NOW)["fired"] == 1
    assert (
        service.evaluate(db, NOW + timedelta(seconds=30))["fired"] == 0
    )  # deduplicated
    alerts = open_alerts(client, admin_headers)
    assert len(alerts) == 1 and alerts[0]["title"] == "Agent offline"
    assert alerts[0]["detail"] == "No heartbeat for 12 min"
    assert [m.subject for m in outbox if "Agent offline" in m.subject] == [
        "[critical] Agent offline: web-1"
    ]
    inbox = client.get("/api/v1/notifications", headers=admin_headers).json()
    assert inbox["items"][0]["title"] == "Agent offline: web-1"

    heartbeat_at(db, server_id, NOW)
    assert service.evaluate(db, NOW)["resolved"] == 1
    assert open_alerts(client, admin_headers) == []
    assert any(m.subject == "Resolved: Agent offline: web-1" for m in outbox)


def test_sustained_cpu_fires_but_a_spike_does_not(client, admin_headers, db: Session):
    server_id, _ = enrolled_agent(client, admin_headers)
    heartbeat_at(db, server_id, NOW)
    samples(
        db, server_id, minutes=2, cpu_percent=99
    )  # too few samples for a 15 min window
    assert service.evaluate(db, NOW)["fired"] == 0
    samples(
        db,
        server_id,
        minutes=15,
        end=NOW - timedelta(minutes=2, seconds=7),
        cpu_percent=96,
    )
    assert service.evaluate(db, NOW)["fired"] == 1
    alert = open_alerts(client, admin_headers)[0]
    assert alert["title"] == "CPU sustained high" and alert["value"] > 90
    assert "averaged" in alert["detail"]


def test_hysteresis_and_resolution(client, admin_headers, db: Session):
    server_id, _ = enrolled_agent(client, admin_headers)
    heartbeat_at(db, server_id, NOW)
    samples(db, server_id, minutes=10, memory_percent=95)
    assert service.evaluate(db, NOW)["fired"] == 1
    later = NOW + timedelta(minutes=11)
    heartbeat_at(db, server_id, later)
    samples(
        db, server_id, minutes=10, end=later, memory_percent=88.5
    )  # within 3 points
    assert service.evaluate(db, later)["resolved"] == 0
    much_later = later + timedelta(minutes=11)
    heartbeat_at(db, server_id, much_later)
    samples(db, server_id, minutes=10, end=much_later, memory_percent=60)
    assert service.evaluate(db, much_later)["resolved"] == 1


def test_app_down_waits_for_its_duration(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    complete(client, agent, claim(client, agent)["id"])  # released
    client.post(
        "/agent/v1/inventory",
        json={
            "containers": [
                {
                    "id": "1",
                    "name": "vp-shop",
                    "image": "x",
                    "state": "exited",
                    "status": "Exited (1)",
                    "ports": "",
                }
            ]
        },
        headers=agent,
    )
    heartbeat_at(db, server_id, NOW)
    assert service.evaluate(db, NOW)["fired"] == 0
    assert open_alerts(client, admin_headers) == []  # pending isn't shown
    assert service.evaluate(db, NOW + timedelta(minutes=3))["fired"] == 1
    alert = open_alerts(client, admin_headers)[0]
    assert alert["target_type"] == "application" and alert["target_id"] == app["id"]
    assert alert["detail"].startswith("Container is exited")

    client.post(
        "/agent/v1/inventory",
        json={
            "containers": [
                {
                    "id": "1",
                    "name": "vp-shop",
                    "image": "x",
                    "state": "running",
                    "status": "Up",
                    "ports": "",
                }
            ]
        },
        headers=agent,
    )
    assert service.evaluate(db, NOW + timedelta(minutes=3))["resolved"] == 1


def test_acknowledge_and_rule_changes(client, admin_headers, db: Session):
    server_id, _ = enrolled_agent(client, admin_headers)
    heartbeat_at(db, server_id, NOW - timedelta(hours=1))
    service.evaluate(db, NOW)
    alert = open_alerts(client, admin_headers)[0]
    ack = client.post(f"{MON}/alerts/{alert['id']}/acknowledge", headers=admin_headers)
    assert (
        ack.json()["state"] == "acknowledged"
        and ack.json()["acknowledged_by"] == "admin@example.com"
    )
    assert (
        client.post(
            f"{MON}/alerts/{alert['id']}/acknowledge", headers=admin_headers
        ).status_code
        == 409
    )
    # Still open (acknowledged), and not re-announced.
    assert service.evaluate(db, NOW)["fired"] == 0

    rule = db.query(AlertRule).filter(AlertRule.kind == "agent_offline").one()
    r = client.patch(
        f"{MON}/rules/{rule.id}", json={"enabled": False}, headers=admin_headers
    )
    assert r.json()["enabled"] is False
    assert (
        db.query(Alert).filter(Alert.state.in_(("firing", "acknowledged"))).count() == 0
    )

    bad = client.patch(
        f"{MON}/rules/{rule.id}", json={"threshold": 150}, headers=admin_headers
    )
    assert bad.status_code == 422
    created = client.post(
        f"{MON}/rules",
        json={
            "kind": "disk_high",
            "name": "Disk on web-1",
            "threshold": 70,
            "duration_minutes": 5,
            "server_id": server_id,
        },
        headers=admin_headers,
    )
    assert created.status_code == 201 and created.json()["server_id"] == server_id
    no_threshold = client.post(
        f"{MON}/rules", json={"kind": "cpu_high"}, headers=admin_headers
    )
    assert no_threshold.status_code == 422
    assert (
        client.delete(
            f"{MON}/rules/{created.json()['id']}", headers=admin_headers
        ).status_code
        == 204
    )


def test_fleet_series(client, admin_headers, db: Session):
    server_id, _ = enrolled_agent(client, admin_headers)
    heartbeat_at(db, server_id, NOW)
    samples(db, server_id, minutes=5, cpu_percent=42)
    body = client.get(f"{MON}/fleet?range=1h", headers=admin_headers).json()
    assert (
        body["servers"][0]["name"] == "web-1"
        and body["servers"][0]["status"] == "online"
    )
    assert body["servers"][0]["points"][-1]["cpu_percent"] == 42
    assert body["firing"] == 0


def test_removed_targets_close_their_alerts(client, admin_headers, db: Session):
    server_id, _ = enrolled_agent(client, admin_headers)
    heartbeat_at(db, server_id, NOW - timedelta(hours=1))
    service.evaluate(db, NOW)
    db.delete(db.get(Server, server_id))
    db.commit()
    service.evaluate(db, NOW)
    assert open_alerts(client, admin_headers) == []
    assert db.query(Application).count() == 0


def test_threshold_limits_follow_the_rule_kind(client, admin_headers):
    rules = "/api/v1/monitoring/rules"
    pct = client.post(
        rules, json={"kind": "cpu_high", "threshold": 150}, headers=admin_headers
    )
    assert pct.status_code == 422
    weekly = client.post(
        rules, json={"kind": "backup_stale", "threshold": 168}, headers=admin_headers
    )
    assert weekly.status_code == 201, weekly.text
    edited = client.patch(
        f"{rules}/{weekly.json()['id']}",
        json={"threshold": 200, "name": "Weekly"},
        headers=admin_headers,
    )
    assert edited.status_code == 200 and edited.json()["threshold"] == 200
