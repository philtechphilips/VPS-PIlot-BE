"""Pending OS updates: reported by the agent, alerted on, installed by a job."""

import subprocess
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session
from vpspilot_agent import collectors, system

from app.monitoring import service as monitoring
from app.monitoring.models import Alert, AlertRule
from app.servers.models import Server
from tests.test_jobs import claim
from tests.test_runtimes import _agent
from tests.test_servers import enrolled_agent

APT_LIST = (
    "Listing...\n"
    "openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable…]\n"
    "curl/jammy-updates 7.81.0-1ubuntu1.20 amd64 [upgradable from: x]\n"
    "libssl3/jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: x]\n"
)


def test_agent_reads_pending_updates_from_apt(monkeypatch):
    monkeypatch.setattr(collectors.shutil, "which", lambda name: "/usr/bin/apt")
    monkeypatch.setattr(
        collectors.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, APT_LIST, ""),
    )
    found = collectors.updates(force=True)
    assert (found["total"], found["security"]) == (3, 2)
    assert [p["name"] for p in found["packages"]] == ["openssl", "libssl3", "curl"]
    assert found["packages"][0] == {
        "name": "openssl",
        "version": "3.0.2-0ubuntu1.18",
        "security": True,
    }


def test_upgrades_run_in_their_own_unit(monkeypatch):
    calls = []

    class Proc:
        stdout = iter(["Reading package lists...\n", "1 upgraded\n"])

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(system.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(system.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(
        system.subprocess, "Popen", lambda cmd, **k: calls.append(cmd) or Proc()
    )
    events = []
    out = system.upgrade({"mode": "all"}, lambda kind, text: events.append(text))
    assert out["exit_code"] == 0
    cmd = calls[0]
    assert cmd[:2] == ["systemd-run", "--unit=vpspilot-os-upgrade"]
    assert "--setenv=NEEDRESTART_SUSPEND=1" in cmd
    assert cmd[-1].startswith("apt-get update -q && apt-get -y")
    assert "1 upgraded" in events

    monkeypatch.setattr(
        system.shutil, "which", lambda name: None if "unattended" in name else name
    )
    refused = system.upgrade({"mode": "security"}, lambda *_: None)
    assert refused["exit_code"] == 1 and "unattended-upgrades" in refused["error"]


def test_updates_are_stored_alerted_and_installed(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    report = {
        "updates": {
            "total": 3,
            "security": 2,
            "packages": [{"name": "openssl", "version": "3.0.2", "security": True}],
            "reboot_required": True,
            "checked_at": 1_792_000_000,
        }
    }
    assert (
        client.post("/agent/v1/inventory", json=report, headers=agent).status_code
        == 202
    )
    detail = client.get(f"/api/v1/servers/{server_id}", headers=admin_headers).json()
    assert detail["inventory"]["updates"]["security"] == 2

    monitoring.ensure_default_rules(db)
    rule = db.scalars(
        select(AlertRule).where(AlertRule.kind == "updates_pending")
    ).one()
    now = datetime.now(UTC)
    monitoring.evaluate(db, now)
    alert = db.scalars(select(Alert).where(Alert.rule_id == rule.id)).one()
    assert alert.state == "pending"  # waits 3 days for unattended-upgrades
    server = db.get(Server, server_id)
    server.inventory_at = now + timedelta(days=3, minutes=1)
    db.commit()
    monitoring.evaluate(db, now + timedelta(days=3, minutes=1))
    db.refresh(alert)
    assert alert.state == "firing"
    assert alert.detail == "2 security updates pending (3 in all); a reboot is required"

    queued = client.post(
        f"/api/v1/servers/{server_id}/actions",
        json={"type": "os.upgrade", "payload": {"mode": "security"}},
        headers=admin_headers,
    )
    assert (
        queued.status_code == 409 and "Upgrade it to 1.1.4" in queued.json()["detail"]
    )
    _agent(db, server_id)
    queued = client.post(
        f"/api/v1/servers/{server_id}/actions",
        json={"type": "os.upgrade", "payload": {"mode": "security"}},
        headers=admin_headers,
    )
    assert queued.status_code == 202
    job = claim(client, agent)
    assert job["type"] == "os.upgrade" and job["payload"] == {"mode": "security"}
    bad = client.post(
        f"/api/v1/servers/{server_id}/actions",
        json={"type": "os.upgrade", "payload": {"mode": "dist"}},
        headers=admin_headers,
    )
    assert bad.status_code == 422
