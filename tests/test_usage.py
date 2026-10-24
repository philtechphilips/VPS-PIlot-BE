"""Per-app CPU and memory, disk usage and cleanup."""

import json

import pytest
from sqlalchemy.orm import Session
from vpspilot_agent import usage

from tests.test_apps import APPS, git_app
from tests.test_jobs import claim
from tests.test_runtimes import _agent
from tests.test_servers import enrolled_agent

STATS = "\n".join(
    json.dumps(row)
    for row in [
        {"Name": "vp-shop", "CPUPerc": "12.50%", "MemUsage": "100MiB / 1.9GiB"},
        {"Name": "vp-blog-web-1", "CPUPerc": "1.00%", "MemUsage": "50MiB / 1.9GiB"},
        {"Name": "vp-blog-worker-1", "CPUPerc": "2.00%", "MemUsage": "25MiB / 1.9GiB"},
        {"Name": "vp-shop-candidate", "CPUPerc": "50%", "MemUsage": "1GiB / 1.9GiB"},
        {"Name": "vpdb-main", "CPUPerc": "3%", "MemUsage": "200MiB / 1.9GiB"},
    ]
)
NAMES = "vp-shop\t\nvp-blog-web-1\tvp-blog\nvp-blog-worker-1\tvp-blog\nvpdb-main\t\n"


def test_usage_per_app(monkeypatch):
    def fake_run(cmd, timeout=60, **kwargs):
        if cmd[:2] == ["docker", "ps"]:
            return 0, NAMES
        if cmd[:2] == ["docker", "stats"]:
            return 0, STATS
        if cmd[:2] == ["systemctl", "list-units"]:
            return 0, "vp-api.service loaded active running VPSPilot app api\n"
        if cmd[:2] == ["systemctl", "show"]:
            return 0, "MemoryCurrent=52428800\nCPUUsageNSec=1000000000\n"
        return 1, ""

    monkeypatch.setattr(usage.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(usage.d, "_run", fake_run)
    rows = {r["app"]: r for r in json.loads(usage.apps_usage({})["output"])["rows"]}
    assert set(rows) == {"shop", "blog", "api"}  # candidates and databases left out
    assert rows["shop"] == {
        "app": "shop",
        "cpu_percent": 12.5,
        "memory_bytes": 100 * 1024**2,
    }
    assert rows["blog"]["cpu_percent"] == 3.0  # a Compose project's services summed
    assert rows["blog"]["memory_bytes"] == 75 * 1024**2
    assert rows["api"]["memory_bytes"] == 52428800


def test_cleanup_targets_are_an_allowlist():
    with pytest.raises(usage.Rejected):
        usage.disk_cleanup({"targets": ["volumes"]}, lambda *a: None)


def test_usage_is_stored_and_charted(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    rows = [
        {"app": "shop", "cpu_percent": 12.5, "memory_bytes": 104857600},
        {"app": "elsewhere", "cpu_percent": 1, "memory_bytes": 1},
    ]
    res = client.post("/agent/v1/app-usage", json={"rows": rows}, headers=agent)
    assert res.status_code == 202 and res.json()["stored"] == 1
    chart = client.get(
        f"{APPS}/{app['id']}/usage?range=1h", headers=admin_headers
    ).json()
    assert chart["cpu_percent"] == 12.5 and chart["memory_bytes"] == 104857600
    assert sum(1 for p in chart["points"] if p["memory_bytes"]) == 1


def test_disk_jobs_need_a_new_agent(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    url = f"/api/v1/servers/{server_id}/actions"
    old = client.post(
        url, json={"type": "disk.usage", "payload": {}}, headers=admin_headers
    )
    assert old.status_code == 409
    _agent(db, server_id)
    for body in (
        {"type": "disk.usage", "payload": {}},
        {"type": "disk.cleanup", "payload": {"targets": ["build_cache", "journal"]}},
    ):
        assert client.post(url, json=body, headers=admin_headers).status_code == 202
        assert claim(client, agent)["type"] == body["type"]
    bad = {"type": "disk.cleanup", "payload": {"targets": ["volumes"]}}
    assert client.post(url, json=bad, headers=admin_headers).status_code == 422
