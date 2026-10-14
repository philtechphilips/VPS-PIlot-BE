import json

from sqlalchemy.orm import Session

from app.audit.models import AuditLog
from app.jobs.models import Job
from tests.test_apps import APPS, git_app
from tests.test_jobs import claim
from tests.test_servers import enrolled_agent

LOGS = "/api/v1/logs"


def test_journal_read_and_follow(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    job_id = client.post(
        LOGS,
        json={
            "server_id": server_id,
            "source": "journal",
            "unit": "nginx.service",
            "priority": 4,
        },
        headers=admin_headers,
    ).json()["job_id"]
    job = claim(client, agent)
    assert job["type"] == "logs.read"
    payload = {k: v for k, v in job["payload"].items() if v is not None}
    assert payload == {
        "source": "journal",
        "unit": "nginx.service",
        "lines": 200,
        "priority": 4,
    }
    body = {
        "source": "journal",
        "cursor": "s=abc;i=1",
        "lines": [{"t": 1, "u": "nginx.service", "p": 3, "m": "upstream timed out"}],
    }
    client.post(
        f"/agent/v1/jobs/{job['id']}/complete",
        json={"status": "succeeded", "output": json.dumps(body)},
        headers=agent,
    )
    result = client.get(f"{LOGS}/{job_id}", headers=admin_headers).json()
    assert (
        result["cursor"] == "s=abc;i=1"
        and result["lines"][0]["m"] == "upstream timed out"
    )
    assert "upstream" not in db.get(Job, job_id).output  # encrypted at rest
    # Following with the cursor isn't audited again, and stays out of activity.
    for _ in range(3):
        client.post(
            LOGS,
            json={"server_id": server_id, "source": "journal", "cursor": "s=abc;i=1"},
            headers=admin_headers,
        )
    assert db.query(AuditLog).filter(AuditLog.action == "job.logs.read").count() == 1
    activity = client.get(
        f"/api/v1/jobs?server_id={server_id}", headers=admin_headers
    ).json()
    assert all(j["type"] != "logs.read" for j in activity)


def test_validation(client, admin_headers):
    server_id, _ = enrolled_agent(client, admin_headers)
    bad = [
        {"source": "journal", "unit": "x; rm -rf /"},
        {"source": "journal", "cursor": "bad cursor\n"},
        {"source": "container"},
        {"source": "container", "container": "../etc"},
        {"source": "journal", "priority": 9},
        {"source": "files"},
    ]
    for body in bad:
        assert (
            client.post(
                LOGS, json={"server_id": server_id, **body}, headers=admin_headers
            ).status_code
            == 422
        ), body


def test_sources_label_apps_and_databases(client, admin_headers):
    server_id, agent = enrolled_agent(client, admin_headers)
    client.post(APPS, json=git_app(server_id, deploy=False), headers=admin_headers)
    client.post(
        "/agent/v1/inventory",
        json={
            "services": [
                {
                    "name": "nginx.service",
                    "active": "active",
                    "sub": "running",
                    "description": "nginx",
                }
            ],
            "containers": [
                {
                    "id": "1",
                    "name": "vp-shop",
                    "image": "x",
                    "state": "running",
                    "status": "Up",
                    "ports": "",
                },
                {
                    "id": "2",
                    "name": "redis-old",
                    "image": "redis",
                    "state": "exited",
                    "status": "Exited",
                    "ports": "",
                },
            ],
        },
        headers=agent,
    )
    body = client.get(
        f"{LOGS}/sources?server_id={server_id}", headers=admin_headers
    ).json()
    assert body["units"] == ["nginx.service"]
    assert [(c["name"], c["kind"], c["label"]) for c in body["containers"]] == [
        ("vp-shop", "app", "shop"),
        ("redis-old", "container", "redis-old"),
    ]
