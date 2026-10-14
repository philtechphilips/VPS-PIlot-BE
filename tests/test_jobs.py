from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.audit.models import AuditLog
from app.jobs.models import Job
from tests.test_servers import SERVERS, enrolled_agent

ACTIONS = "/actions"


def act(client, headers, server_id, type_, payload, key=None):
    body = {"type": type_, "payload": payload}
    if key:
        body["idempotency_key"] = key
    return client.post(f"{SERVERS}/{server_id}{ACTIONS}", json=body, headers=headers)


def claim(client, agent):
    return client.post("/agent/v1/jobs/claim", json={}, headers=agent).json()["job"]


def test_action_is_queued_with_202_and_audited(client, admin_headers, db: Session):
    server_id, _ = enrolled_agent(client, admin_headers)
    response = act(
        client, admin_headers, server_id, "service.restart", {"unit": "cron.service"}
    )
    assert response.status_code == 202
    job = response.json()
    assert job["status"] == "queued" and job["type"] == "service.restart"
    entry = db.query(AuditLog).filter(AuditLog.action == "job.service.restart").one()
    assert entry.result == "accepted" and entry.correlation_id == job["correlation_id"]


def test_payload_is_strictly_validated(client, admin_headers):
    server_id, _ = enrolled_agent(client, admin_headers)
    bad = [
        ("service.restart", {"unit": "cron.service; rm -rf /"}),
        ("service.restart", {"unit": "cron"}),
        ("service.restart", {"unit": "cron.service", "extra": 1}),
        ("container.logs", {"container": "web", "lines": 5000}),
        ("container.stop", {"container": "../etc"}),
    ]
    for type_, payload in bad:
        assert (
            act(client, admin_headers, server_id, type_, payload).status_code == 422
        ), payload
    assert (
        act(client, admin_headers, server_id, "shell.run", {"cmd": "id"}).status_code
        == 422
    )


def test_policy_protects_agent_and_ssh(client, admin_headers, db: Session):
    server_id, _ = enrolled_agent(client, admin_headers)
    assert (
        act(
            client,
            admin_headers,
            server_id,
            "service.stop",
            {"unit": "vpspilot-agent.service"},
        ).status_code
        == 403
    )
    assert (
        act(
            client, admin_headers, server_id, "service.stop", {"unit": "ssh.service"}
        ).status_code
        == 403
    )
    # Restarting SSH and reading the agent's logs are fine.
    assert (
        act(
            client, admin_headers, server_id, "service.restart", {"unit": "ssh.service"}
        ).status_code
        == 202
    )
    assert (
        act(
            client,
            admin_headers,
            server_id,
            "service.logs",
            {"unit": "vpspilot-agent.service"},
        ).status_code
        == 202
    )
    assert db.query(AuditLog).filter(AuditLog.result == "rejected").count() == 2


def test_idempotency_key_returns_same_job(client, admin_headers):
    server_id, _ = enrolled_agent(client, admin_headers)
    first = act(
        client,
        admin_headers,
        server_id,
        "service.restart",
        {"unit": "cron.service"},
        key="deploy-123",
    )
    again = act(
        client,
        admin_headers,
        server_id,
        "service.restart",
        {"unit": "cron.service"},
        key="deploy-123",
    )
    assert first.status_code == 202 and again.status_code == 200
    assert first.json()["id"] == again.json()["id"]


def test_agent_claims_only_its_own_jobs(client, admin_headers):
    server_a, agent_a = enrolled_agent(client, admin_headers, "web-a")
    _, agent_b = enrolled_agent(client, admin_headers, "web-b")
    job_id = act(
        client, admin_headers, server_a, "service.restart", {"unit": "cron.service"}
    ).json()["id"]

    assert claim(client, agent_b) is None
    job = claim(client, agent_a)
    assert job["id"] == job_id and job["payload"] == {"unit": "cron.service"}
    # Another agent can't report on it either.
    events = {"events": [{"level": "info", "message": "x"}]}
    assert (
        client.post(
            f"/agent/v1/jobs/{job_id}/events", json=events, headers=agent_b
        ).status_code
        == 404
    )


def test_full_job_lifecycle(client, admin_headers):
    server_id, agent = enrolled_agent(client, admin_headers)
    job_id = act(
        client,
        admin_headers,
        server_id,
        "service.logs",
        {"unit": "cron.service", "lines": 50},
    ).json()["id"]
    claim(client, agent)
    client.post(
        f"/agent/v1/jobs/{job_id}/events",
        json={"events": [{"message": "Running service.logs"}]},
        headers=agent,
    )
    done = client.post(
        f"/agent/v1/jobs/{job_id}/complete",
        json={"status": "succeeded", "exit_code": 0, "output": "line 1\nline 2"},
        headers=agent,
    )
    assert done.status_code == 202

    detail = client.get(f"/api/v1/jobs/{job_id}", headers=admin_headers).json()
    assert detail["status"] == "succeeded" and detail["output"] == "line 1\nline 2"
    assert detail["events"][0]["message"] == "Running service.logs"
    # Finished jobs can't be completed twice.
    again = client.post(
        f"/agent/v1/jobs/{job_id}/complete", json={"status": "failed"}, headers=agent
    )
    assert again.status_code == 409


def test_output_is_bounded(client, admin_headers):
    server_id, agent = enrolled_agent(client, admin_headers)
    job_id = act(
        client, admin_headers, server_id, "service.logs", {"unit": "cron.service"}
    ).json()["id"]
    claim(client, agent)
    client.post(
        f"/agent/v1/jobs/{job_id}/complete",
        json={"status": "succeeded", "exit_code": 0, "output": "x" * 200_000},
        headers=agent,
    )
    detail = client.get(f"/api/v1/jobs/{job_id}", headers=admin_headers).json()
    assert len(detail["output"]) == 64 * 1024


def test_unclaimed_jobs_expire(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    act(client, admin_headers, server_id, "service.restart", {"unit": "cron.service"})
    db.query(Job).update({"expires_at": datetime.now(UTC) - timedelta(seconds=1)})
    db.commit()
    assert claim(client, agent) is None
    jobs = client.get(
        f"/api/v1/jobs?server_id={server_id}", headers=admin_headers
    ).json()
    assert jobs[0]["status"] == "expired"


def test_cancel_only_queued(client, admin_headers):
    server_id, agent = enrolled_agent(client, admin_headers)
    queued = act(
        client, admin_headers, server_id, "service.restart", {"unit": "a.service"}
    ).json()["id"]
    assert (
        client.post(f"/api/v1/jobs/{queued}/cancel", headers=admin_headers).json()[
            "status"
        ]
        == "canceled"
    )
    running = act(
        client, admin_headers, server_id, "service.restart", {"unit": "b.service"}
    ).json()["id"]
    claim(client, agent)
    assert (
        client.post(f"/api/v1/jobs/{running}/cancel", headers=admin_headers).status_code
        == 409
    )


def test_heartbeat_reports_pending_jobs(client, admin_headers):
    server_id, agent = enrolled_agent(client, admin_headers)
    act(client, admin_headers, server_id, "service.restart", {"unit": "cron.service"})
    reply = client.post("/agent/v1/heartbeat", json={}, headers=agent).json()
    assert reply["jobs_pending"] == 1


def test_actions_need_an_active_agent(client, admin_headers):
    server_id, _ = enrolled_agent(client, admin_headers)
    client.post(f"{SERVERS}/{server_id}/revoke", headers=admin_headers)
    response = act(
        client, admin_headers, server_id, "service.restart", {"unit": "cron.service"}
    )
    assert response.status_code == 409


def test_audit_log_lists_security_events(client, admin_headers):
    server_id, _ = enrolled_agent(client, admin_headers)
    client.post(f"{SERVERS}/{server_id}/revoke", headers=admin_headers)
    entries = client.get("/api/v1/audit-logs?limit=50", headers=admin_headers).json()
    actions = [e["action"] for e in entries]
    assert {
        "auth.login",
        "server.enrollment.create",
        "agent.enroll",
        "server.revoke",
    } <= set(actions)
    # Never contains secrets.
    blob = str(entries)
    assert "ept_" not in blob and "agt_" not in blob and "password" not in blob.lower()


def test_failed_login_is_audited(client, db: Session):
    client.post(
        "/api/v1/auth/login", json={"email": "nobody@example.com", "password": "x"}
    )
    entry = db.query(AuditLog).filter(AuditLog.action == "auth.login").one()
    assert entry.result == "failure" and entry.actor == "anonymous"


def test_vpspilot_containers_cannot_be_stopped(client, admin_headers):
    server_id, _ = enrolled_agent(client, admin_headers)
    r = act(
        client,
        admin_headers,
        server_id,
        "container.stop",
        {"container": "vpspilot-api"},
    )
    assert r.status_code == 403
    assert (
        act(
            client,
            admin_headers,
            server_id,
            "container.restart",
            {"container": "vpspilot-proxy"},
        ).status_code
        == 202
    )


def test_control_plane_host_is_marked(client, admin_headers):
    server_id, agent = enrolled_agent(client, admin_headers)
    client.post(
        "/agent/v1/inventory",
        json={
            "containers": [
                {
                    "id": "1",
                    "name": "vpspilot-api",
                    "image": "x",
                    "state": "running",
                    "status": "Up",
                    "ports": "",
                }
            ]
        },
        headers=agent,
    )
    assert (
        client.get(f"/api/v1/servers/{server_id}", headers=admin_headers).json()[
            "is_control_plane"
        ]
        is True
    )
