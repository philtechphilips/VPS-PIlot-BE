import json
import subprocess
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.audit.models import AuditLog
from app.jobs.models import Job
from tests.test_apps import APPS, complete, git_app
from tests.test_jobs import claim
from tests.test_servers import enrolled_agent

LOGS = {
    "state": "running",
    "started_at": "2026-10-14T03:00:00Z",
    "restarts": 1,
    "lines": [
        {"t": "2026-10-14T03:00:01.5Z", "s": "out", "m": "listening on 3000"},
        {"t": "2026-10-14T03:00:02Z", "s": "err", "m": "warning: slow query"},
    ],
}


def setup_app(client, headers):
    server_id, agent = enrolled_agent(client, headers)
    app = client.post(APPS, json=git_app(server_id), headers=headers).json()
    complete(client, agent, claim(client, agent)["id"])  # first deploy
    return app, agent


def test_read_runtime_logs(client, admin_headers, db: Session):
    app, agent = setup_app(client, admin_headers)
    url = f"{APPS}/{app['id']}/logs"
    job_id = client.post(url, json={"lines": 300}, headers=admin_headers).json()[
        "job_id"
    ]
    pending = client.get(f"{url}/{job_id}", headers=admin_headers).json()
    assert pending["status"] == "queued" and pending["lines"] == []

    job = claim(client, agent)
    assert job["type"] == "app.logs"
    assert job["payload"] == {
        "app": "shop",
        "lines": 300,
        "since": None,
        "runtime": "docker",
        "service": None,
    }
    client.post(
        f"/agent/v1/jobs/{job['id']}/complete",
        json={"status": "succeeded", "output": json.dumps(LOGS)},
        headers=agent,
    )
    body = client.get(f"{url}/{job_id}", headers=admin_headers).json()
    assert body["status"] == "succeeded" and body["state"] == "running"
    assert [line["m"] for line in body["lines"]] == [
        "listening on 3000",
        "warning: slow query",
    ]
    assert body["lines"][1]["s"] == "err"
    # Stored encrypted, like all job output.
    assert "listening on 3000" not in db.get(Job, job_id).output


def test_following_is_audited_once_and_hidden_from_activity(
    client, admin_headers, db: Session
):
    app, _ = setup_app(client, admin_headers)
    url = f"{APPS}/{app['id']}/logs"
    client.post(url, json={}, headers=admin_headers)
    for _ in range(3):
        r = client.post(
            url, json={"since": "2026-10-14T03:00:02.123Z"}, headers=admin_headers
        )
        assert r.status_code == 202
    assert db.query(AuditLog).filter(AuditLog.action == "job.app.logs").count() == 1
    activity = client.get(
        f"/api/v1/jobs?server_id={app['server_id']}", headers=admin_headers
    ).json()
    assert all(j["type"] != "app.logs" for j in activity)


def test_bad_requests(client, admin_headers):
    app, _ = setup_app(client, admin_headers)
    url = f"{APPS}/{app['id']}/logs"
    assert (
        client.post(url, json={"lines": 5000}, headers=admin_headers).status_code == 422
    )
    assert (
        client.post(
            url, json={"since": "yesterday; rm -rf /"}, headers=admin_headers
        ).status_code
        == 422
    )
    assert client.get(f"{url}/nope", headers=admin_headers).status_code == 404


def test_old_log_reads_are_cleaned_up(client, admin_headers, db: Session):
    app, agent = setup_app(client, admin_headers)
    url = f"{APPS}/{app['id']}/logs"
    old_id = client.post(url, json={}, headers=admin_headers).json()["job_id"]
    job = db.get(Job, old_id)
    job.status, job.finished_at = "succeeded", datetime.now(UTC) - timedelta(hours=2)
    db.commit()
    client.post(url, json={}, headers=admin_headers)
    db.expire_all()
    assert db.get(Job, old_id) is None


# ---------------------------------------------------------------------------
# Agent side
# ---------------------------------------------------------------------------

from vpspilot_agent import deploy  # noqa: E402


def test_helper_merges_stdout_and_stderr_by_time(monkeypatch):
    calls = []

    def fake_run(cmd, timeout=60, cwd=None, env=None):
        calls.append(cmd)
        return 0, "running|2026-10-14T03:00:00Z|0"

    def fake_subprocess(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout="2026-10-14T03:00:01.5Z first\n2026-10-14T03:00:03Z third\n",
            stderr="2026-10-14T03:00:02.25Z second (stderr)\n",
        )

    monkeypatch.setattr(deploy, "_run", fake_run)
    monkeypatch.setattr(deploy.subprocess, "run", fake_subprocess)
    result = deploy.app_logs(
        {"app": "shop", "lines": 2, "since": "2026-10-14T03:00:00Z"}
    )
    body = json.loads(result["output"])
    assert [(x["s"], x["m"]) for x in body["lines"]] == [
        ("err", "second (stderr)"),
        ("out", "third"),
    ]
    since = ["--since", "2026-10-14T03:00:00Z"]
    assert calls[1] == [
        "docker",
        "logs",
        "--timestamps",
        "--tail",
        "2",
        *since,
        "vp-shop",
    ]


def test_helper_validates_log_requests():
    bad_requests = (
        {"app": "../x"},
        {"app": "shop", "lines": 0},
        {"app": "shop", "since": "now; id"},
    )
    for bad in bad_requests:
        try:
            deploy.app_logs(bad)
        except deploy.Rejected:
            continue
        raise AssertionError(f"accepted {bad}")
