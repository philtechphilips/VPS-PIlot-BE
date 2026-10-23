"""Scheduled jobs: cron parsing, scheduling, runs and failure notices."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from vpspilot_agent import appexec

from app.apps import crons
from app.apps.models import AppCronJob, Application
from app.core import cron
from app.notifications.models import Notification
from tests.test_apps import APPS, complete, git_app
from tests.test_jobs import claim
from tests.test_runtimes import _agent
from tests.test_servers import enrolled_agent

T0 = datetime(2026, 10, 23, 10, 7, 30, tzinfo=UTC)  # a Friday


@pytest.mark.parametrize(
    ("expression", "zone", "expected"),
    [
        ("*/15 * * * *", "UTC", datetime(2026, 10, 23, 10, 15, tzinfo=UTC)),
        ("0 2 * * *", "UTC", datetime(2026, 10, 24, 2, 0, tzinfo=UTC)),
        # 2am in Lagos (UTC+1) is 1am UTC.
        ("0 2 * * *", "Africa/Lagos", datetime(2026, 10, 24, 1, 0, tzinfo=UTC)),
        ("@weekly", "UTC", datetime(2026, 10, 25, 0, 0, tzinfo=UTC)),
        ("30 9 * * 1-5", "UTC", datetime(2026, 10, 26, 9, 30, tzinfo=UTC)),
        ("0 0 1 1 *", "UTC", datetime(2027, 1, 1, 0, 0, tzinfo=UTC)),
        # Day of month OR day of week, like cron: the 1st, or any Sunday.
        ("0 12 1 * 0", "UTC", datetime(2026, 10, 25, 12, 0, tzinfo=UTC)),
        ("0 12 * * 7", "UTC", datetime(2026, 10, 25, 12, 0, tzinfo=UTC)),
    ],
)
def test_next_run(expression, zone, expected):
    assert cron.parse(expression).next_after(T0, zone) == expected


@pytest.mark.parametrize(
    "bad", ["* * * *", "61 * * * *", "*/0 * * * *", "a * * * *", "0 0 31 2 *"]
)
def test_bad_schedules_are_refused(bad):
    with pytest.raises(cron.CronError):
        cron.parse(bad).next_after(T0)


def test_commands_run_inside_the_app():
    base = {"app": "shop", "command": "npm run cleanup", "job_id": "a" * 32}
    assert appexec._command({**base, "runtime": "docker"}) == [
        "docker", "exec", "vp-shop", "sh", "-c", "npm run cleanup",
    ]  # fmt: skip
    compose = appexec._command({**base, "runtime": "compose", "service": "web"})
    assert compose[:3] == ["docker", "exec", "vp-shop-web-1"]
    with pytest.raises(appexec.Rejected):
        appexec._command({**base, "runtime": "docker", "command": "a\nb"})


def _live_app(client, admin_headers, db):
    server_id, agent = enrolled_agent(client, admin_headers)
    _agent(db, server_id)
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    claim(client, agent)  # the first deploy
    row = db.get(Application, app["id"])
    row.current_deployment_id = "f" * 32
    db.commit()
    return agent, app


def test_schedule_run_and_failure_notice(client, admin_headers, db: Session):
    agent, app = _live_app(client, admin_headers, db)
    url = f"{APPS}/{app['id']}/cron"
    bad = client.post(
        url,
        json={"name": "x", "schedule": "every day", "command": "true"},
        headers=admin_headers,
    )
    assert bad.status_code == 422
    made = client.post(
        url,
        json={
            "name": "Nightly cleanup",
            "schedule": "0 2 * * *",
            "timezone": "Africa/Lagos",
            "command": "npm run cleanup",
        },
        headers=admin_headers,
    )
    assert made.status_code == 201, made.text
    job = made.json()
    assert job["next_run_at"] and job["timezone"] == "Africa/Lagos"

    entry = db.get(AppCronJob, job["id"])
    entry.next_run_at = datetime.now(UTC) - timedelta(minutes=1)
    db.commit()
    assert crons.run_due(db) == 1
    queued = claim(client, agent)
    assert queued["type"] == "app.exec"
    assert queued["payload"]["command"] == "npm run cleanup"
    assert queued["payload"]["cron_id"] == job["id"]

    # Still running: the next tick (or Run now) doesn't start another.
    entry.next_run_at = datetime.now(UTC) - timedelta(minutes=1)
    db.commit()
    assert crons.run_due(db) == 0
    db.refresh(entry)
    assert entry.last_status == "skipped"
    entry.last_job_id = queued["id"]
    db.commit()

    complete(client, agent, queued["id"], ok=False, error="Exited with code 1: boom")
    db.refresh(entry)
    assert entry.last_status == "failed" and "boom" in entry.last_error
    notes = db.scalars(select(Notification).where(Notification.kind == "job.failed"))
    assert "Nightly cleanup failed on shop" in next(notes).title

    run = client.post(f"{url}/{job['id']}/run", headers=admin_headers)
    assert run.status_code == 202
    assert claim(client, agent)["id"] == run.json()["job_id"]


def test_jobs_need_a_live_release(client, admin_headers):
    server_id, _ = enrolled_agent(client, admin_headers)
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    url = f"{APPS}/{app['id']}/cron"
    job = client.post(
        url,
        json={"name": "x", "schedule": "@hourly", "command": "true"},
        headers=admin_headers,
    ).json()
    run = client.post(f"{url}/{job['id']}/run", headers=admin_headers)
    assert run.status_code == 409 and "Deploy the app first" in run.json()["detail"]
    off = client.patch(
        f"{url}/{job['id']}", json={"enabled": False}, headers=admin_headers
    )
    assert off.json()["next_run_at"] is None
    assert client.delete(f"{url}/{job['id']}", headers=admin_headers).status_code == 204
