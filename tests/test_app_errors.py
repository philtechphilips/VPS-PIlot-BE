"""Error lines in apps' logs: found by the agent, alerted on by the control plane."""

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session
from vpspilot_agent import apperrors, runner

from app.apps import service as apps
from app.apps.models import AppErrorMetric
from app.monitoring import service as monitoring
from app.monitoring.models import Alert, AlertRule
from app.notifications.models import Notification
from tests.test_apps import APPS, git_app
from tests.test_servers import enrolled_agent

# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


def test_error_lines_are_recognised():
    errors = [
        "ERROR:    Exception in ASGI application",
        "TypeError: Cannot read properties of undefined (reading 'id')",
        "Traceback (most recent call last):",
        " ⨯ Error: connect ECONNREFUSED 127.0.0.1:5432",
        '{"level":"error","msg":"db down"}',
        '{"level":50,"msg":"boom"}',
        "npm ERR! code ELIFECYCLE",
        "2026/10/23 10:00:00 [error] 12#12: upstream timed out",
        'level=error msg="failed to connect"',
    ]
    fine = [
        "GET /api/users 200 12ms",
        "Listening on 0.0.0.0:3000",
        "0 errors, 2 warnings",
        '{"level":"info","msg":"retrying","error":null}',
        '{"level":30,"msg":"Error page rendered"}',
    ]
    assert all(apperrors.is_error(line) for line in errors)
    assert not any(apperrors.is_error(line) for line in fine)
    # The journal's own priority counts, whatever the text says.
    assert apperrors.is_error("something went wrong", priority="3")
    assert not apperrors.is_error("all good", priority="6")


def test_secrets_are_masked_in_samples():
    masked = apperrors.redact(
        "Error: login failed password=hunter2 url=postgres://app:s3cret@db/x "
        "Authorization: Bearer eyJabc.def"
    )
    for secret in ("hunter2", "s3cret", "eyJabc"):
        assert secret not in masked
    assert len(apperrors.redact("x" * 1000)) == apperrors.MAX_SAMPLE


def test_scan_counts_errors_per_app_and_minute(monkeypatch):
    base = 1_792_000_020  # a minute boundary
    monkeypatch.setattr(
        apperrors,
        "_sources",
        lambda: [("shop", "docker", "vp-shop"), ("api", "systemd", "vp-api.service")],
    )

    def docker_lines(name, since, until, deadline):
        yield base + 1, "\x1b[31mTypeError: x is undefined\x1b[0m", None
        yield base + 2, "GET / 200", None
        yield base + 61, "ERROR db password=hunter2 refused", None

    def journal_lines(unit, since, until, deadline):
        yield base + 5, "worker crashed", "3"
        yield base + 6, "started", "6"

    monkeypatch.setattr(apperrors, "_docker_lines", docker_lines)
    monkeypatch.setattr(apperrors, "_journal_lines", journal_lines)
    result = apperrors.scan({"since": "2026-10-01T00:00:00.5Z"})
    body = json.loads(result["output"])
    rows = {(r["app"], r["minute"]): r for r in body["rows"]}
    assert rows[("shop", base)]["errors"] == 1
    assert rows[("shop", base)]["sample"] == "TypeError: x is undefined"
    assert rows[("shop", base + 60)]["sample"] == "ERROR db password=[redacted] refused"
    assert rows[("api", base)] == {
        "app": "api",
        "minute": base,
        "errors": 1,
        "sample": "worker crashed",
    }
    assert body["until"].endswith("Z") and body["until"] > "2026-10-01"


def test_agent_sends_errors_and_moves_its_cursor(monkeypatch):
    calls, posts = [], []
    reply = {"until": "2026-10-23T10:01:00.000000000Z", "rows": [{"app": "shop"}]}

    def fake_call(op, args, socket, timeout):
        calls.append((op, args))
        return {"ok": True, "output": json.dumps(reply)}

    class FakeClient:
        def post(self, path, body):
            posts.append((path, body))
            return {}

    monkeypatch.setattr(runner.os.path, "exists", lambda path: True)
    monkeypatch.setattr(runner.helper, "call", fake_call)
    agent = runner.Runner.__new__(runner.Runner)
    agent.client, agent.errors_since = FakeClient(), "2026-10-23T10:00:00.000000000Z"
    agent.error_ignore = {"shop": ["ECONNRESET"]}
    agent.send_app_errors()
    assert calls == [
        (
            "app.errors",
            {"since": "2026-10-23T10:00:00.000000000Z", "ignore": agent.error_ignore},
        )
    ]
    assert posts == [("/agent/v1/app-errors", {"rows": [{"app": "shop"}]})]
    assert agent.errors_since == reply["until"]


# ---------------------------------------------------------------------------
# Control plane
# ---------------------------------------------------------------------------


def _minute(now: datetime) -> int:
    return int(now.timestamp()) // 60 * 60


def test_error_counts_are_stored_per_app_and_merged(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    client.post(APPS, json=git_app(server_id), headers=admin_headers)
    minute = _minute(datetime.now(UTC))
    rows = [
        {"app": "shop", "minute": minute, "errors": 2, "sample": "TypeError: a"},
        {"app": "unknown", "minute": minute, "errors": 9, "sample": "x"},
    ]
    again = {**rows[0], "errors": 1, "sample": "ReferenceError: b"}
    for payload in ({"rows": rows}, {"rows": [again]}):
        res = client.post("/agent/v1/app-errors", json=payload, headers=agent)
        assert res.status_code == 202
    stored = db.scalars(select(AppErrorMetric)).one()
    assert stored.errors == 3
    assert "ReferenceError" not in stored.sample  # encrypted at rest
    count, latest = apps.recent_errors(db, stored.application_id, datetime.now(UTC))
    assert (count, latest) == (3, "ReferenceError: b")

    # Another server can't report errors for this server's app.
    _, intruder = enrolled_agent(client, admin_headers, name="web-9")
    client.post("/agent/v1/app-errors", json={"rows": rows}, headers=intruder)
    assert db.scalars(select(AppErrorMetric)).one().errors == 3


def test_errors_fire_an_alert_and_resolve_once_quiet(
    client, admin_headers, db: Session
):
    server_id, agent = enrolled_agent(client, admin_headers)
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    now = datetime.now(UTC)
    monitoring.ensure_default_rules(db)
    rule = db.scalars(select(AlertRule).where(AlertRule.kind == "app_errors")).one()
    assert (rule.threshold, rule.duration_minutes, rule.enabled) == (1, 5, True)

    monitoring.evaluate(db, now)
    assert db.scalars(select(Alert).where(Alert.rule_id == rule.id)).first() is None

    row = {"app": "shop", "minute": _minute(now), "errors": 4,
           "sample": "TypeError: Cannot read properties of undefined"}  # fmt: skip
    client.post("/agent/v1/app-errors", json={"rows": [row]}, headers=agent)
    assert monitoring.evaluate(db, now)["fired"] == 1
    alert = db.scalars(select(Alert).where(Alert.rule_id == rule.id)).one()
    assert alert.state == "firing" and alert.target_id == app["id"]
    assert alert.detail.startswith("4 error lines in 5 min. Latest: TypeError")
    note = db.scalars(
        select(Notification).where(Notification.kind == "alert.firing")
    ).first()
    assert note is not None and "App logging errors: shop" in note.title

    # Quiet for one window: still one incident (errors every few minutes
    # mustn't page again and again).
    assert monitoring.evaluate(db, now + timedelta(minutes=7))["resolved"] == 0
    # Quiet for three windows: resolved.
    assert monitoring.evaluate(db, now + timedelta(minutes=16))["resolved"] == 1
    assert db.get(Alert, alert.id).state == "resolved"


def test_error_rule_threshold_is_a_count(client, admin_headers):
    rules = "/api/v1/monitoring/rules"
    low = client.post(
        rules, json={"kind": "app_errors", "threshold": 0}, headers=admin_headers
    )
    assert low.status_code == 422
    made = client.post(
        rules,
        json={"kind": "app_errors", "threshold": 250, "duration_minutes": 10},
        headers=admin_headers,
    )
    assert made.status_code == 201 and made.json()["threshold"] == 250


def test_ignored_lines_are_not_counted(monkeypatch):
    monkeypatch.setattr(apperrors, "_sources", lambda: [("shop", "docker", "vp-shop")])

    def lines(name, since, until, deadline):
        yield 1_792_000_020, "Error: read ECONNRESET", None
        yield 1_792_000_021, "TypeError: boom", None

    monkeypatch.setattr(apperrors, "_docker_lines", lines)
    out = apperrors.scan(
        {"since": "2026-10-01T00:00:00Z", "ignore": {"shop": ["econnreset"]}}
    )
    rows = json.loads(out["output"])["rows"]
    assert rows[0]["errors"] == 1 and rows[0]["sample"] == "TypeError: boom"


def test_ignore_lists_reach_the_agent(client, admin_headers):
    server_id, agent = enrolled_agent(client, admin_headers)
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    client.patch(
        f"{APPS}/{app['id']}",
        json={"error_ignore": ["ECONNRESET", "DeprecationWarning", "ECONNRESET"]},
        headers=admin_headers,
    )
    reply = client.post("/agent/v1/heartbeat", json={"facts": {}}, headers=agent).json()
    assert reply["error_ignore"] == {"shop": ["ECONNRESET", "DeprecationWarning"]}
