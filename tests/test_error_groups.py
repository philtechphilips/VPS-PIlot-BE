"""Errors grouped by cause, ignoring a group, and searching logs."""

import json
from datetime import UTC, datetime

from sqlalchemy.orm import Session
from vpspilot_agent import apperrors

from tests.test_apps import APPS, git_app
from tests.test_jobs import claim
from tests.test_runtimes import _agent
from tests.test_servers import enrolled_agent


def test_the_agent_groups_the_same_bug(monkeypatch):
    monkeypatch.setattr(apperrors, "_sources", lambda: [("shop", "docker", "vp-shop")])

    def lines(name, since, until, deadline, limit=None):
        yield (
            1_792_000_020,
            "TypeError: Cannot read properties of undefined (reading 'id')",
            None,
        )
        yield (
            1_792_000_021,
            "TypeError: Cannot read properties of undefined (reading 'email')",
            None,
        )
        yield 1_792_000_022, "Error: connect ECONNREFUSED 127.0.0.1:5432", None

    monkeypatch.setattr(apperrors, "_docker_lines", lines)
    out = apperrors.scan({"since": "2026-10-01T00:00:00Z"})
    groups = json.loads(out["output"])["rows"][0]["groups"]
    assert sorted(g["count"] for g in groups) == [1, 2]
    ignored = next(g["fp"] for g in groups if g["count"] == 2)
    out = apperrors.scan(
        {"since": "2026-10-01T00:00:00Z", "ignore": {"shop": [f"fp:{ignored}"]}}
    )
    row = json.loads(out["output"])["rows"][0]
    assert row["errors"] == 1 and "ECONNREFUSED" in row["sample"]


def test_search_finds_lines_across_apps(monkeypatch):
    monkeypatch.setattr(
        apperrors,
        "_sources",
        lambda: [("shop", "docker", "vp-shop"), ("api", "systemd", "vp-api.service")],
    )
    monkeypatch.setattr(
        apperrors,
        "_docker_lines",
        lambda *a, **k: iter([(1.0, "order 42 paid", None), (2.0, "GET /", None)]),
    )
    monkeypatch.setattr(
        apperrors,
        "_journal_lines",
        lambda *a, **k: iter([(3.0, "Order 42 shipped", "6")]),
    )
    body = json.loads(
        apperrors.search({"query": "order 42", "since": "2026-10-01T00:00:00Z"})[
            "output"
        ]
    )
    assert [(m["app"], m["line"]) for m in body["matches"]] == [
        ("shop", "order 42 paid"),
        ("api", "Order 42 shipped"),
    ]
    only = json.loads(
        apperrors.search(
            {"query": "order", "since": "2026-10-01T00:00:00Z", "apps": ["api"]}
        )["output"]
    )
    assert [m["app"] for m in only["matches"]] == ["api"]


def test_groups_are_stored_listed_and_ignored(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    minute = int(datetime.now(UTC).timestamp()) // 60 * 60
    group = {"fp": "a" * 16, "count": 3, "sample": "TypeError: boom"}
    for _ in range(2):
        client.post(
            "/agent/v1/app-errors",
            json={
                "rows": [
                    {"app": "shop", "minute": minute, "errors": 3, "groups": [group]}
                ]
            },
            headers=agent,
        )
    groups = client.get(f"{APPS}/{app['id']}/errors", headers=admin_headers).json()
    assert len(groups) == 1
    assert (groups[0]["total"], groups[0]["today"], groups[0]["sample"]) == (
        6,
        6,
        "TypeError: boom",
    )
    assert len(groups[0]["days"]) == 14

    client.post(
        f"{APPS}/{app['id']}/errors/{groups[0]['id']}/ignore", headers=admin_headers
    )
    reply = client.post("/agent/v1/heartbeat", json={"facts": {}}, headers=agent).json()
    assert reply["error_ignore"] == {"shop": [f"fp:{'a' * 16}"]}


def test_log_search_fans_out_per_server(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    _agent(db, server_id)
    client.post(APPS, json=git_app(server_id, deploy=False), headers=admin_headers)
    out = client.post(
        "/api/v1/logs/search",
        json={"query": "order 42", "range": "7d"},
        headers=admin_headers,
    ).json()
    assert len(out["searches"]) == 1 and out["searches"][0]["job_id"]
    job = claim(client, agent)
    assert job["type"] == "logs.search"
    assert job["payload"]["query"] == "order 42" and job["payload"]["apps"] == ["shop"]
