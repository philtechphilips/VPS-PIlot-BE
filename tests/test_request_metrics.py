"""Per-app request metrics from the proxy's access log."""

import io
import json
import time

from sqlalchemy.orm import Session
from vpspilot_agent import proxy

from app.apps.models import RequestMetric
from app.domains.models import Domain
from tests.test_apps import APPS, git_app
from tests.test_servers import enrolled_agent


def _line(stamp: str, host: str, status: int, duration: float, ts: float) -> str:
    entry = {"level": "info", "ts": ts, "logger": "http.log.access.log0",
             "request": {"host": f"{host}:443"}, "status": status,
             "duration": duration, "size": 100}  # fmt: skip
    return f"{stamp} {json.dumps(entry)}\n"


def test_agent_counts_requests_per_site_and_minute(monkeypatch):
    minute = int(time.time()) // 60 * 60
    log = "".join(
        [
            _line(
                "2026-10-14T12:00:00.000000001Z",
                "shop.example.com",
                200,
                0.010,
                minute + 1,
            ),  # before cursor
            _line(
                "2026-10-14T12:00:01.000000000Z",
                "shop.example.com",
                200,
                0.020,
                minute + 2,
            ),
            _line(
                "2026-10-14T12:00:02.000000000Z",
                "shop.example.com",
                503,
                0.400,
                minute + 3,
            ),
            _line(
                "2026-10-14T12:00:03.000000000Z",
                "api.example.com",
                404,
                0.005,
                minute + 4,
            ),
            '2026-10-14T12:00:04.000000000Z {"logger":"tls","msg":"certificate obtained"}\n',
        ]
    )

    class FakeProc:
        stderr = io.StringIO(log)

        def kill(self): ...

        def wait(self): ...

    monkeypatch.setattr(proxy, "_running", lambda: True)
    monkeypatch.setattr(proxy.subprocess, "Popen", lambda *a, **k: FakeProc())
    result = proxy.requests({"since": "2026-10-14T12:00:00.000000001Z"})
    body = json.loads(result["output"])
    assert body["until"] == "2026-10-14T12:00:03.000000000Z"
    rows = {r["host"]: r for r in body["rows"]}
    shop = rows["shop.example.com"]
    assert (shop["requests"], shop["s2xx"], shop["s5xx"], shop["bytes"]) == (
        2,
        1,
        1,
        200,
    )
    assert shop["p95_ms"] == 400.0 and rows["api.example.com"]["s4xx"] == 1


def test_sites_log_access_requests():
    text = proxy.render(
        [{"host": "shop.example.com", "tls": "auto", "upstream": "vp-shop:3000"}], None
    )
    assert "\tlog {\n\t\toutput stderr\n\t\tformat json\n\t}" in text


def test_counts_are_stored_per_app_and_merged(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    db.add(Domain(id="d" * 32, hostname="shop.example.com", server_id=server_id,
                  application_id=app["id"], tls_mode="auto", status="active", created_by="t"))  # fmt: skip
    db.commit()
    minute = int(time.time()) // 60 * 60
    row = {"host": "shop.example.com", "minute": minute, "requests": 10, "s2xx": 9,
           "s3xx": 0, "s4xx": 0, "s5xx": 1, "bytes": 1000, "p50_ms": 5.0, "p95_ms": 50.0}  # fmt: skip
    other = {**row, "host": "elsewhere.example.com"}
    for payload in (
        {"rows": [row, other]},
        {"rows": [{**row, "requests": 5, "s2xx": 5, "s5xx": 0, "p95_ms": 80.0}]},
    ):
        assert (
            client.post("/agent/v1/requests", json=payload, headers=agent).status_code
            == 202
        )
    stored = db.query(RequestMetric).one()
    assert (stored.requests, stored.s5xx, stored.p95_ms) == (15, 1, 80.0)

    traffic = client.get(
        f"{APPS}/{app['id']}/requests?range=1h", headers=admin_headers
    ).json()
    assert traffic["totals"]["requests"] == 15 and traffic["hosts"] == [
        "shop.example.com"
    ]
    assert traffic["totals"]["error_rate"] == round(1 / 15, 4)
    assert sum(p["requests"] for p in traffic["points"]) == 15

    # Another server can't report traffic for this server's domain.
    _, intruder = enrolled_agent(client, admin_headers, name="web-9")
    client.post("/agent/v1/requests", json={"rows": [row]}, headers=intruder)
    assert db.query(RequestMetric).one().requests == 15
