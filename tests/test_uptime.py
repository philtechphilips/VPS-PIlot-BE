"""Uptime checks of domains and the Site down alert."""

import socket
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domains import uptime
from app.domains.models import Domain, UptimeCheck
from app.monitoring import service as monitoring
from app.monitoring.models import Alert, AlertRule
from tests.test_apps import APPS, git_app
from tests.test_servers import enrolled_agent


@pytest.fixture
def site():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server's name
            code = {"/health": 200, "/broken": 503, "/login": 401}.get(self.path, 404)
            self.send_response(code)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_probe_reads_what_a_visitor_would_see(site):
    up = uptime.probe(f"{site}/health")
    assert up.ok and up.status == 200 and up.ms is not None
    down = uptime.probe(f"{site}/broken")
    assert not down.ok and down.error == "HTTP 503"
    assert uptime.probe(f"{site}/login").ok  # a login page is a working site

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    refused = uptime.probe(f"http://127.0.0.1:{port}/")
    assert not refused.ok and refused.error == "Connection refused"


def _domain(client, admin_headers, db, tls="auto"):
    server_id, _ = enrolled_agent(client, admin_headers)
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    domain = Domain(id="d" * 32, hostname="shop.example.com", server_id=server_id,
                    application_id=app["id"], tls_mode=tls, status="active",
                    created_by="t")  # fmt: skip
    db.add(domain)
    db.commit()
    return domain


def test_checks_run_once_a_minute_per_domain(
    client, admin_headers, db: Session, monkeypatch
):
    domain = _domain(client, admin_headers, db)
    seen = []

    def fake_probe(url, verify=True):
        seen.append((url, verify))
        return uptime.Probe(True, 200, 42.0, None)

    monkeypatch.setattr(uptime, "probe", fake_probe)
    now = datetime.now(UTC)
    assert uptime.check_due(db, now) == 1
    assert seen == [("https://shop.example.com/health", True)]
    assert uptime.check_due(db, now + timedelta(seconds=20)) == 0
    assert uptime.check_due(db, now + timedelta(seconds=60)) == 1

    listed = client.get("/api/v1/domains", headers=admin_headers).json()[0]
    assert listed["uptime"]["up"] is True and listed["uptime"]["uptime_24h"] == 100
    chart = client.get(
        f"/api/v1/domains/{domain.id}/uptime?range=24h", headers=admin_headers
    ).json()
    assert chart["uptime"] == 100 and chart["checks"] == 2
    assert chart["url"] == "https://shop.example.com/health"


def test_site_down_alert_fires_after_its_duration_and_resolves(
    client, admin_headers, db: Session
):
    domain = _domain(client, admin_headers, db)
    monitoring.ensure_default_rules(db)
    rule = db.scalars(select(AlertRule).where(AlertRule.kind == "site_down")).one()
    assert (rule.duration_minutes, rule.severity) == (2, "critical")
    now = datetime.now(UTC)

    def check(minutes_ago, ok):
        db.add(UptimeCheck(domain_id=domain.id, ts=now - timedelta(minutes=minutes_ago),
                           ok=ok, status_code=200 if ok else 502,
                           ms=30.0 if ok else None,
                           error=None if ok else "HTTP 502"))  # fmt: skip
        db.commit()

    check(5, True)
    check(1, False)
    monitoring.evaluate(db, now)  # down for a minute: not yet
    assert db.scalars(select(Alert).where(Alert.rule_id == rule.id)).first() is None

    check(3, False)  # failing since 3 minutes ago
    assert monitoring.evaluate(db, now)["fired"] == 1
    alert = db.scalars(select(Alert).where(Alert.rule_id == rule.id)).one()
    assert alert.target_label == "shop.example.com"
    assert alert.detail == "HTTP 502 for 3 min"

    check(0, True)
    assert monitoring.evaluate(db, now + timedelta(seconds=5))["resolved"] == 1


# ---------------------------------------------------------------------------
# High error rate (from the proxy's request counts)
# ---------------------------------------------------------------------------


def test_error_rate_alert(client, admin_headers, db: Session):
    from app.apps.models import RequestMetric

    domain = _domain(client, admin_headers, db)
    monitoring.ensure_default_rules(db)
    rule = db.scalars(select(AlertRule).where(AlertRule.kind == "error_rate")).one()
    now = datetime.now(UTC).replace(second=30)

    def minute(ago, requests, s5xx):
        db.add(RequestMetric(server_id=domain.server_id, host=domain.hostname,
                             application_id=domain.application_id,
                             minute=(now - timedelta(minutes=ago)).replace(second=0),
                             requests=requests, s2xx=requests - s5xx, s3xx=0, s4xx=0,
                             s5xx=s5xx, bytes=0, p50_ms=1, p95_ms=2))  # fmt: skip
        db.commit()

    minute(1, 10, 5)  # half failing, but only 10 requests: too few to judge
    monitoring.evaluate(db, now)
    assert db.scalars(select(Alert).where(Alert.rule_id == rule.id)).first() is None

    minute(2, 90, 5)  # 10 of 100 failed: above 5%
    assert monitoring.evaluate(db, now)["fired"] == 1
    alert = db.scalars(select(Alert).where(Alert.rule_id == rule.id)).one()
    assert alert.detail.startswith("10.0% of 100 requests failed with 5xx")

    later = now + timedelta(minutes=10)
    for ago in range(5):
        db.add(RequestMetric(server_id=domain.server_id, host=f"h{ago}.example.com",
                             application_id=domain.application_id,
                             minute=(later - timedelta(minutes=ago)).replace(second=0),
                             requests=100, s2xx=100, s3xx=0, s4xx=0, s5xx=0, bytes=0,
                             p50_ms=1, p95_ms=2))  # fmt: skip
    db.commit()
    assert monitoring.evaluate(db, later)["resolved"] == 1


def test_thresholds_follow_their_unit(client, admin_headers):
    rules = "/api/v1/monitoring/rules"
    post = lambda body: client.post(rules, json=body, headers=admin_headers)  # noqa: E731
    assert post({"kind": "error_rate", "threshold": 0}).status_code == 422
    assert post({"kind": "error_rate", "threshold": 100}).status_code == 422
    assert post({"kind": "error_rate", "threshold": 0.5}).status_code == 201
    assert post({"kind": "backup_stale", "threshold": 168}).status_code == 201
