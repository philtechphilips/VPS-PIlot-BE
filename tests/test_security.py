"""Vulnerability scans and findings, security alerts, account events, rate
limits and response headers."""

from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.apps.models import Application, Deployment
from app.audit.models import AuditLog
from app.jobs.models import Job
from app.monitoring import service as monitoring
from app.monitoring.models import Alert, AlertRule
from app.security import eol, osv
from app.security import service as security
from app.security.models import AppFinding, AppScan
from app.servers.models import Server
from app.users.models import Role
from tests.conftest import AUTH, create_user, sign_in, start_login
from tests.test_apps import APPS, complete, git_app
from tests.test_jobs import claim
from tests.test_runtimes import _agent
from tests.test_servers import enrolled_agent

NEXT_ADVISORY = {
    "id": "GHSA-2464-fhr4-w9xw",
    "summary": "Next.js: Remote Code Execution in Image Optimization API",
    "aliases": [],
    "modified": "2026-10-20T00:00:00Z",
    "database_specific": {"severity": "CRITICAL"},
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "next"},
            "ranges": [{"events": [{"introduced": "10.0.0"}, {"fixed": "15.5.28"}]}],
        },
        {
            "package": {"ecosystem": "npm", "name": "next"},
            "ranges": [{"events": [{"introduced": "16.0.0"}, {"fixed": "16.4.1"}]}],
        },
    ],
}
OPENSSL_FIXED = {
    "id": "DEBIAN-CVE-2023-5678",
    "summary": "Excessively long X9.42 DH keys",
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    ],
    "affected": [
        {
            "package": {"ecosystem": "Debian:12", "name": "openssl"},
            "ranges": [
                {"events": [{"introduced": "0"}, {"fixed": "3.0.13-1~deb12u1"}]}
            ],
        }
    ],
}
ZLIB_UNFIXED = {
    "id": "DEBIAN-CVE-2023-45853",
    "summary": "zlib through 1.3 has an integer overflow",
    "affected": [
        {
            "package": {"ecosystem": "Debian:12", "name": "zlib"},
            "ranges": [{"events": [{"introduced": "0"}]}],
        }
    ],
}


# ---------------------------------------------------------------------------
# OSV helpers
# ---------------------------------------------------------------------------


def test_versions_pick_the_nearest_fix():
    assert osv.fixed_version(NEXT_ADVISORY, "npm", "next", "16.1.6") == "16.4.1"
    assert osv.fixed_version(NEXT_ADVISORY, "npm", "next", "14.2.0") == "15.5.28"
    assert osv.fixed_version(NEXT_ADVISORY, "npm", "next", "16.4.3") is None
    # Debian: "~" sorts before the release it precedes.
    assert osv.version_key("3.0.13-1~deb12u1") < osv.version_key("3.0.13-1")
    assert osv.version_key("3.0.11-1~deb12u2") < osv.version_key("3.0.13-1~deb12u1")
    assert osv.version_key("1:2.0") > osv.version_key("9.9")  # epochs win


def test_severity_from_rating_or_cvss():
    assert osv.severity(NEXT_ADVISORY) == "critical"
    assert osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L") == 5.3
    assert osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert osv.severity(OPENSSL_FIXED) == "critical"
    assert osv.severity(ZLIB_UNFIXED) == "unknown"


# ---------------------------------------------------------------------------
# Scans and findings
# ---------------------------------------------------------------------------


@pytest.fixture
def released(client, admin_headers, db: Session):
    """An app with a live deployment on a 1.1.7 agent."""
    server_id, agent = enrolled_agent(client, admin_headers)
    _agent(db, server_id, "1.1.7")
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    job = claim(client, agent)
    result = {"commit_sha": "a" * 40, "build_plan": "Next.js · pnpm 10 · Node 18"}
    assert complete(client, agent, job["id"], result=result).status_code == 202
    return server_id, agent, app


def report(app_name="shop", **extra):
    return {
        "app": app_name,
        "packages": [["npm", "next", "16.1.6"], ["npm", "react", "19.2.3"]],
        "lockfiles": ["pnpm-lock.yaml"],
        "os": {
            "ecosystem": "Debian:12",
            "id": "debian",
            "version": "12",
            "packages": [["openssl", "3.0.11-1~deb12u2"], ["zlib", "1:1.2.13"]],
        },
        "secrets": [{"path": ".env.production", "line": 3, "rule": "AWS access key"}],
        **extra,
    }


def fake_osv(monkeypatch):
    by_package = {
        ("npm", "next"): [NEXT_ADVISORY],
        ("Debian:12", "openssl"): [OPENSSL_FIXED],
        ("Debian:12", "zlib"): [ZLIB_UNFIXED],
    }

    def query(packages):
        return [
            [
                {"id": a["id"], "modified": a.get("modified")}
                for a in by_package.get((eco, name), [])
            ]
            for eco, name, _ in packages
        ]

    every = {a["id"]: a for found in by_package.values() for a in found}
    monkeypatch.setattr(osv, "query", query)
    monkeypatch.setattr(
        osv, "advisories", lambda db, wanted: {i: every[i] for i in wanted}
    )
    monkeypatch.setattr(
        eol,
        "end_of_life",
        lambda db, product, cycle: (
            date(2025, 4, 30)
            if (product, cycle) == ("nodejs", "18")
            else date(2028, 6, 30)
        ),
    )


def test_a_successful_deploy_queues_a_scan(client, db: Session, released):
    server_id, agent, app = released
    job = db.scalar(select(Job).where(Job.type == "apps.audit"))
    assert job is not None and job.server_id == server_id
    assert job.payload["apps"] == [
        {"app": "shop", "runtime": "docker", "context": ".", "service": ""}
    ]
    claimed = claim(client, agent)
    assert claimed["type"] == "apps.audit"


def test_older_agents_get_no_scan_jobs(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    _agent(db, server_id, "1.1.5")
    client.post(APPS, json=git_app(server_id), headers=admin_headers)
    complete(client, agent, claim(client, agent)["id"])
    assert db.scalar(select(Job).where(Job.type == "apps.audit")) is None
    app = db.scalar(select(Application))
    res = client.post(f"/api/v1/security/apps/{app.id}/scan", headers=admin_headers)
    assert res.status_code == 409 and "1.1.7" in res.json()["detail"]


def test_package_reports_only_for_the_agents_own_job_and_apps(
    client, admin_headers, db: Session, released
):
    _, agent, app = released
    job = db.scalar(select(Job).where(Job.type == "apps.audit"))
    url = "/agent/v1/app-packages"
    other_id, other = enrolled_agent(client, admin_headers, name="web-2")
    # Another server's agent can't report against this job.
    res = client.post(url, json={"job_id": job.id, **report()}, headers=other)
    assert res.status_code == 404
    # An app that isn't on the server is ignored.
    res = client.post(
        url, json={"job_id": job.id, **report("elsewhere")}, headers=agent
    )
    assert res.json() == {"stored": False}
    res = client.post(url, json={"job_id": job.id, **report()}, headers=agent)
    assert res.status_code == 202 and res.json() == {"stored": True}
    scan = db.get(AppScan, app["id"])
    assert scan.packages[0] == ["npm", "next", "16.1.6"]
    assert scan.os_ecosystem == "Debian:12" and scan.checked_at is None
    # Bounded: no unbounded lists from an agent.
    huge = report(packages=[["npm", f"p{i}", "1.0.0"] for i in range(20001)])
    res = client.post(url, json={"job_id": job.id, **huge}, headers=agent)
    assert res.status_code == 422


def test_check_turns_advisories_into_findings(
    client, admin_headers, db: Session, released, monkeypatch
):
    _, agent, app = released
    fake_osv(monkeypatch)
    job = db.scalar(select(Job).where(Job.type == "apps.audit"))
    client.post(
        "/agent/v1/app-packages", json={"job_id": job.id, **report()}, headers=agent
    )
    security.check_app(db, app["id"])

    body = client.get(
        f"/api/v1/security/apps/{app['id']}", headers=admin_headers
    ).json()
    by_kind = {}
    for f in body["findings"]:
        by_kind.setdefault(f["kind"], []).append(f)
    dep = by_kind["dependency"][0]
    assert (dep["package"], dep["version"], dep["fixed"]) == (
        "next",
        "16.1.6",
        "16.4.1",
    )
    assert dep["severity"] == "critical" and dep["advisory"] == "GHSA-2464-fhr4-w9xw"
    # OS packages only count when the distro has a fix.
    assert [f["package"] for f in by_kind["os"]] == ["openssl"]
    assert by_kind["secret"][0]["path"] == ".env.production:3"
    titles = [f["title"] for f in by_kind["eol"]]
    assert titles == ["Node.js 18 stopped getting security fixes on 30 Apr 2025"]
    assert body["counts"]["critical"] == 2 and body["scan"]["packages"] == 2


def test_ignores_and_first_seen_survive_a_recheck(
    client, admin_headers, db: Session, released, monkeypatch
):
    _, agent, app = released
    fake_osv(monkeypatch)
    job = db.scalar(select(Job).where(Job.type == "apps.audit"))
    client.post(
        "/agent/v1/app-packages", json={"job_id": job.id, **report()}, headers=agent
    )
    security.check_app(db, app["id"])
    finding = db.scalar(select(AppFinding).where(AppFinding.kind == "dependency"))
    first_seen = finding.first_seen_at
    res = client.post(
        f"/api/v1/security/findings/{finding.id}/ignore",
        json={"ignored": True},
        headers=admin_headers,
    )
    assert res.status_code == 200 and res.json()["ignored_by"] == "admin@example.com"
    security.check_app(db, app["id"])
    again = db.scalar(select(AppFinding).where(AppFinding.kind == "dependency"))
    assert again.id != finding.id  # rebuilt...
    assert again.ignored_at is not None and again.first_seen_at == first_seen


def test_without_lookups_only_secrets_are_checked(
    client, admin_headers, db: Session, released, monkeypatch
):
    _, agent, app = released
    res = client.put(
        "/api/v1/platform", json={"vuln_checks": False}, headers=admin_headers
    )
    assert res.status_code == 200 and res.json()["vuln_checks"] is False

    def no_network(*args):
        raise AssertionError("OSV must not be called")

    monkeypatch.setattr(osv, "query", no_network)
    job = db.scalar(select(Job).where(Job.type == "apps.audit"))
    client.post(
        "/agent/v1/app-packages", json={"job_id": job.id, **report()}, headers=agent
    )
    security.check_app(db, app["id"])
    kinds = set(db.scalars(select(AppFinding.kind)))
    assert kinds == {"secret"}


def test_an_osv_outage_keeps_the_last_findings(
    db: Session, released, client, monkeypatch
):
    _, agent, app = released
    fake_osv(monkeypatch)
    job = db.scalar(select(Job).where(Job.type == "apps.audit"))
    client.post(
        "/agent/v1/app-packages", json={"job_id": job.id, **report()}, headers=agent
    )
    security.check_app(db, app["id"])
    before = db.query(AppFinding).count()

    def down(packages):
        raise osv.OsvError("OSV.dev didn't answer")

    monkeypatch.setattr(osv, "query", down)
    security.check_app(db, app["id"])
    assert db.query(AppFinding).count() == before
    assert db.get(AppScan, app["id"]).check_error == "OSV.dev didn't answer"


# ---------------------------------------------------------------------------
# Alert rules
# ---------------------------------------------------------------------------


def test_security_rules_fire(client, db: Session, released, monkeypatch):
    server_id, agent, app = released
    fake_osv(monkeypatch)
    job = db.scalar(select(Job).where(Job.type == "apps.audit"))
    client.post(
        "/agent/v1/app-packages", json={"job_id": job.id, **report()}, headers=agent
    )
    security.check_app(db, app["id"])
    monitoring.evaluate(db)
    fired = {
        db.get(AlertRule, a.rule_id).kind: a
        for a in db.scalars(select(Alert).where(Alert.state == "firing"))
    }
    vulns = fired["vulnerable_deps"]
    assert vulns.value == 2
    assert "next 16.1.6 (fixed in 16.4.1)" in vulns.detail
    assert "openssl" in vulns.detail
    assert ".env.production:3" in fired["secrets_committed"].detail
    assert "Node.js 18" in fired["runtime_eol"].detail

    # Ignoring the findings resolves the alert.
    for f in db.scalars(
        select(AppFinding).where(AppFinding.kind.in_(("dependency", "os")))
    ):
        f.ignored_at = datetime.now(UTC)
    db.commit()
    monitoring.evaluate(db)
    assert db.get(Alert, vulns.id).state == "resolved"


def test_outdated_agents_alert_after_three_days(client, admin_headers, db: Session):
    server_id, _ = enrolled_agent(client, admin_headers)
    _agent(db, server_id, "1.1.4")
    now = datetime.now(UTC)
    monitoring.evaluate(db, now)
    rule = db.scalar(select(AlertRule).where(AlertRule.kind == "agent_outdated"))
    alert = db.scalar(select(Alert).where(Alert.rule_id == rule.id))
    assert alert.state == "pending"
    monitoring.evaluate(db, now + timedelta(days=3, minutes=1))
    assert db.get(Alert, alert.id).state == "firing"
    assert "latest 1.1.7" in db.get(Alert, alert.id).detail
    _agent(db, server_id, "1.1.7")
    monitoring.evaluate(db, now + timedelta(days=3, minutes=2))
    assert db.get(Alert, alert.id).state == "resolved"


# ---------------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------------


def test_apps_never_scanned_get_one_scan_an_hour(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    _agent(db, server_id, "1.1.5")
    client.post(APPS, json=git_app(server_id), headers=admin_headers)
    complete(client, agent, claim(client, agent)["id"])
    _agent(db, server_id, "1.1.7")  # upgraded after the deploy
    security.run_due(db)
    security.run_due(db)
    assert db.query(Job).filter(Job.type == "apps.audit").count() == 1


def test_weekly_rebuild_redeploys_the_live_commit(
    client, admin_headers, db: Session, released
):
    _, _, app = released
    res = client.put(
        f"/api/v1/security/apps/{app['id']}/auto-rebuild",
        json={"enabled": True},
        headers=admin_headers,
    )
    assert res.json() == {"auto_rebuild": True}
    security.rebuild_due(db)
    assert db.query(Deployment).count() == 1  # deployed today: not yet
    live = db.scalar(select(Deployment))
    live.created_at = datetime.now(UTC) - timedelta(days=8)
    db.commit()
    security.rebuild_due(db)
    rebuild = db.scalar(select(Deployment).where(Deployment.trigger == "rebuild"))
    assert rebuild is not None and rebuild.requested_ref == "a" * 40
    security.rebuild_due(db)  # one at a time
    assert db.query(Deployment).filter(Deployment.trigger == "rebuild").count() == 1


def test_weekly_report_lists_security(client, db: Session, released, monkeypatch):
    from app.notifications import weekly

    _, agent, app = released
    fake_osv(monkeypatch)
    job = db.scalar(select(Job).where(Job.type == "apps.audit"))
    client.post(
        "/agent/v1/app-packages", json={"job_id": job.id, **report()}, headers=agent
    )
    security.check_app(db, app["id"])
    sections = dict(weekly.build(db)["sections"])
    lines = sections["Security"]
    assert any("shop: 2 critical/high with a fix" in line for line in lines)
    assert any("possible secrets" in line for line in lines)


# ---------------------------------------------------------------------------
# Account events, rate limits, headers
# ---------------------------------------------------------------------------


def _login_from(client, outbox, email, ip):
    client.headers["X-Forwarded-For"] = ip
    try:
        return sign_in(client, outbox, email)
    finally:
        del client.headers["X-Forwarded-For"]


def test_sign_in_from_a_new_address_is_reported(client, db: Session, outbox):
    create_user(db, "owner@example.com", role=Role.ADMIN)
    _login_from(client, outbox, "owner@example.com", "203.0.113.5")  # first ever
    _login_from(client, outbox, "owner@example.com", "203.0.113.5")  # known
    assert not db.scalars(
        select(AuditLog).where(AuditLog.action == "security.new_sign_in")
    ).all()
    _login_from(client, outbox, "owner@example.com", "198.51.100.7")
    event = db.scalar(select(AuditLog).where(AuditLog.action == "security.new_sign_in"))
    assert "198.51.100.7" in event.detail
    mail = [m for m in outbox if m.subject.startswith("Security:")]
    assert mail and mail[-1].to == "owner@example.com"


def test_lockout_and_role_changes_are_reported(client, admin_headers, db: Session):
    target = create_user(db, "viewer@example.com", role=Role.VIEWER)
    for _ in range(5):
        start_login(client, "viewer@example.com", "wrong-password")
    assert db.scalar(
        select(AuditLog).where(AuditLog.action == "security.account_locked")
    )
    res = client.patch(
        f"/api/v1/users/{target.id}/role", json={"role": "admin"}, headers=admin_headers
    )
    assert res.status_code == 200
    event = db.scalar(
        select(AuditLog).where(AuditLog.action == "security.role_changed")
    )
    assert event.target_label == "viewer@example.com"


def test_logins_are_rate_limited_per_address(client, db: Session):
    for i in range(10):
        client.headers["X-Forwarded-For"] = "203.0.113.9"
        start_login(client, f"nobody{i}@example.com", "x" * 12)
    res = start_login(client, "nobody@example.com", "x" * 12)
    assert res.status_code == 429 and "Retry-After" in res.headers
    client.headers["X-Forwarded-For"] = "203.0.113.10"
    assert start_login(client, "nobody@example.com", "x" * 12).status_code == 401
    del client.headers["X-Forwarded-For"]


def test_api_responses_carry_security_headers(client):
    res = client.get(f"{AUTH}/setup-status")
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert res.headers["Referrer-Policy"] == "no-referrer"
    assert "Strict-Transport-Security" not in res.headers  # plain HTTP here
    # Behind Caddy, uvicorn's proxy headers make the scheme https.
    https = client.get(f"https://testserver{AUTH}/setup-status")
    assert https.headers["Strict-Transport-Security"] == "max-age=31536000"


def test_overview_lists_apps_agents_and_events(
    client, admin_headers, db: Session, released, monkeypatch
):
    server_id, agent, app = released
    fake_osv(monkeypatch)
    job = db.scalar(select(Job).where(Job.type == "apps.audit"))
    client.post(
        "/agent/v1/app-packages", json={"job_id": job.id, **report()}, headers=agent
    )
    security.check_app(db, app["id"])
    other_id, _ = enrolled_agent(client, admin_headers, name="old-box")
    _agent(db, other_id, "1.1.2")
    body = client.get("/api/v1/security/overview", headers=admin_headers).json()
    row = next(r for r in body["apps"] if r["name"] == "shop")
    assert (
        row["fixable"] == 2 and row["secrets"] == 1 and row["counts"]["critical"] == 2
    )
    assert [a["name"] for a in body["outdated_agents"]] == ["old-box"]
    assert db.get(Server, server_id).agent_version == "1.1.7"


def test_cached_advisories_compare_osv_timestamps_exactly():
    # The batch query reports microseconds, the advisory itself nanoseconds.
    assert osv._stamp("2026-09-10T03:50:48.280629201Z") == osv._stamp(
        "2026-09-10T03:50:48.280629Z"
    )
    assert osv._stamp("2026-09-10T03:50:48Z") < osv._stamp("2026-09-10T03:50:48.1Z")
