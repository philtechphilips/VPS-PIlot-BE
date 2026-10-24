"""The weekly report."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domains.models import Domain, UptimeCheck
from app.notifications import weekly
from app.notifications.models import Notification
from app.platform import service as platform
from tests.test_apps import APPS, git_app
from tests.test_servers import enrolled_agent

MONDAY_9 = datetime(2026, 10, 26, 8, 0, tzinfo=UTC)  # 09:00 in Lagos


def test_report_sums_up_the_week(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    db.add(Domain(id="d" * 32, hostname="shop.example.com", server_id=server_id,
                  application_id=app["id"], tls_mode="auto", status="active",
                  created_by="t"))  # fmt: skip
    now = datetime.now(UTC)
    for minutes, ok in ((10, True), (20, True), (30, True), (40, False)):
        db.add(
            UptimeCheck(domain_id="d" * 32, ts=now - timedelta(minutes=minutes), ok=ok)
        )
    db.commit()
    minute = int(now.timestamp()) // 60 * 60
    client.post(
        "/agent/v1/app-errors",
        json={"rows": [{"app": "shop", "minute": minute, "errors": 7, "sample": "x"}]},
        headers=agent,
    )
    report = weekly.build(db, now + timedelta(minutes=1))
    sections = dict(report["sections"])
    assert sections["Uptime"] == ["shop.example.com: 75.00%"]
    assert sections["Deploys"] == ["1 deploys: 0 succeeded"]
    assert sections["App errors"] == ["shop: 7 error lines"]
    assert sections["Alerts"] == ["None fired. A quiet week."]
    assert "• shop.example.com: 75.00%" in weekly.as_text(report)


def test_sent_monday_morning_in_the_chosen_timezone(client, admin_headers, db: Session):
    row = platform.get(db)
    row.report_timezone = "Africa/Lagos"
    db.commit()
    # Turning it on doesn't send a report for the week already under way.
    assert weekly.run_due(db, MONDAY_9 - timedelta(days=2)) is False
    assert weekly.run_due(db, MONDAY_9 - timedelta(hours=2)) is False  # Mon 07:00
    assert weekly.run_due(db, MONDAY_9) is True
    assert weekly.run_due(db, MONDAY_9 + timedelta(hours=3)) is False  # once a week
    assert weekly.run_due(db, MONDAY_9 + timedelta(days=7)) is True
    notes = db.scalars(select(Notification).where(Notification.kind == "report.weekly"))
    assert "Your week on VPSPilot" in next(notes).title


def test_send_now_and_settings(client, admin_headers):
    sent = client.post("/api/v1/platform/weekly-report", headers=admin_headers)
    assert sent.status_code == 202 and sent.json()["title"].startswith("Your week")
    bad = client.put(
        "/api/v1/platform", json={"report_timezone": "Mars/Base"}, headers=admin_headers
    )
    assert bad.status_code == 422
    ok = client.put(
        "/api/v1/platform",
        json={"report_timezone": "Africa/Lagos", "weekly_report": False},
        headers=admin_headers,
    ).json()
    assert ok["report_timezone"] == "Africa/Lagos" and ok["weekly_report"] is False
