"""Public status pages."""

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.domains import status_pages
from app.domains.models import Domain, UptimeCheck
from tests.test_apps import APPS, git_app
from tests.test_servers import enrolled_agent


def _site(client, admin_headers, db):
    server_id, _ = enrolled_agent(client, admin_headers)
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    for i, host in enumerate(("shop.example.com", "api.example.com")):
        db.add(Domain(id=str(i) * 32, hostname=host, server_id=server_id,
                      application_id=app["id"], tls_mode="auto", status="active",
                      created_by="t"))  # fmt: skip
    db.commit()
    now = datetime.now(UTC)
    for minutes, ok in ((60, True), (30, False), (1, True)):
        db.add(
            UptimeCheck(domain_id="0" * 32, ts=now - timedelta(minutes=minutes), ok=ok)
        )
    db.add(UptimeCheck(domain_id="1" * 32, ts=now - timedelta(minutes=1), ok=False,
                       error="HTTP 502"))  # fmt: skip
    db.commit()


def test_status_page_is_public_and_shows_only_what_it_should(
    client, admin_headers, db: Session
):
    _site(client, admin_headers, db)
    made = client.post(
        "/api/v1/status-pages",
        json={
            "slug": "acme",
            "title": "Acme status",
            "components": [
                {"domain_id": "0" * 32, "label": "Website"},
                {"domain_id": "1" * 32, "label": "API"},
            ],
        },
        headers=admin_headers,
    )
    assert made.status_code == 201, made.text
    status_pages._cache.clear()
    page = client.get("/api/v1/status/acme")  # no sign-in
    assert page.status_code == 200
    body = page.json()
    assert body["title"] == "Acme status" and body["overall"] == "degraded"
    website, api = body["components"]
    assert (website["label"], website["status"]) == ("Website", "up")
    assert api["status"] == "down" and len(website["days"]) == 30
    assert round(website["uptime"]) == 67  # 2 of 3 checks
    text = page.text
    for private in ("example.com", "web-1", "HTTP 502", "server"):
        assert private not in text
    assert client.get("/api/v1/status/nope").status_code == 404


def test_slugs_are_unique_and_simple(client, admin_headers, db: Session):
    _site(client, admin_headers, db)
    ok = {"slug": "acme", "components": [{"domain_id": "0" * 32}]}
    assert (
        client.post("/api/v1/status-pages", json=ok, headers=admin_headers).status_code
        == 201
    )
    again = client.post("/api/v1/status-pages", json=ok, headers=admin_headers)
    assert again.status_code == 409
    bad = client.post(
        "/api/v1/status-pages", json={"slug": "Bad Slug"}, headers=admin_headers
    )
    assert bad.status_code == 422
