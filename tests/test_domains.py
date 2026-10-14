import json
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.domains import service as domains
from app.domains.models import Domain
from app.monitoring import service as monitoring
from tests.test_apps import APPS, git_app
from tests.test_jobs import claim
from tests.test_servers import enrolled_agent

DOM = "/api/v1/domains"


def setup(client, headers, monkeypatch):
    monkeypatch.setattr(
        domains,
        "_resolve",
        lambda host: ["203.0.113.7"] if host.endswith("example.com") else [],
    )
    server_id, agent = enrolled_agent(client, headers)
    app = client.post(
        APPS, json=git_app(server_id, deploy=False), headers=headers
    ).json()
    return server_id, agent, app


def finish(client, agent, job_id, ok=True, output=None):
    client.post(
        f"/agent/v1/jobs/{job_id}/complete",
        json={
            "status": "succeeded" if ok else "failed",
            "output": json.dumps(output) if output else "",
            "error": None if ok else "Port 80 is already used by another program",
        },
        headers=agent,
    )


def test_add_domain_with_www_redirect(client, admin_headers, monkeypatch, db: Session):
    _, agent, app = setup(client, admin_headers, monkeypatch)
    r = client.post(
        DOM,
        json={
            "hostname": "Shop.Example.com.",
            "application_id": app["id"],
            "redirect_www": True,
        },
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    hosts = {d["hostname"]: d for d in r.json()}
    assert set(hosts) == {"shop.example.com", "www.shop.example.com"}
    assert hosts["www.shop.example.com"]["redirect_to"] == "shop.example.com"
    assert hosts["shop.example.com"]["dns_addresses"] == ["203.0.113.7"]
    assert hosts["shop.example.com"]["status"] == "pending"
    job = claim(client, agent)
    assert job["type"] == "proxy.apply"
    sites = [
        {k: v for k, v in s.items() if v is not None} for s in job["payload"]["sites"]
    ]
    assert sites == [
        {"host": "shop.example.com", "tls": "auto", "upstream": "vp-shop:3000"},
        {
            "host": "www.shop.example.com",
            "tls": "auto",
            "redirect_to": "shop.example.com",
        },
    ]
    finish(client, agent, job["id"])
    assert {d["status"] for d in client.get(DOM, headers=admin_headers).json()} == {
        "active"
    }


def test_validation_and_duplicates(client, admin_headers, monkeypatch):
    _, _, app = setup(client, admin_headers, monkeypatch)
    for bad in (
        "https://shop.example.com",
        "shop",
        "-bad-.example.com",
        "a" * 64 + ".com",
        "shop.example.com/path",
    ):
        r = client.post(
            DOM,
            json={"hostname": bad, "application_id": app["id"]},
            headers=admin_headers,
        )
        assert r.status_code == 422, bad
    client.post(
        DOM,
        json={"hostname": "shop.example.com", "application_id": app["id"]},
        headers=admin_headers,
    )
    again = client.post(
        DOM,
        json={"hostname": "SHOP.example.com", "application_id": app["id"]},
        headers=admin_headers,
    )
    assert again.status_code == 409


def test_failed_apply_is_reported(client, admin_headers, monkeypatch):
    _, agent, app = setup(client, admin_headers, monkeypatch)
    client.post(
        DOM,
        json={"hostname": "shop.example.com", "application_id": app["id"]},
        headers=admin_headers,
    )
    finish(client, agent, claim(client, agent)["id"], ok=False)
    d = client.get(DOM, headers=admin_headers).json()[0]
    assert d["status"] == "error" and "Port 80" in d["error"]


def test_removing_a_domain_or_app_reapplies(
    client, admin_headers, monkeypatch, db: Session
):
    _, agent, app = setup(client, admin_headers, monkeypatch)
    created = client.post(
        DOM,
        json={
            "hostname": "shop.example.com",
            "application_id": app["id"],
            "redirect_www": True,
        },
        headers=admin_headers,
    ).json()
    claim(client, agent)
    main = next(d for d in created if not d["redirect_to"])
    assert (
        client.delete(f"{DOM}/{main['id']}", headers=admin_headers).status_code == 204
    )
    job = claim(client, agent)
    assert job["payload"]["sites"] == []  # the www redirect went with it
    client.post(
        DOM,
        json={"hostname": "shop.example.com", "application_id": app["id"]},
        headers=admin_headers,
    )
    claim(client, agent)
    client.delete(f"{APPS}/{app['id']}", headers=admin_headers)
    jobs_after = [claim(client, agent), claim(client, agent)]
    applies = [j for j in jobs_after if j and j["type"] == "proxy.apply"]
    assert applies and applies[-1]["payload"]["sites"] == []
    assert db.query(Domain).count() == 0


def test_certificate_status_and_expiry_alert(
    client, admin_headers, monkeypatch, db: Session
):
    _, agent, app = setup(client, admin_headers, monkeypatch)
    created = client.post(
        DOM,
        json={"hostname": "shop.example.com", "application_id": app["id"]},
        headers=admin_headers,
    ).json()
    finish(client, agent, claim(client, agent)["id"])
    check = client.post(f"{DOM}/{created[0]['id']}/check", headers=admin_headers).json()
    job = claim(client, agent)
    assert job["id"] == check["job_id"] and job["payload"]["hosts"] == [
        "shop.example.com"
    ]
    expires = (datetime.now(UTC) + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
    finish(
        client,
        agent,
        job["id"],
        output={
            "running": True,
            "certificates": [
                {
                    "host": "shop.example.com",
                    "ok": True,
                    "issuer": "Let's Encrypt",
                    "not_after": expires,
                }
            ],
        },
    )
    d = client.get(DOM, headers=admin_headers).json()[0]
    assert d["cert_issuer"] == "Let's Encrypt" and d["cert_days_left"] in (4, 5)
    assert monitoring.evaluate(db)["fired"] >= 1
    alert = next(
        a
        for a in client.get("/api/v1/monitoring/alerts", headers=admin_headers).json()
        if a["title"] == "Certificate expiring"
    )
    assert (
        alert["target_label"] == "shop.example.com" and "expires in" in alert["detail"]
    )


def test_container_port_change_reapplies(client, admin_headers, monkeypatch):
    _, agent, app = setup(client, admin_headers, monkeypatch)
    client.post(
        DOM,
        json={"hostname": "shop.example.com", "application_id": app["id"]},
        headers=admin_headers,
    )
    claim(client, agent)
    client.patch(
        f"{APPS}/{app['id']}", json={"container_port": 8080}, headers=admin_headers
    )
    job = claim(client, agent)
    assert (
        job["type"] == "proxy.apply"
        and job["payload"]["sites"][0]["upstream"] == "vp-shop:8080"
    )
