"""Password-protected and IP-restricted sites."""

import bcrypt
import pytest
from sqlalchemy.orm import Session
from vpspilot_agent import proxy

from app.domains import service as domains
from app.domains.models import Domain
from tests.test_apps import APPS, git_app
from tests.test_servers import enrolled_agent

HASH = bcrypt.hashpw(b"hunter22", bcrypt.gensalt(4)).decode()


def test_protected_sites_render_auth_and_allowlist():
    sites = proxy._sites(
        {
            "sites": [
                {
                    "host": "staging.example.com",
                    "tls": "auto",
                    "upstream": "vp-shop:3000",
                    "auth": {"user": "team", "hash": HASH},
                    "allow": ["203.0.113.0/24", "198.51.100.7"],
                }
            ]
        }
    )
    text = proxy.render(sites, None)
    assert "\t@blocked not remote_ip 203.0.113.0/24 198.51.100.7/32" in text
    assert '\trespond @blocked "Forbidden" 403' in text
    assert f"\tbasic_auth {{\n\t\tteam {HASH}\n\t}}" in text


@pytest.mark.parametrize(
    "bad",
    [
        {"auth": {"user": "team", "hash": "plain-password"}},
        {"auth": {"user": "a b", "hash": HASH}},
        {"allow": ["not-an-ip"]},
    ],
)
def test_bad_protection_is_refused(bad):
    site = {"host": "a.example.com", "tls": "auto", "upstream": "vp-shop:3000", **bad}
    with pytest.raises(proxy.Rejected):
        proxy._sites({"sites": [site]})


def test_setting_a_password_and_allowlist(client, admin_headers, db: Session):
    server_id, _ = enrolled_agent(client, admin_headers)
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    db.add(Domain(id="d" * 32, hostname="staging.example.com", server_id=server_id,
                  application_id=app["id"], tls_mode="auto", status="active",
                  created_by="t"))  # fmt: skip
    db.commit()
    url = f"/api/v1/domains/{'d' * 32}/access"
    short = client.put(url, json={"password": "short"}, headers=admin_headers)
    assert short.status_code == 422
    out = client.put(
        url,
        json={"user": "team", "password": "hunter22!", "allow": ["203.0.113.0/24"]},
        headers=admin_headers,
    ).json()
    assert out["access"] == {
        "user": "team",
        "password": True,
        "allow": ["203.0.113.0/24"],
    }
    site = domains.desired_sites(db, server_id)[0]
    assert bcrypt.checkpw(b"hunter22!", site["auth"]["hash"].encode())
    assert site["allow"] == ["203.0.113.0/24"]

    cleared = client.put(
        url, json={"remove_password": True, "allow": []}, headers=admin_headers
    ).json()
    assert cleared["access"] == {"user": None, "password": False, "allow": []}
    assert "auth" not in domains.desired_sites(db, server_id)[0]
