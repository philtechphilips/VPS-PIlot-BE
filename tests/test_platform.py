from app import __version__
from app.agent_version import AGENT_VERSION
from tests.conftest import AUTH, PASSWORD
from tests.test_servers import create_enrollment

PLATFORM = "/api/v1/platform"


def test_versions_match():
    import vpspilot_agent

    assert AGENT_VERSION == vpspilot_agent.__version__
    assert __version__


def test_public_url_drives_install_commands(client, admin_headers):
    body = client.get(PLATFORM, headers=admin_headers).json()
    assert body["name"] == "VPSPilot" and body["public_url"] is None
    updated = client.put(
        PLATFORM,
        json={"name": "Acme Ops", "public_url": "https://pilot.acme.dev/"},
        headers=admin_headers,
    ).json()
    assert (
        updated["agent_url"] == "https://pilot.acme.dev"
        and updated["webhook_url"] == "https://pilot.acme.dev/api/v1/github/webhook"
    )
    enrollment = create_enrollment(client, admin_headers, "web-9")
    assert enrollment["install_command"].startswith(
        "curl -fsSL https://pilot.acme.dev/agent/install.sh"
    )
    assert 'API_URL="https://pilot.acme.dev"' in client.get("/agent/install.sh").text
    assert (
        client.put(
            PLATFORM, json={"public_url": "ftp://x"}, headers=admin_headers
        ).status_code
        == 422
    )
    cleared = client.put(
        PLATFORM, json={"public_url": ""}, headers=admin_headers
    ).json()
    assert cleared["public_url"] is None


def test_change_password_signs_out_other_sessions(client, admin_headers, user_headers):
    wrong = client.post(
        f"{AUTH}/password",
        json={"current_password": "nope", "new_password": "a-new-strong-passphrase"},
        headers=admin_headers,
    )
    assert wrong.status_code == 400
    short = client.post(
        f"{AUTH}/password",
        json={"current_password": PASSWORD, "new_password": "short"},
        headers=admin_headers,
    )
    assert short.status_code == 422
    ok = client.post(
        f"{AUTH}/password",
        json={"current_password": PASSWORD, "new_password": "a-new-strong-passphrase"},
        headers=admin_headers,
    )
    assert ok.status_code == 200
    # The session that changed it keeps working.
    assert client.get(f"{AUTH}/me", headers=admin_headers).status_code == 200


def test_enrollment_tokens_list_and_revoke(client, admin_headers):
    create_enrollment(client, admin_headers, "web-7")
    tokens = client.get("/api/v1/servers/enrollments", headers=admin_headers).json()
    assert tokens[0]["server_name"] == "web-7" and tokens[0]["state"] == "pending"
    assert (
        client.delete(
            f"/api/v1/servers/enrollments/{tokens[0]['id']}", headers=admin_headers
        ).status_code
        == 204
    )
    assert client.get("/api/v1/servers/enrollments", headers=admin_headers).json() == []


def test_recovery_kit_needs_the_password_and_is_audited(
    client, admin_headers, user_headers, db
):
    from app.audit.models import AuditLog
    from app.backups import service as backups
    from app.core.security import decrypt_secret

    url = "/api/v1/platform/recovery-kit"
    assert (
        client.post(url, json={"password": "x"}, headers=user_headers).status_code
        == 403
    )
    wrong = client.post(url, json={"password": "wrong-password"}, headers=admin_headers)
    assert wrong.status_code == 403
    kit = client.post(url, json={"password": PASSWORD}, headers=admin_headers)
    assert kit.status_code == 200
    assert "attachment" in kit.headers["content-disposition"]
    assert kit.headers["cache-control"] == "no-store"
    key = decrypt_secret(backups.get_settings(db).encryption_key, backups.PURPOSE)
    assert f"VPB_KEY={key}" in kit.text
    assert "SECRET_KEY=" in kit.text and "pg_restore" in kit.text
    results = [
        a.result for a in db.query(AuditLog).filter_by(action="platform.recovery_kit")
    ]
    assert sorted(results) == ["denied", "success"]
    platform = client.get("/api/v1/platform", headers=admin_headers).json()
    assert platform["recovery_kit_at"] is not None
