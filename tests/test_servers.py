import io
import tarfile
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.core.config import settings
from app.servers.models import EnrollmentToken, MetricSample, Server

SERVERS = "/api/v1/servers"


def sample(**overrides):
    base = {
        "ts": datetime.now(UTC).isoformat(),
        "cpu_percent": 12.5,
        "memory_percent": 40.0,
        "memory_used": 800_000_000,
        "swap_percent": 0.0,
        "disk_percent": 30.0,
        "disk_used": 5_000_000_000,
        "inode_percent": 4.0,
        "load_1": 0.2,
        "load_5": 0.1,
        "load_15": 0.05,
        "net_rx_bps": 1000.0,
        "net_tx_bps": 500.0,
    }
    return {**base, **overrides}


FACTS = {
    "hostname": "web-1",
    "os_name": "Ubuntu",
    "os_version": "24.04.5 LTS (Noble Numbat)",
    "kernel": "6.8.0",
    "arch": "aarch64",
    "cpu_count": 2,
    "memory_total": 1_500_000_000,
    "disk_total": 12_000_000_000,
    "ip_addresses": ["192.168.5.15"],
    "agent_version": "0.1.0",
    "uptime_seconds": 120,
    "capabilities": {"metrics": True, "systemd": True, "docker": False},
}


def create_enrollment(client, headers, name="web-1", tags=("prod",)):
    response = client.post(
        f"{SERVERS}/enrollments",
        json={"name": name, "tags": list(tags)},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


def enroll(client, token):
    return client.post("/agent/v1/enroll", json={"token": token, "facts": FACTS})


def enrolled_agent(client, headers, name="web-1"):
    enrollment = create_enrollment(client, headers, name)
    reply = enroll(client, enrollment["token"]).json()
    return enrollment["server"]["id"], {
        "Authorization": f"Bearer {reply['agent_token']}"
    }


# ---------------------------------------------------------------------------
# Enrollment
# ---------------------------------------------------------------------------


def test_enrollment_creates_pending_server(client, admin_headers, db: Session):
    body = create_enrollment(client, admin_headers)
    assert body["server"]["status"] == "pending"
    assert body["token"].startswith("ept_")
    assert body["install_command"] == (
        f"curl -fsSL {settings.agent_api_url}/agent/install.sh | sudo bash -s -- "
        f"--token {body['token']}"
    )
    stored = db.query(EnrollmentToken).one()
    assert stored.token_hash != body["token"]


def test_enrollment_is_admin_only(client, user_headers):
    response = client.post(
        f"{SERVERS}/enrollments", json={"name": "x"}, headers=user_headers
    )
    assert response.status_code == 403


def test_enrollment_validates_name(client, admin_headers):
    for bad in ["Web 1", "-web", "web_1", "a" * 64]:
        response = client.post(
            f"{SERVERS}/enrollments", json={"name": bad}, headers=admin_headers
        )
        assert response.status_code == 422, bad
    create_enrollment(client, admin_headers, "web-1")
    duplicate = client.post(
        f"{SERVERS}/enrollments", json={"name": "web-1"}, headers=admin_headers
    )
    assert duplicate.status_code == 409


def test_agent_enrolls_with_single_use_token(client, admin_headers, db: Session):
    enrollment = create_enrollment(client, admin_headers)
    first = enroll(client, enrollment["token"])
    assert first.status_code == 200
    assert first.json()["agent_token"].startswith("agt_")
    assert first.json()["heartbeat_seconds"] == settings.agent_heartbeat_seconds

    assert enroll(client, enrollment["token"]).status_code == 401
    server = db.query(Server).one()
    assert server.hostname == "web-1" and server.os_name == "Ubuntu"
    assert server.agent_token_hash and server.enrolled_at


def test_expired_enrollment_token_rejected(client, admin_headers, db: Session):
    enrollment = create_enrollment(client, admin_headers)
    db.query(EnrollmentToken).update(
        {"expires_at": datetime.now(UTC) - timedelta(seconds=1)}
    )
    db.commit()
    response = enroll(client, enrollment["token"])
    assert response.status_code == 401
    assert "expired" in response.json()["detail"]


def test_reissue_replaces_unused_token(client, admin_headers):
    enrollment = create_enrollment(client, admin_headers)
    server_id = enrollment["server"]["id"]
    again = client.post(f"{SERVERS}/{server_id}/enrollments", headers=admin_headers)
    assert again.status_code == 200
    assert enroll(client, enrollment["token"]).status_code == 401
    assert enroll(client, again.json()["token"]).status_code == 200
    # Enrolled servers can't get new tokens.
    third = client.post(f"{SERVERS}/{server_id}/enrollments", headers=admin_headers)
    assert third.status_code == 409


# ---------------------------------------------------------------------------
# Agent protocol
# ---------------------------------------------------------------------------


def test_agent_endpoints_require_agent_token(client):
    assert client.post("/agent/v1/heartbeat", json={}).status_code == 401
    bad = {"Authorization": "Bearer agt_nope"}
    assert client.post("/agent/v1/heartbeat", json={}, headers=bad).status_code == 401


def test_heartbeat_marks_online_then_offline(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    reply = client.post("/agent/v1/heartbeat", json={"facts": FACTS}, headers=agent)
    assert reply.status_code == 200
    assert reply.json()["heartbeat_seconds"] == settings.agent_heartbeat_seconds

    detail = client.get(f"{SERVERS}/{server_id}", headers=admin_headers).json()
    assert detail["status"] == "online"

    db.query(Server).update(
        {"last_heartbeat_at": datetime.now(UTC) - timedelta(minutes=5)}
    )
    db.commit()
    detail = client.get(f"{SERVERS}/{server_id}", headers=admin_headers).json()
    assert detail["status"] == "offline"


def test_metrics_are_stored_and_listed(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    response = client.post(
        "/agent/v1/metrics",
        json={"samples": [sample(), sample(cpu_percent=50)]},
        headers=agent,
    )
    assert response.status_code == 202
    assert db.query(MetricSample).count() == 2

    listed = client.get(SERVERS, headers=admin_headers).json()
    assert listed[0]["latest"]["cpu_percent"] in (12.5, 50)
    series = client.get(
        f"{SERVERS}/{server_id}/metrics?range=1h", headers=admin_headers
    )
    assert series.status_code == 200 and len(series.json()) >= 1


def test_metrics_are_bounded(client, admin_headers):
    _, agent = enrolled_agent(client, admin_headers)
    too_hot = client.post(
        "/agent/v1/metrics", json={"samples": [sample(cpu_percent=150)]}, headers=agent
    )
    assert too_hot.status_code == 422
    too_many = client.post(
        "/agent/v1/metrics", json={"samples": [sample()] * 121}, headers=agent
    )
    assert too_many.status_code == 422


def test_old_metrics_are_pruned(client, admin_headers, db: Session):
    _, agent = enrolled_agent(client, admin_headers)
    old = (
        datetime.now(UTC) - timedelta(days=settings.metrics_retention_days + 1)
    ).isoformat()
    client.post("/agent/v1/metrics", json={"samples": [sample(ts=old)]}, headers=agent)
    client.post("/agent/v1/metrics", json={"samples": [sample()]}, headers=agent)
    assert db.query(MetricSample).count() == 1


def test_inventory_is_visible_on_detail(client, admin_headers):
    server_id, agent = enrolled_agent(client, admin_headers)
    inventory = {
        "services": [{"name": "ssh.service", "active": "active", "sub": "running"}],
        "containers": [],
        "runtimes": {"python": "Python 3.12.3"},
        "docker_access": False,
    }
    assert (
        client.post("/agent/v1/inventory", json=inventory, headers=agent).status_code
        == 202
    )
    detail = client.get(f"{SERVERS}/{server_id}", headers=admin_headers).json()
    assert detail["inventory"]["services"][0]["name"] == "ssh.service"
    assert detail["inventory"]["runtimes"]["python"] == "Python 3.12.3"


def test_revoke_cuts_off_agent_then_allows_delete(client, admin_headers):
    server_id, agent = enrolled_agent(client, admin_headers)
    # Live servers can't be deleted.
    assert (
        client.delete(f"{SERVERS}/{server_id}", headers=admin_headers).status_code
        == 409
    )

    revoked = client.post(f"{SERVERS}/{server_id}/revoke", headers=admin_headers)
    assert revoked.json()["status"] == "revoked"
    assert client.post("/agent/v1/heartbeat", json={}, headers=agent).status_code == 401

    assert (
        client.delete(f"{SERVERS}/{server_id}", headers=admin_headers).status_code
        == 204
    )
    assert (
        client.get(f"{SERVERS}/{server_id}", headers=admin_headers).status_code == 404
    )


def test_servers_api_is_admin_only(client, user_headers):
    assert client.get(SERVERS, headers=user_headers).status_code == 403


# ---------------------------------------------------------------------------
# Installer
# ---------------------------------------------------------------------------


def test_install_script_points_at_control_plane(client):
    script = client.get("/agent/install.sh")
    assert script.status_code == 200
    assert f'API_URL="{settings.agent_api_url}"' in script.text
    assert "RestartPreventExitStatus=78" in script.text
    assert "User=vpspilot" in script.text


def test_agent_package_contains_the_agent(client):
    response = client.get("/agent/package.tar.gz")
    assert response.status_code == 200
    with tarfile.open(fileobj=io.BytesIO(response.content)) as tar:
        names = tar.getnames()
    assert "vpspilot_agent/__main__.py" in names
    assert not any(n.endswith(".pyc") for n in names)
