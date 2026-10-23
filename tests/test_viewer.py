"""View-only users: see everything except secrets, change nothing."""

from sqlalchemy.orm import Session

from app.users.models import Role
from tests.conftest import create_user, sign_in
from tests.test_apps import APPS, git_app
from tests.test_databases import managed
from tests.test_servers import enrolled_agent


def test_viewers_can_look_but_not_touch(client, db: Session, outbox, admin_headers):
    server_id, agent = enrolled_agent(client, admin_headers)
    app = client.post(APPS, json=git_app(server_id), headers=admin_headers).json()
    create_user(db, "viewer@example.com", role=Role.VIEWER)
    viewer = sign_in(client, outbox, "viewer@example.com")

    for path in (
        "/api/v1/servers",
        f"/api/v1/servers/{server_id}",
        APPS,
        f"{APPS}/{app['id']}",
        "/api/v1/monitoring/rules",
        "/api/v1/monitoring/alerts",
        "/api/v1/domains",
        "/api/v1/backups",
        "/api/v1/audit-logs",
    ):
        assert client.get(path, headers=viewer).status_code == 200, path

    # Reading logs is a POST, but it doesn't change anything.
    logs = client.post(f"{APPS}/{app['id']}/logs", json={}, headers=viewer)
    assert logs.status_code == 202

    for method, path, body in (
        ("post", f"{APPS}/{app['id']}/deployments", {}),
        ("patch", f"{APPS}/{app['id']}", {"health_path": "/x"}),
        ("delete", f"{APPS}/{app['id']}", None),
        (
            "post",
            f"/api/v1/servers/{server_id}/actions",
            {"type": "service.restart", "payload": {"unit": "cron.service"}},
        ),
        ("post", "/api/v1/monitoring/maintenance", {"minutes": 30}),
    ):
        response = getattr(client, method)(
            path, headers=viewer, **({"json": body} if body is not None else {})
        )
        assert response.status_code == 403, (method, path)
        assert "view-only" in response.json()["detail"]


def test_viewers_dont_see_secrets(client, db: Session, outbox, admin_headers):
    instance, _, _ = managed(client, admin_headers)
    create_user(db, "viewer@example.com", role=Role.VIEWER)
    viewer = sign_in(client, outbox, "viewer@example.com")
    assert (
        client.get(f"/api/v1/databases/{instance['id']}", headers=viewer).status_code
        == 200
    )
    assert (
        client.get(
            f"/api/v1/databases/{instance['id']}/connection", headers=viewer
        ).status_code
        == 403
    )
    assert client.get("/api/v1/users/", headers=viewer).status_code == 403


def test_viewers_get_the_inbox(client, db: Session, outbox, admin_headers):
    from app.notifications import service as notifications

    create_user(db, "viewer@example.com", role=Role.VIEWER)
    users = notifications.notify(
        db, "alert.firing", "warn", "Disk almost full", None, None
    )
    assert {u.email for u in users} == {"admin@example.com", "viewer@example.com"}
