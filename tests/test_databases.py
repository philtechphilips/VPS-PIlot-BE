import json

from sqlalchemy.orm import Session

from app.apps import service as apps
from app.apps.models import Application
from app.audit.models import AuditLog
from app.databases.models import DatabaseCredential, DatabaseInstance
from tests.test_apps import APPS, git_app
from tests.test_jobs import claim
from tests.test_servers import enrolled_agent

DB = "/api/v1/databases"


def finish(client, agent, job_id, ok=True, output=None, error=None):
    r = client.post(
        f"/agent/v1/jobs/{job_id}/complete",
        json={
            "status": "succeeded" if ok else "failed",
            "output": json.dumps(output) if output is not None else "",
            "error": error,
        },
        headers=agent,
    )
    assert r.status_code == 202, r.text


def secrets_for(client, agent, job_id):
    return client.get(f"/agent/v1/jobs/{job_id}/secrets", headers=agent).json()[
        "secrets"
    ]


def managed(client, headers, engine="postgres", name="main"):
    server_id, agent = enrolled_agent(client, headers, name=f"srv-{name}")
    r = client.post(
        DB,
        json={"name": name, "server_id": server_id, "engine": engine},
        headers=headers,
    )
    assert r.status_code == 202, r.text
    body = r.json()
    job = claim(client, agent)
    assert job["type"] == "db.create"
    finish(client, agent, job["id"])
    return body["database"], agent, server_id


def test_create_managed_postgres(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    r = client.post(
        DB,
        json={"name": "main", "server_id": server_id, "engine": "postgres"},
        headers=admin_headers,
    )
    instance = r.json()["database"]
    assert instance["status"] == "creating" and instance["host"] == "vpdb-main"
    assert (
        instance["default_database"] == "main" and instance["admin_user"] == "postgres"
    )
    job = claim(client, agent)
    assert job["payload"] == {
        "instance_id": instance["id"],
        "has_secrets": True,
        "name": "main",
        "engine": "postgres",
        "version": "17",
        "user": "postgres",
        "database": "main",
        "local_port": None,
    }
    password = secrets_for(client, agent, job["id"])["password"]
    assert len(password) == 32 and password.isalnum()
    stored = db.get(DatabaseInstance, instance["id"])
    assert password not in stored.admin_password  # encrypted at rest
    finish(client, agent, job["id"])
    assert (
        client.get(f"{DB}/{instance['id']}", headers=admin_headers).json()["status"]
        == "running"
    )


def test_create_validation(client, admin_headers):
    server_id, _ = enrolled_agent(client, admin_headers)
    bad = [
        {"name": "Main!", "engine": "postgres"},
        {"name": "x", "engine": "oracle"},
        {"name": "x", "engine": "postgres", "version": "9"},
        {"name": "x", "engine": "postgres", "database": "bad-name"},
        {"name": "x", "engine": "postgres", "local_port": 22},
    ]
    for body in bad:
        r = client.post(
            DB, json={"server_id": server_id, **body}, headers=admin_headers
        )
        assert r.status_code == 422, body
    client.post(
        DB,
        json={"name": "x", "server_id": server_id, "engine": "redis"},
        headers=admin_headers,
    )
    assert (
        client.post(
            DB,
            json={"name": "x", "server_id": server_id, "engine": "redis"},
            headers=admin_headers,
        ).status_code
        == 409
    )


def test_failed_create_is_shown(client, admin_headers):
    server_id, agent = enrolled_agent(client, admin_headers)
    instance = client.post(
        DB,
        json={"name": "main", "server_id": server_id, "engine": "mysql"},
        headers=admin_headers,
    ).json()["database"]
    finish(
        client,
        agent,
        claim(client, agent)["id"],
        ok=False,
        error="Couldn't pull mysql:8.4",
    )
    body = client.get(f"{DB}/{instance['id']}", headers=admin_headers).json()
    assert body["status"] == "error" and body["error"] == "Couldn't pull mysql:8.4"


def test_queries_keep_sql_out_of_jobs_and_audit(client, admin_headers, db: Session):
    instance, agent, _ = managed(client, admin_headers)
    sql = "SELECT 'sk_live_123' AS secret_value"
    job_id = client.post(
        f"{DB}/{instance['id']}/query",
        json={"sql": sql, "database": "main"},
        headers=admin_headers,
    ).json()["job_id"]
    job = claim(client, agent)
    assert job["id"] == job_id and job["type"] == "db.query"
    assert (
        "sk_live" not in json.dumps(job["payload"])
        and job["payload"]["readonly"] is True
    )
    assert secrets_for(client, agent, job_id)["sql"] == sql
    finish(
        client,
        agent,
        job_id,
        output={
            "columns": ["secret_value"],
            "rows": [["sk_live_123"]],
            "truncated": False,
            "duration_ms": 3,
        },
    )
    result = client.get(
        f"{DB}/{instance['id']}/jobs/{job_id}", headers=admin_headers
    ).json()
    assert result["status"] == "succeeded" and result["data"]["rows"] == [
        ["sk_live_123"]
    ]
    entry = db.query(AuditLog).filter(AuditLog.action == "database.query").one()
    assert "sk_live" not in (entry.detail or "") and "read-only query" in entry.detail
    # Secrets are only for the agent running the job, only while it runs.
    assert (
        client.get(f"/agent/v1/jobs/{job_id}/secrets", headers=agent).status_code == 404
    )


def test_create_user_and_rotate(client, admin_headers, db: Session):
    instance, agent, _ = managed(client, admin_headers)
    r = client.post(
        f"{DB}/{instance['id']}/users",
        json={"username": "reporting", "database": "main", "access": "readonly"},
        headers=admin_headers,
    )
    job = claim(client, agent)
    assert (
        job["payload"]["action"] == "create_user"
        and job["payload"]["access"] == "readonly"
    )
    new_password = secrets_for(client, agent, job["id"])["new_password"]
    finish(client, agent, job["id"], output={"ok": True})
    details = client.get(
        f"{DB}/{instance['id']}/connection", headers=admin_headers
    ).json()
    login = next(lg for lg in details["logins"] if lg["username"] == "reporting")
    assert login["status"] == "active" and login["password"] == new_password
    assert login["url"] == f"postgresql://reporting:{new_password}@vpdb-main:5432/main"

    client.post(
        f"{DB}/{instance['id']}/users/{r.json()['credential_id']}/rotate",
        headers=admin_headers,
    )
    job = claim(client, agent)
    rotated = secrets_for(client, agent, job["id"])["new_password"]
    assert rotated != new_password
    finish(client, agent, job["id"], output={"ok": True})
    cred = db.get(DatabaseCredential, r.json()["credential_id"])
    db.refresh(cred)
    assert cred.pending_password is None and cred.rotated_at is not None


def test_failed_user_creation_is_forgotten(client, admin_headers, db: Session):
    instance, agent, _ = managed(client, admin_headers)
    client.post(
        f"{DB}/{instance['id']}/users", json={"username": "app"}, headers=admin_headers
    )
    finish(
        client, agent, claim(client, agent)["id"], ok=False, error="role already exists"
    )
    assert db.query(DatabaseCredential).count() == 0


def test_attach_postgres_to_app(client, admin_headers, db: Session):
    instance, agent, server_id = managed(client, admin_headers)
    app = client.post(
        APPS, json=git_app(server_id, deploy=False, env=[]), headers=admin_headers
    ).json()
    r = client.post(
        f"{DB}/{instance['id']}/attach",
        json={"application_id": app["id"]},
        headers=admin_headers,
    )
    assert r.status_code == 202, r.text
    first, second = claim(client, agent), None
    assert (
        first["payload"]["action"] == "create_database"
        and first["payload"]["database"] == "shop"
    )
    finish(client, agent, first["id"], output={"ok": True})
    second = claim(client, agent)
    assert (
        second["payload"]["action"] == "create_user"
        and second["payload"]["access"] == "owner"
    )
    password = secrets_for(client, agent, second["id"])["new_password"]
    finish(client, agent, second["id"], output={"ok": True})
    stored = db.get(Application, app["id"])
    db.refresh(stored)
    env = apps.env_values(stored)
    assert env["DATABASE_URL"] == f"postgresql://shop:{password}@vpdb-main:5432/shop"
    assert next(e for e in stored.env if e["key"] == "DATABASE_URL")["secret"] is True
    # Only once per variable, and only on the database's own server.
    assert (
        client.post(
            f"{DB}/{instance['id']}/attach",
            json={"application_id": app["id"]},
            headers=admin_headers,
        ).status_code
        == 409
    )


def test_attach_needs_same_server(client, admin_headers):
    instance, _, _ = managed(client, admin_headers)
    other_server, _ = enrolled_agent(client, admin_headers, name="elsewhere")
    app = client.post(
        APPS, json=git_app(other_server, deploy=False, env=[]), headers=admin_headers
    ).json()
    r = client.post(
        f"{DB}/{instance['id']}/attach",
        json={"application_id": app["id"]},
        headers=admin_headers,
    )
    assert r.status_code == 409


def test_attach_redis_is_immediate(client, admin_headers, db: Session):
    instance, _, server_id = managed(
        client, admin_headers, engine="redis", name="cache"
    )
    app = client.post(
        APPS, json=git_app(server_id, deploy=False, env=[]), headers=admin_headers
    ).json()
    r = client.post(
        f"{DB}/{instance['id']}/attach",
        json={"application_id": app["id"], "env_key": "REDIS_URL"},
        headers=admin_headers,
    )
    assert r.json()["job_id"] is None
    stored = db.get(Application, app["id"])
    db.refresh(stored)
    assert (
        apps.env_values(stored)["REDIS_URL"].startswith("redis://:")
        and "@vpdb-cache:6379/0" in apps.env_values(stored)["REDIS_URL"]
    )


def test_external_connection_check(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    r = client.post(
        f"{DB}/external",
        json={
            "name": "legacy",
            "server_id": server_id,
            "engine": "mysql",
            "host": "127.0.0.1",
            "user": "root",
            "password": "hunter2",
            "database": "shop",
        },
        headers=admin_headers,
    )
    instance = r.json()["database"]
    assert (
        instance["status"] == "checking"
        and instance["mode"] == "external"
        and instance["port"] == 3306
    )
    job = claim(client, agent)
    assert job["type"] == "db.explore" and job["payload"]["target"] == {
        "mode": "external",
        "engine": "mysql",
        "host": "127.0.0.1",
        "port": 3306,
        "user": "root",
        "name": None,
    }
    assert secrets_for(client, agent, job["id"])["password"] == "hunter2"
    finish(
        client, agent, job["id"], output={"columns": ["version"], "rows": [["8.0.36"]]}
    )
    body = client.get(f"{DB}/{instance['id']}", headers=admin_headers).json()
    assert body["status"] == "running" and body["server_version"] == "8.0.36"
    # Forgetting an external database doesn't touch it.
    assert (
        client.delete(f"{DB}/{instance['id']}", headers=admin_headers).json()["job_id"]
        is None
    )
    assert db.query(DatabaseInstance).count() == 0


def test_remove_managed_and_live_status(client, admin_headers, db: Session):
    instance, agent, _ = managed(client, admin_headers)
    client.post(
        "/agent/v1/inventory",
        json={
            "containers": [
                {
                    "id": "1",
                    "name": "vpdb-main",
                    "image": "postgres:17-alpine",
                    "state": "exited",
                    "status": "Exited (0)",
                    "ports": "",
                }
            ]
        },
        headers=agent,
    )
    assert (
        client.get(f"{DB}/{instance['id']}", headers=admin_headers).json()["status"]
        == "stopped"
    )
    job_id = client.delete(
        f"{DB}/{instance['id']}?delete_data=true", headers=admin_headers
    ).json()["job_id"]
    job = claim(client, agent)
    assert job["id"] == job_id and job["payload"]["delete_data"] is True
    finish(client, agent, job_id)
    assert db.query(DatabaseInstance).count() == 0


def test_results_are_scoped_to_their_instance(client, admin_headers):
    a, agent, _ = managed(client, admin_headers, name="one")
    b, _, _ = managed(client, admin_headers, name="two")
    job_id = client.post(
        f"{DB}/{a['id']}/explore", json={"what": "databases"}, headers=admin_headers
    ).json()["job_id"]
    assert (
        client.get(f"{DB}/{b['id']}/jobs/{job_id}", headers=admin_headers).status_code
        == 404
    )
