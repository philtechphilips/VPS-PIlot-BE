"""Moving an app to another server: files, database, deploy, domains."""

import asyncio
import gzip

from sqlalchemy.orm import Session

from app.apps import moves
from app.apps import service as apps
from app.apps.models import Application
from app.core import artifacts
from app.domains import service as domains
from app.domains.models import Domain
from tests.test_apps import APPS, complete, git_app
from tests.test_backups import BK
from tests.test_databases import DB, finish, managed, secrets_for
from tests.test_jobs import claim
from tests.test_runtimes import _agent
from tests.test_servers import enrolled_agent

STORAGE = {
    "storage_enabled": True,
    "endpoint": "https://s3.example.com",
    "region": "us-east-1",
    "bucket": "my-backups",
    "access_key": "AKIAEXAMPLE",
    "secret_key": "s3cr3t-value",
}


async def _one(data: bytes):
    yield data


def _setup(client, admin_headers, db):
    instance, src_agent, src = managed(client, admin_headers)
    _agent(db, src)
    app = client.post(
        APPS,
        json=git_app(src, deploy=False, env=[], runtime="systemd"),
        headers=admin_headers,
    ).json()
    client.post(
        f"{DB}/{instance['id']}/attach",
        json={"application_id": app["id"]},
        headers=admin_headers,
    )
    finish(client, src_agent, claim(client, src_agent)["id"], output={"ok": True})
    finish(client, src_agent, claim(client, src_agent)["id"], output={"ok": True})
    row = db.get(Application, app["id"])
    row.current_deployment_id = "f" * 32
    db.add(Domain(id="d" * 32, hostname="shop.example.com", server_id=src,
                  application_id=app["id"], tls_mode="auto", status="active",
                  created_by="t"))  # fmt: skip
    db.commit()
    dst, dst_agent = enrolled_agent(client, admin_headers, name="web-2")
    _agent(db, dst)
    return app, src, src_agent, dst, dst_agent


def test_files_need_off_server_storage(client, admin_headers, db: Session):
    app, src, _, dst, _ = _setup(client, admin_headers, db)
    plan = client.get(f"{APPS}/{app['id']}/move", headers=admin_headers).json()["plan"]
    assert plan == {
        "databases": [{"name": "main", "engine": "postgres"}],
        "files": True,
        "storage": False,
    }
    refused = client.post(
        f"{APPS}/{app['id']}/move", json={"server_id": dst}, headers=admin_headers
    )
    assert refused.status_code == 409 and "Backup Storage" in refused.json()["detail"]


def test_a_full_move(client, admin_headers, db: Session):
    app, src, src_agent, dst, dst_agent = _setup(client, admin_headers, db)
    client.put(f"{BK}/settings", json=STORAGE, headers=admin_headers)
    started = client.post(
        f"{APPS}/{app['id']}/move", json={"server_id": dst}, headers=admin_headers
    )
    assert started.status_code == 202, started.text

    # 1. Files backed up on the old server, to storage.
    job = claim(client, src_agent)
    assert job["type"] == "backup.files" and job["payload"]["storage"]
    complete(
        client,
        src_agent,
        job["id"],
        result={
            "path": None,
            "remote_key": "apps/x.enc",
            "storage": "s3",
            "size": 10,
            "sha256": "a" * 64,
        },
    )
    # 2. A new Postgres on the new server, the data exported from the old one.
    job = claim(client, dst_agent)
    assert job["type"] == "db.create" and job["payload"]["name"] == "main-2"
    finish(client, dst_agent, job["id"])
    job = claim(client, src_agent)
    assert job["type"] == "db.export" and job["payload"]["database"] == "shop"
    asyncio.run(
        artifacts.write(
            f"{job['id']}.out", _one(gzip.compress(b"CREATE TABLE t();")), 10**9
        )
    )
    finish(client, src_agent, job["id"])
    # ...a database and login for the app there, and the import.
    job = claim(client, dst_agent)
    assert job["payload"]["action"] == "create_database"
    finish(client, dst_agent, job["id"], output={"ok": True})
    job = claim(client, dst_agent)
    assert job["payload"]["action"] == "create_user"
    password = secrets_for(client, dst_agent, job["id"])["new_password"]
    finish(client, dst_agent, job["id"], output={"ok": True})
    job = claim(client, dst_agent)
    assert job["type"] == "db.import" and job["payload"]["database"] == "shop"
    finish(client, dst_agent, job["id"])
    # 3. Deployed on the new server, pointing at the new database.
    job = claim(client, dst_agent)
    assert job["type"] == "app.deploy"
    row = db.get(Application, app["id"])
    db.refresh(row)
    assert row.server_id == dst
    assert (
        apps.env_values(row)["DATABASE_URL"]
        == f"postgresql://shop:{password}@vpdb-main-2:5432/shop"
    )
    complete(client, dst_agent, job["id"], result={"image_ref": "release:x"})
    # 4. Files restored there.
    job = claim(client, dst_agent)
    assert job["type"] == "backup.files_restore" and job["payload"]["mode"] == "replace"
    complete(client, dst_agent, job["id"], result={"files": 3})
    # 5. Both proxies serve the domain until DNS moves.
    status = client.get(f"{APPS}/{app['id']}/move", headers=admin_headers).json()[
        "move"
    ]
    assert status["status"] == "waiting_dns", status
    assert [s["host"] for s in domains.desired_sites(db, dst)] == ["shop.example.com"]
    assert [s["host"] for s in domains.desired_sites(db, src)] == ["shop.example.com"]

    done = client.post(f"{APPS}/{app['id']}/move/finish", headers=admin_headers).json()
    assert done["status"] == "done"
    assert domains.desired_sites(db, src) == []
    removed = [j for j in iter(lambda: claim(client, src_agent), None)]
    assert any(j["type"] == "app.remove" for j in removed)


def test_a_failed_deploy_puts_everything_back(client, admin_headers, db: Session):
    app, src, src_agent, dst, dst_agent = _setup(client, admin_headers, db)
    original = apps.env_values(db.get(Application, app["id"]))["DATABASE_URL"]
    client.post(
        f"{APPS}/{app['id']}/move",
        json={"server_id": dst, "include_files": False},
        headers=admin_headers,
    )
    finish(client, dst_agent, claim(client, dst_agent)["id"])  # db.create
    job = claim(client, src_agent)  # export
    asyncio.run(artifacts.write(f"{job['id']}.out", _one(gzip.compress(b"x")), 10**9))
    finish(client, src_agent, job["id"])
    for _ in range(3):  # create database, create user, import
        finish(client, dst_agent, claim(client, dst_agent)["id"], output={"ok": True})
    job = claim(client, dst_agent)
    assert job["type"] == "app.deploy"
    complete(client, dst_agent, job["id"], ok=False, error="health check failed")
    move = client.get(f"{APPS}/{app['id']}/move", headers=admin_headers).json()["move"]
    assert move["status"] == "failed" and "health check failed" in move["error"]
    row = db.get(Application, app["id"])
    db.refresh(row)
    assert row.server_id == src
    assert apps.env_values(row)["DATABASE_URL"] == original
    assert moves.active_for(db, app["id"]) is None

