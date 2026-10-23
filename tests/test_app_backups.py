"""Backups of apps' files: the Docker data folder, systemd shared folders and
Compose volumes."""

import os
import shutil

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from vpspilot_agent import backups as agent_backups
from vpspilot_agent import deploy, filebackups

from app.backups.models import BackupPolicy, BackupRun
from app.monitoring import service as monitoring
from tests.test_apps import APPS, git_app
from tests.test_backups import BK, finish, secrets
from tests.test_jobs import claim
from tests.test_runtimes import _agent
from tests.test_servers import enrolled_agent

KEY = "ab" * 32

# ---------------------------------------------------------------------------
# Agent: pack, verify and restore for real (openssl and tarfile)
# ---------------------------------------------------------------------------


@pytest.fixture
def shared(monkeypatch, tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("openssl not installed")
    folder = tmp_path / "shared"
    (folder / "uploads").mkdir(parents=True)
    (folder / "uploads" / "a.png").write_bytes(b"\x89PNG" + b"x" * 5000)
    (folder / "notes.txt").write_text("hello")
    os.symlink("notes.txt", folder / "latest")
    monkeypatch.setattr(agent_backups, "DIR", str(tmp_path / "backups"))
    monkeypatch.setattr(
        filebackups, "sources", lambda app, runtime: [("shared", str(folder))]
    )
    calls = []
    monkeypatch.setattr(
        filebackups, "_control", lambda app, runtime, action: calls.append(action)
    )
    return folder, calls


def _args(**extra):
    return {
        "app": "shop",
        "runtime": "systemd",
        "application_id": "1" * 32,
        "backup_id": "2" * 32,
        "secrets": {"backup_key": KEY},
        **extra,
    }


def test_files_are_packed_encrypted_and_restored(shared):
    folder, calls = shared
    events = []
    emit = lambda kind, text: events.append((kind, text))  # noqa: E731

    made = filebackups.create(_args(), emit)
    assert made["exit_code"] == 0, made
    result = made["result"]
    assert result["files"] == 2 and result["remote_key"] is None
    with open(result["path"], "rb") as handle:
        assert handle.read(8) == b"Salted__"  # openssl output, not a plain tar

    checked = filebackups.restore(
        _args(mode="verify", path=result["path"], sha256=result["sha256"]), emit
    )
    assert checked["exit_code"] == 0 and checked["result"]["files"] == 2
    assert calls == []  # verifying never stops the app

    # Break things, then restore: the folder is back exactly, app restarted.
    (folder / "notes.txt").write_text("changed")
    (folder / "junk.tmp").write_text("x")
    shutil.rmtree(folder / "uploads")
    done = filebackups.restore(
        _args(mode="replace", path=result["path"], sha256=result["sha256"]), emit
    )
    assert done["exit_code"] == 0, done
    assert (folder / "notes.txt").read_text() == "hello"
    assert (folder / "uploads" / "a.png").read_bytes().startswith(b"\x89PNG")
    assert not (folder / "junk.tmp").exists()
    assert os.readlink(folder / "latest") == "notes.txt"
    assert calls == ["stop", "start"]


def test_a_tampered_backup_is_refused(shared):
    folder, calls = shared
    made = filebackups.create(_args(), lambda *_: None)["result"]
    with open(made["path"], "ab") as handle:
        handle.write(b"tampered")
    out = filebackups.restore(
        _args(mode="replace", path=made["path"], sha256=made["sha256"]),
        lambda *_: None,
    )
    assert out["exit_code"] == 1 and "Checksum" in out["error"]
    assert (folder / "notes.txt").read_text() == "hello" and calls == []


def test_nothing_to_back_up_says_why(monkeypatch):
    monkeypatch.setattr(filebackups, "sources", lambda app, runtime: [])
    out = filebackups.create(_args(runtime="docker"), lambda *_: None)
    assert out["exit_code"] == 1 and "data folder" in out["error"]


def test_docker_apps_mount_their_data_volume():
    spec = {
        "app": "shop",
        "deployment_id": "d" * 32,
        "cpus": None,
        "memory": None,
        "data_path": "/app/uploads",
    }
    args = deploy._run_args(spec, "vp-shop", "img", "/tmp/env", "3000:3000")
    assert args[args.index("-v") + 1] == "vp-shop-data:/app/uploads"
    assert "-v" not in deploy._run_args({**spec, "data_path": None}, "x", "i", "e", "p")


# ---------------------------------------------------------------------------
# Control plane
# ---------------------------------------------------------------------------


def _app(client, admin_headers, db, **extra):
    server_id, agent = enrolled_agent(client, admin_headers)
    _agent(db, server_id)
    app = client.post(
        APPS, json=git_app(server_id, deploy=False, **extra), headers=admin_headers
    )
    assert app.status_code == 201, app.text
    return agent, app.json()


def test_docker_apps_need_a_data_folder_first(client, admin_headers, db: Session):
    agent, app = _app(client, admin_headers, db)
    first = client.post(f"{BK}/apps/{app['id']}/run", headers=admin_headers)
    assert first.status_code == 422 and "data folder" in first.json()["detail"]
    assert (
        client.get(f"{BK}/apps/{app['id']}/policy", headers=admin_headers).json()[
            "ready"
        ]
        is False
    )

    bad = client.patch(
        f"{APPS}/{app['id']}", json={"data_path": "/app/../etc"}, headers=admin_headers
    )
    assert bad.status_code == 422
    client.patch(
        f"{APPS}/{app['id']}", json={"data_path": "/app/uploads"}, headers=admin_headers
    )
    detail = client.get(f"{APPS}/{app['id']}", headers=admin_headers).json()
    assert detail["data_path"] == "/app/uploads"

    run = client.post(f"{BK}/apps/{app['id']}/run", headers=admin_headers)
    assert run.status_code == 202 and run.json()["kind"] == "files"
    job = claim(client, agent)
    assert job["type"] == "backup.files"
    assert job["payload"]["app"] == "shop" and job["payload"]["runtime"] == "docker"
    assert secrets(client, agent, job["id"])["backup_key"]


def test_app_backup_lifecycle(client, admin_headers, db: Session):
    agent, app = _app(client, admin_headers, db, runtime="systemd")
    policy = client.put(
        f"{BK}/apps/{app['id']}/policy",
        json={"enabled": True, "every_hours": 12, "keep": 2},
        headers=admin_headers,
    ).json()
    assert policy["enabled"] and policy["ready"] and policy["next_run_at"]

    ids = []
    for n in range(3):
        run = client.post(f"{BK}/apps/{app['id']}/run", headers=admin_headers).json()
        job = claim(client, agent)
        finish(
            client,
            agent,
            job["id"],
            result={
                "path": f"/var/lib/vpspilot-backups/apps/{app['id']}/{run['id']}.enc",
                "size": 900 + n,
                "sha256": "c" * 64,
                "files": 12,
            },
        )
        ids.append(run["id"])
    listed = client.get(
        f"{BK}?application_id={app['id']}", headers=admin_headers
    ).json()
    assert [r["id"] for r in listed] == ids[:0:-1]  # keep=2: the oldest is pruned
    assert listed[0]["files"] == 12 and listed[0]["application_name"] == "shop"
    prune = claim(client, agent)
    assert prune["type"] == "backup.delete"

    verify = client.post(f"{BK}/{ids[-1]}/verify", headers=admin_headers)
    assert verify.status_code == 202
    job = claim(client, agent)
    assert job["type"] == "backup.files_restore" and job["payload"]["mode"] == "verify"
    finish(client, agent, job["id"], result={"files": 12})
    run = db.get(BackupRun, ids[-1])
    db.refresh(run)
    assert run.verify_status == "passed" and "12 files" in run.verify_detail

    new = client.post(
        f"{BK}/{ids[-1]}/restore",
        json={"mode": "new", "into": "x"},
        headers=admin_headers,
    )
    assert new.status_code == 422
    replace = client.post(
        f"{BK}/{ids[-1]}/restore", json={"mode": "replace"}, headers=admin_headers
    )
    assert replace.status_code == 202
    assert claim(client, agent)["payload"]["mode"] == "replace"


def test_scheduled_app_backups_and_stale_alert(client, admin_headers, db: Session):
    from datetime import UTC, datetime, timedelta

    from app.backups import service as backups

    agent, app = _app(client, admin_headers, db, runtime="systemd")
    client.put(
        f"{BK}/apps/{app['id']}/policy", json={"enabled": True}, headers=admin_headers
    )
    policy = db.scalars(
        select(BackupPolicy).where(BackupPolicy.application_id == app["id"])
    ).one()
    policy.next_run_at = datetime.now(UTC) - timedelta(minutes=1)
    db.commit()
    assert backups.run_due(db) == 0  # never deployed: nothing to back up yet

    from app.apps.models import Application

    row = db.get(Application, app["id"])
    row.current_deployment_id = "f" * 32
    policy.next_run_at = datetime.now(UTC) - timedelta(minutes=1)
    db.commit()
    assert backups.run_due(db) == 1
    job = claim(client, agent)
    finish(client, agent, job["id"], ok=False, error="disk full")

    monitoring.evaluate(db)
    from app.monitoring.models import Alert

    alert = db.scalars(select(Alert).where(Alert.target_id == app["id"])).one()
    assert alert.target_type == "application" and "disk full" in alert.detail
