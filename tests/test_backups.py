from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.backups import service as backups
from app.backups.models import BackupPolicy, BackupRun, BackupSettings
from app.monitoring import service as monitoring
from tests.test_databases import managed
from tests.test_jobs import claim

BK = "/api/v1/backups"


def secrets(client, agent, job_id):
    return client.get(f"/agent/v1/jobs/{job_id}/secrets", headers=agent).json()[
        "secrets"
    ]


def finish(client, agent, job_id, ok=True, result=None, error=None):
    r = client.post(
        f"/agent/v1/jobs/{job_id}/complete",
        json={
            "status": "succeeded" if ok else "failed",
            "result": result or {},
            "error": error,
        },
        headers=agent,
    )
    assert r.status_code == 202, r.text


def backup_once(client, headers, agent, instance_id, n=0):
    runs = client.post(
        f"{BK}/run", json={"instance_id": instance_id}, headers=headers
    ).json()
    job = claim(client, agent)
    assert job["type"] == "backup.create"
    finish(
        client,
        agent,
        job["id"],
        result={
            "path": f"/var/lib/vpspilot-backups/x/main/{runs[0]['id']}.pgdump.enc",
            "size": 1000 + n,
            "sha256": "a" * 64,
        },
    )
    return runs[0]


def test_settings_keep_secrets_secret(client, admin_headers, db: Session):
    body = client.get(f"{BK}/settings", headers=admin_headers).json()
    assert body["storage_enabled"] is False and body["has_credentials"] is False
    row = db.get(BackupSettings, 1)
    assert len(backups.decrypt_secret(row.encryption_key, backups.PURPOSE)) == 64
    bad = client.put(
        f"{BK}/settings",
        json={"storage_enabled": True, "endpoint": "https://s3.example.com"},
        headers=admin_headers,
    )
    assert bad.status_code == 422
    good = client.put(
        f"{BK}/settings",
        json={
            "storage_enabled": True,
            "endpoint": "https://s3.example.com",
            "region": "us-east-1",
            "bucket": "my-backups",
            "access_key": "AKIAEXAMPLE",
            "secret_key": "s3cr3t-value",
        },
        headers=admin_headers,
    ).json()
    assert good["has_credentials"] is True and "secret" not in str(good).replace(
        "has_credentials", ""
    )
    db.refresh(row)
    assert "s3cr3t-value" not in (row.secret_key or "")


def test_backup_run_secrets_and_result(client, admin_headers, db: Session):
    instance, agent, _ = managed(client, admin_headers)
    client.put(
        f"{BK}/settings",
        json={
            "storage_enabled": True,
            "endpoint": "https://s3.example.com",
            "region": "us-east-1",
            "bucket": "my-backups",
            "access_key": "AK",
            "secret_key": "SK",
        },
        headers=admin_headers,
    )
    runs = client.post(
        f"{BK}/run", json={"instance_id": instance["id"]}, headers=admin_headers
    ).json()
    assert [r["database"] for r in runs] == ["main"]
    job = claim(client, agent)
    assert job["payload"]["storage"] == {
        "endpoint": "https://s3.example.com",
        "region": "us-east-1",
        "bucket": "my-backups",
        "prefix": "",
    }
    assert "SK" not in str(job["payload"])
    s = secrets(client, agent, job["id"])
    assert (
        len(s["backup_key"]) == 64
        and s["s3_access_key"] == "AK"
        and s["s3_secret_key"] == "SK"
        and len(s["password"]) == 32
    )
    finish(
        client,
        agent,
        job["id"],
        result={
            "path": "/var/lib/vpspilot-backups/a/main/x.pgdump.enc",
            "remote_key": "a/main/x.pgdump.enc",
            "size": 2048,
            "sha256": "b" * 64,
        },
    )
    run = client.get(BK, headers=admin_headers).json()[0]
    assert (
        run["status"] == "succeeded"
        and run["size"] == 2048
        and run["local"]
        and run["remote"]
    )
    assert client.get(f"{BK}/summary", headers=admin_headers).json()["size"] == 2048


def test_retention_prunes_old_backups(client, admin_headers, db: Session):
    instance, agent, _ = managed(client, admin_headers)
    client.put(
        f"{BK}/policies/{instance['id']}",
        json={"enabled": False, "keep": 2},
        headers=admin_headers,
    )
    first = backup_once(client, admin_headers, agent, instance["id"], 1)
    backup_once(client, admin_headers, agent, instance["id"], 2)
    backup_once(client, admin_headers, agent, instance["id"], 3)
    assert [r["size"] for r in client.get(BK, headers=admin_headers).json()] == [
        1003,
        1002,
    ]
    delete = claim(client, agent)
    assert (
        delete["type"] == "backup.delete"
        and first["id"] in delete["payload"]["items"][0]["path"]
    )


def test_verify_and_restore(client, admin_headers, db: Session):
    instance, agent, _ = managed(client, admin_headers)
    run = backup_once(client, admin_headers, agent, instance["id"])
    job_id = client.post(f"{BK}/{run['id']}/verify", headers=admin_headers).json()[
        "job_id"
    ]
    job = claim(client, agent)
    assert (
        job["id"] == job_id
        and job["payload"]["mode"] == "verify"
        and job["payload"]["sha256"] == "a" * 64
    )
    finish(client, agent, job_id, result={"verified": True, "tables": 4})
    run_after = client.get(BK, headers=admin_headers).json()[0]
    assert (
        run_after["verify_status"] == "passed"
        and "4 tables" in run_after["verify_detail"]
    )
    assert (
        client.post(
            f"{BK}/{run['id']}/restore", json={"mode": "new"}, headers=admin_headers
        ).status_code
        == 422
    )
    r = client.post(
        f"{BK}/{run['id']}/restore",
        json={"mode": "new", "into": "main_copy"},
        headers=admin_headers,
    )
    assert (
        r.status_code == 202 and claim(client, agent)["payload"]["into"] == "main_copy"
    )


def test_redis_restore_is_refused_but_verify_allowed(client, admin_headers):
    instance, agent, _ = managed(client, admin_headers, engine="redis", name="cache")
    run = backup_once(client, admin_headers, agent, instance["id"])
    assert run["database"] == "redis"
    assert (
        client.post(
            f"{BK}/{run['id']}/restore", json={"mode": "replace"}, headers=admin_headers
        ).status_code
        == 409
    )
    assert (
        client.post(f"{BK}/{run['id']}/verify", headers=admin_headers).status_code
        == 202
    )


def test_schedule_and_stale_alert(client, admin_headers, db: Session):
    instance, agent, _ = managed(client, admin_headers)
    policy = client.put(
        f"{BK}/policies/{instance['id']}",
        json={"enabled": True, "every_hours": 6, "keep": 5},
        headers=admin_headers,
    ).json()
    assert policy["enabled"] and policy["next_run_at"]
    row = db.query(BackupPolicy).one()
    row.next_run_at = datetime.now(UTC) - timedelta(minutes=1)
    db.commit()
    assert backups.run_due(db) == 1
    job = claim(client, agent)
    finish(client, agent, job["id"], ok=False, error="pg_dump: connection refused")
    assert monitoring.evaluate(db)["fired"] >= 1
    alert = next(
        a
        for a in client.get("/api/v1/monitoring/alerts", headers=admin_headers).json()
        if a["title"] == "Backups stale or failing"
    )
    assert "last backup failed" in alert["detail"]
    assert db.query(BackupRun).filter(BackupRun.trigger == "scheduled").count() == 1
