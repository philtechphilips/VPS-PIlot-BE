"""External TLS + SSRF guard, Redis ACL logins, metrics history,
export/import."""

import asyncio
import gzip
import os
import socket
from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session
from vpspilot_agent import databases as agent_db
from vpspilot_agent.errors import Rejected

from app.core import artifacts
from app.databases import service
from app.databases.models import DatabaseCredential, DatabaseMetric
from app.servers.models import Server
from tests.test_databases import DB, finish, managed, secrets_for
from tests.test_jobs import claim
from tests.test_servers import enrolled_agent

CA = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBszCCAVmgAwIBAgIUQ2VydGlmaWNhdGVGb3JUZXN0c09ubHkwCgYIKoZIzj0E\n"
    "-----END CERTIFICATE-----\n"
)


def _agent_version(db: Session, server_id: str, version: str = "1.1.0") -> None:
    server = db.get(Server, server_id)
    server.agent_version = version
    server.last_heartbeat_at = datetime.now(UTC)
    db.commit()


def external(client, headers, server=None, **extra):
    server_id, agent = server or enrolled_agent(client, headers, name="ext")
    body = {
        "name": "ext",
        "server_id": server_id,
        "engine": "postgres",
        "host": "db.example.com",
        "user": "app",
        "password": "pw",
        **extra,
    }
    return client.post(f"{DB}/external", json=body, headers=headers), agent


# ---------------------------------------------------------------------------
# SSRF guard and TLS
# ---------------------------------------------------------------------------


def test_metadata_and_link_local_hosts_are_refused(client, admin_headers):
    server = enrolled_agent(client, admin_headers, name="ext")
    for host in ("169.254.169.254", "[fe80::1]", "0.0.0.0", "224.0.0.1",
                 "metadata.google.internal"):  # fmt: skip
        response, _ = external(client, admin_headers, server, host=host)
        assert response.status_code == 422, host
    # A database installed on the server itself is fine.
    response, _ = external(client, admin_headers, server, host="127.0.0.1")
    assert response.status_code == 202


def test_agent_resolves_and_refuses_internal_addresses(monkeypatch):
    def fake(addresses):
        return lambda *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in addresses
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake(["169.254.169.254"]))
    with pytest.raises(Rejected, match="isn't allowed"):
        agent_db.guard_host("sneaky.example.com")
    monkeypatch.setattr(socket, "getaddrinfo", fake(["127.0.0.1"]))
    assert agent_db.guard_host("localhost") == "127.0.0.1"
    monkeypatch.setattr(socket, "getaddrinfo", fake(["10.0.0.5", "169.254.169.254"]))
    with pytest.raises(Rejected):
        agent_db.guard_host("mixed.example.com")
    monkeypatch.setattr(socket, "getaddrinfo", fake(["10.0.0.5"]))
    assert agent_db.guard_host("db.internal.example") == "10.0.0.5"
    assert agent_db.guard_host("10.0.0.5") is None
    with pytest.raises(Rejected):
        agent_db.guard_host("::ffff:169.254.169.254")


def test_tls_settings_reach_the_agent(client, admin_headers, db: Session):
    response, agent = external(client, admin_headers, tls_mode="verify", ca=CA)
    assert response.status_code == 202, response.text
    instance = response.json()["database"]
    assert instance["tls_mode"] == "verify" and instance["has_ca"] is True
    job = claim(client, agent)
    assert job["payload"]["target"]["tls"] == "verify"
    assert secrets_for(client, agent, job["id"])["ca"].startswith("-----BEGIN")
    finish(client, agent, job["id"], output={"columns": ["v"], "rows": [["17"]]})

    bad = client.put(
        f"{DB}/{instance['id']}/tls", json={"tls_mode": "verify", "ca": "nope"},
        headers=admin_headers,
    )  # fmt: skip
    assert bad.status_code == 422
    changed = client.put(
        f"{DB}/{instance['id']}/tls", json={"tls_mode": "require", "ca": ""},
        headers=admin_headers,
    )  # fmt: skip
    assert changed.status_code == 202
    assert changed.json()["database"]["has_ca"] is False
    job = claim(client, agent)
    assert job["payload"]["target"]["tls"] == "require"


@pytest.mark.parametrize(
    ("engine", "tls", "env", "flags"),
    [
        (
            "postgres",
            "verify",
            {"PGSSLMODE": "verify-full", "PGSSLROOTCERT": "/vp-ca.pem"},
            [],
        ),
        ("postgres", "disable", {"PGSSLMODE": "disable"}, []),
        ("mysql", "verify", {}, ["--ssl-mode=VERIFY_IDENTITY", "--ssl-ca=/vp-ca.pem"]),
        ("mariadb", "require", {}, ["--ssl", "--disable-ssl-verify-server-cert"]),
        ("redis", "verify", {}, ["--tls", "--cacert", "/vp-ca.pem"]),
        ("redis", "require", {}, ["--tls", "--insecure"]),
    ],
)
def test_agent_tls_options(tmp_path, engine, tls, env, flags):
    target = {"engine": engine, "tls": tls, "host": "db.example.com",
              "address": "10.0.0.5", "ca": CA}  # fmt: skip
    docker, got_env, got_flags = agent_db.external_options(target, str(tmp_path))
    assert got_env == env and got_flags == flags
    assert ["--add-host", "db.example.com:10.0.0.5"] == docker[:2]
    assert f"{tmp_path}/ca.pem:/vp-ca.pem:ro" in docker


def test_verify_without_ca_uses_the_system_bundle(tmp_path):
    target = {"engine": "mysql", "tls": "verify", "host": "10.0.0.5", "address": None}
    docker, _, flags = agent_db.external_options(target, str(tmp_path))
    assert docker == [] and "--ssl-ca=/etc/pki/tls/certs/ca-bundle.crt" in flags


# ---------------------------------------------------------------------------
# Redis ACL logins
# ---------------------------------------------------------------------------


def test_redis_logins_use_acl(client, admin_headers, db: Session):
    instance, agent, server_id = managed(client, admin_headers, engine="redis")
    _agent_version(db, server_id, "1.0.0")
    old = client.post(
        f"{DB}/{instance['id']}/users",
        json={"username": "worker", "access": "readonly"},
        headers=admin_headers,
    )
    assert old.status_code == 409
    _agent_version(db, server_id)
    owner = client.post(
        f"{DB}/{instance['id']}/users",
        json={"username": "worker", "access": "owner"},
        headers=admin_headers,
    )
    assert owner.status_code == 422
    created = client.post(
        f"{DB}/{instance['id']}/users",
        json={"username": "worker", "access": "readonly", "key_pattern": "jobs:*"},
        headers=admin_headers,
    )
    assert created.status_code == 202, created.text
    job = claim(client, agent)
    assert job["type"] == "db.redis"
    assert job["payload"]["action"] == "acl_setuser"
    assert (
        job["payload"]["pattern"] == "jobs:*" and job["payload"]["access"] == "readonly"
    )
    password = secrets_for(client, agent, job["id"])["new_password"]
    finish(client, agent, job["id"], output={"user": "worker"})
    credential = db.query(DatabaseCredential).one()
    assert credential.status == "active"
    details = client.get(f"{DB}/{instance['id']}/connection", headers=admin_headers)
    urls = [login["url"] for login in details.json()["logins"]]
    assert any(url.startswith(f"redis://worker:{password}@") for url in urls)

    rotate = client.post(
        f"{DB}/{instance['id']}/users/{credential.id}/rotate", headers=admin_headers
    )
    job = claim(client, agent)
    assert rotate.status_code == 202 and job["payload"]["action"] == "acl_setuser"
    finish(client, agent, job["id"], output={})
    db.refresh(credential)
    assert credential.rotated_at is not None and credential.pending_password is None

    dropped = client.delete(
        f"{DB}/{instance['id']}/users/worker", headers=admin_headers
    )
    job = claim(client, agent)
    assert dropped.status_code == 202 and job["payload"]["action"] == "acl_deluser"
    finish(client, agent, job["id"], output={})
    assert db.query(DatabaseCredential).count() == 0


def test_agent_keeps_acl_users_in_the_config(tmp_path):
    conf = tmp_path / "redis.conf"
    conf.write_text("requirepass x\nappendonly yes\n")
    agent_db._save_acl_user(str(conf), "worker", "on #abc ~* &* -@all +@read")
    agent_db._save_acl_user(str(conf), "worker", "on #def ~* &* -@all +@read")
    agent_db._save_acl_user(str(conf), "other", "on #123 ~* &* +@all")
    lines = conf.read_text().splitlines()
    assert lines.count("user worker on #def ~* &* -@all +@read") == 1
    assert "user worker on #abc ~* &* -@all +@read" not in lines
    agent_db._save_acl_user(str(conf), "worker", None)
    assert not any(
        line.startswith("user worker ") for line in conf.read_text().splitlines()
    )
    assert "requirepass x" in conf.read_text()


# ---------------------------------------------------------------------------
# Metrics history
# ---------------------------------------------------------------------------


def test_metrics_are_sampled_and_kept(client, admin_headers, db: Session):
    instance, agent, server_id = managed(client, admin_headers)
    _agent_version(db, server_id)
    assert service.sample_due(db) == 1
    assert service.sample_due(db) == 0  # not again within 5 minutes
    job = claim(client, agent)
    assert job["type"] == "db.explore" and job["payload"]["sample"] is True
    finish(
        client, agent, job["id"],
        output={"columns": ["version", "connections", "max_connections", "size", "uptime"],
                "rows": [["PostgreSQL 17", "7", "100", "8000000", "1 day"]]},
    )  # fmt: skip
    metric = db.query(DatabaseMetric).one()
    assert (metric.connections, metric.max_connections, metric.size_bytes) == (
        7,
        100,
        8000000,
    )
    points = client.get(f"{DB}/{instance['id']}/metrics", headers=admin_headers).json()
    assert len(points) == 1 and points[0]["connections"] == 7


def test_redis_metrics(client, admin_headers, db: Session):
    instance, agent, server_id = managed(client, admin_headers, engine="redis")
    _agent_version(db, server_id)
    service.sample_due(db)
    job = claim(client, agent)
    info = {"connected_clients": "3", "used_memory": "1048576",
            "instantaneous_ops_per_sec": "42", "maxclients": "10000"}  # fmt: skip
    finish(client, agent, job["id"], output={"info": info, "keys": 12})
    metric = db.query(DatabaseMetric).one()
    assert (
        metric.connections,
        metric.memory_bytes,
        metric.keys,
        metric.ops_per_sec,
    ) == (
        3,
        1048576,
        12,
        42.0,
    )


# ---------------------------------------------------------------------------
# Export and import
# ---------------------------------------------------------------------------


async def _chunks(*parts: bytes):
    for part in parts:
        yield part


def test_artifacts_are_encrypted_and_tamper_evident():
    name = "a" * 32 + ".out"
    data = os.urandom(3 * artifacts.CHUNK + 123)
    size = asyncio.run(artifacts.write(name, _chunks(data[:1000], data[1000:]), 10**9))
    assert size == len(data)
    raw = open(artifacts.path_for(name), "rb").read()
    assert data[:64] not in raw
    assert b"".join(artifacts.read(name)) == data
    with open(artifacts.path_for(name), "r+b") as handle:
        handle.seek(len(raw) // 2)
        handle.write(b"\x00\x01\x02")
    with pytest.raises(artifacts.ArtifactError):
        b"".join(artifacts.read(name))
    # Dropping the last chunk is detected too.
    asyncio.run(artifacts.write(name, _chunks(data), 10**9))
    raw = open(artifacts.path_for(name), "rb").read()
    with open(artifacts.path_for(name), "wb") as handle:
        handle.write(raw[: 12 + 4 + 12 + artifacts.CHUNK + 16])
    with pytest.raises(artifacts.ArtifactError):
        b"".join(artifacts.read(name))
    with pytest.raises(artifacts.TooLarge):
        asyncio.run(artifacts.write("b" * 32 + ".in", _chunks(b"x" * 100), 10))
    assert not os.path.exists(artifacts.path_for("b" * 32 + ".in") + ".part")
    artifacts.delete(name)


def test_export_round_trip(client, admin_headers, db: Session):
    instance, agent, _ = managed(client, admin_headers)
    response = client.post(
        f"{DB}/{instance['id']}/export", json={"database": "app"}, headers=admin_headers
    )
    assert response.status_code == 202, response.text
    job_id = response.json()["job_id"]
    early = client.get(f"{DB}/{instance['id']}/exports/{job_id}", headers=admin_headers)
    assert early.status_code == 409
    job = claim(client, agent)
    assert job["type"] == "db.export" and job["payload"]["database"] == "app"
    dump = gzip.compress(b"CREATE TABLE t (id int);\n" * 1000)
    other, other_agent = enrolled_agent(client, admin_headers, name="intruder")
    url = f"/agent/v1/jobs/{job['id']}/artifact"
    assert client.put(url, content=dump, headers=other_agent).status_code == 404
    assert client.put(url, content=dump, headers=agent).status_code == 202
    finish(client, agent, job["id"])
    download = client.get(
        f"{DB}/{instance['id']}/exports/{job_id}", headers=admin_headers
    )
    assert download.status_code == 200
    assert download.content == dump
    assert ".sql.gz" in download.headers["content-disposition"]


def test_import_upload_runs_and_cleans_up(client, admin_headers, db: Session):
    instance, agent, _ = managed(client, admin_headers)
    empty = client.post(
        f"{DB}/{instance['id']}/import?database=app", content=b"", headers=admin_headers
    )
    assert empty.status_code == 422
    binary = client.post(
        f"{DB}/{instance['id']}/import?database=app",
        content=os.urandom(5000),
        headers=admin_headers,
    )
    assert binary.status_code == 422
    sql = b"CREATE TABLE t (id int);\nINSERT INTO t VALUES (1);\n"
    response = client.post(
        f"{DB}/{instance['id']}/import?database=app",
        content=gzip.compress(sql),
        headers=admin_headers,
    )
    assert response.status_code == 202, response.text
    job = claim(client, agent)
    assert job["type"] == "db.import" and job["payload"]["format"] == "sql.gz"
    download = client.get(f"/agent/v1/jobs/{job['id']}/artifact", headers=agent)
    assert gzip.decompress(download.content) == sql
    finish(client, agent, job["id"])
    upload = f"{job['payload']['upload_id']}.in"
    assert not artifacts.exists(upload)
    archive = client.post(
        f"{DB}/{instance['id']}/import?database=app",
        content=b"PGDMP\x01\x0e" + os.urandom(100),
        headers=admin_headers,
    )
    assert archive.status_code == 202
    assert claim(client, agent)["payload"]["format"] == "pgdump"
