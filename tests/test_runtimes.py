"""Native (systemd) and Docker Compose runtimes."""

import os

import pytest
from sqlalchemy.orm import Session
from vpspilot_agent import compose, deploy, native, proxy

from app.apps.models import Application, Deployment
from app.domains import service as domains
from app.domains.models import Domain
from app.monitoring import service as monitoring
from app.servers.models import Server
from tests.test_apps import APPS, complete, deploy_args, git_app
from tests.test_jobs import claim
from tests.test_servers import enrolled_agent


def _agent(db: Session, server_id: str, version: str = "1.1.0") -> None:
    server = db.get(Server, server_id)
    server.agent_version = version
    db.commit()


# ---------------------------------------------------------------------------
# Control plane
# ---------------------------------------------------------------------------


def test_native_app_needs_git_and_a_recent_agent(client, admin_headers, db: Session):
    server_id, _ = enrolled_agent(client, admin_headers)
    _agent(db, server_id, "1.0.0")
    old = client.post(
        APPS, json=git_app(server_id, runtime="systemd"), headers=admin_headers
    )
    assert old.status_code == 409 and "Upgrade" in old.json()["detail"]

    _agent(db, server_id)
    image = git_app(
        server_id, runtime="systemd", source={"type": "image", "image": "nginx"}
    )
    assert client.post(APPS, json=image, headers=admin_headers).status_code == 422
    bad = git_app(server_id, runtime="pm3")
    assert client.post(APPS, json=bad, headers=admin_headers).status_code == 422
    ok = client.post(
        APPS, json=git_app(server_id, runtime="systemd"), headers=admin_headers
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["runtime"] == "systemd"


def test_native_deploy_and_rollback_use_releases(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    _agent(db, server_id)
    app = client.post(
        APPS, json=git_app(server_id, runtime="systemd"), headers=admin_headers
    ).json()
    first = claim(client, agent)
    assert first["payload"]["runtime"] == "systemd"
    assert first["payload"]["source"]["type"] == "git"
    release = "a" * 32
    complete(client, agent, first["id"], result={"image_ref": f"release:{release}"})
    first_dep = db.query(Deployment).filter(Deployment.job_id == first["id"]).one()
    assert first_dep.image_ref == f"release:{release}"

    client.post(f"{APPS}/{app['id']}/deployments", json={}, headers=admin_headers)
    second = claim(client, agent)
    complete(client, agent, second["id"], result={"image_ref": f"release:{'b' * 32}"})

    response = client.post(
        f"/api/v1/deployments/{first_dep.id}/rollback", headers=admin_headers
    )
    assert response.status_code == 202, response.text
    job = claim(client, agent)
    assert job["payload"]["source"] == {"type": "release", "release": release}
    assert job["payload"]["runtime"] == "systemd"


def test_native_domains_point_at_the_host_port(client, admin_headers, db: Session):
    server_id, _ = enrolled_agent(client, admin_headers)
    _agent(db, server_id)
    app = client.post(
        APPS, json=git_app(server_id, runtime="systemd"), headers=admin_headers
    ).json()
    db.add(
        Domain(
            id="d" * 32,
            hostname="shop.example.com",
            server_id=server_id,
            application_id=app["id"],
            tls_mode="auto",
            status="active",
            created_by="test",
        )
    )
    db.commit()
    (site,) = domains.desired_sites(db, server_id)
    assert site["upstream"] == f"host:{app['host_port']}"


def test_compose_app_remembers_its_public_service(client, admin_headers, db: Session):
    server_id, agent = enrolled_agent(client, admin_headers)
    _agent(db, server_id)
    app = client.post(
        APPS,
        json=git_app(server_id, runtime="compose", compose_file="deploy/compose.yaml"),
        headers=admin_headers,
    ).json()
    assert app["compose_file"] == "deploy/compose.yaml"
    # No service yet: logs need a deploy first.
    logs = client.post(f"{APPS}/{app['id']}/logs", json={}, headers=admin_headers)
    assert logs.status_code == 409

    job = claim(client, agent)
    assert job["payload"]["compose_file"] == "deploy/compose.yaml"
    assert job["payload"]["compose_service"] is None
    complete(
        client,
        agent,
        job["id"],
        result={"image_ref": f"release:{'c' * 32}", "public_service": "web"},
    )
    assert db.get(Application, app["id"]).compose_service == "web"
    logs = client.post(f"{APPS}/{app['id']}/logs", json={}, headers=admin_headers)
    assert logs.status_code == 202, logs.text
    job = claim(client, agent)
    assert job["payload"]["runtime"] == "compose"
    assert job["payload"]["service"] == "web"


def test_app_down_checks_the_runtime(db: Session):
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    server = Server(id="s" * 32, name="web-1", inventory_at=now)
    native_app = Application(name="api", runtime="systemd", current_deployment_id="x")
    compose_app = Application(
        name="shop", runtime="compose", compose_service="web", current_deployment_id="x"
    )
    server.inventory = {
        "services": [{"name": "vp-api.service", "active": "failed", "sub": "failed"}],
        "containers": [{"name": "vp-shop-web-1", "state": "running"}],
    }
    assert monitoring._check_app(native_app, server, now).breached is True
    assert monitoring._check_app(compose_app, server, now).breached is False
    server.inventory["services"][0].update(active="active", sub="running")
    assert monitoring._check_app(native_app, server, now).breached is False


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


def test_agent_validates_runtime_and_source():
    release = {"type": "release", "release": "a" * 32}
    image = {"type": "image", "image": "nginx"}
    for extra in (
        {"runtime": "pm3"},
        {"runtime": "docker", "source": release},
        {"runtime": "systemd", "source": image},
        {"runtime": "compose", "source": image},
        {"runtime": "compose", "compose_file": "../compose.yaml"},
        {"runtime": "compose", "compose_service": "web;rm"},
        {"runtime": "systemd", "source": {"type": "release", "release": "../x"}},
    ):
        with pytest.raises(deploy.Rejected):
            deploy.validate(deploy_args(**extra))
    spec = deploy.validate(deploy_args(runtime="systemd", source=release))
    assert spec["runtime"] == "systemd" and spec["source"] == release


def test_native_env_file_and_user_names():
    assert native._quote_env('a"b\\c$D`e') == '"a\\"b\\\\c\\$D\\`e"'
    assert native.user_for("shop") == "vp-shop"
    long = native.user_for("a" * 40)
    assert len(long) == 32 and long.startswith("vp-aaaa")
    assert native.user_for("a" * 40) != native.user_for("a" * 39 + "b")


def test_native_unit_is_hardened(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "UNIT_DIR", str(tmp_path))
    paths = native._paths("shop")
    spec = {"app": "shop", "host_port": 20001, "memory": "512m", "cpus": "1.5"}
    native._write_unit(spec, "vp-shop", paths, "f" * 32)
    text = open(paths["unit"]).read()
    for line in (
        "User=vp-shop",
        "ProtectSystem=strict",
        "NoNewPrivileges=yes",
        "ReadWritePaths=/srv/vpspilot/shop",
        f"ExecStart=/bin/sh /srv/vpspilot/shop/meta/{'f' * 32}/start.sh",
        "MemoryMax=512M",
        "CPUQuota=150%",
        "# port 20001",
    ):
        assert line in text.splitlines(), line
    assert native._unit_port(paths["unit"]) == 20001


def _config(src, **service):
    return {
        "name": "x",
        "services": {"web": {"image": "nginx", **service}},
        "networks": {"default": {"name": "x_default"}},
    }


def test_compose_refuses_host_access(tmp_path):
    src = str(tmp_path)
    outside = str(tmp_path.parent)
    for service in (
        {"privileged": True},
        {"cap_add": ["SYS_ADMIN"]},
        {"network_mode": "host"},
        {"pid": "host"},
        {"devices": ["/dev/sda:/dev/sda"]},
        {"security_opt": ["seccomp=unconfined"]},
        {"volumes": [{"type": "bind", "source": outside, "target": "/x"}]},
        {
            "volumes": [
                {"type": "bind", "source": "/var/run/docker.sock", "target": "/s"}
            ]
        },
        {"build": {"context": outside}},
    ):
        with pytest.raises(deploy.Failed):
            compose._check(_config(src, **service), src, lambda *_: None)
    for top in (
        {"volumes": {"data": {"external": True}}},
        {"volumes": {"data": {"driver_opts": {"type": "none", "o": "bind"}}}},
        {"networks": {"other": {"external": True}}},
    ):
        with pytest.raises(deploy.Failed):
            compose._check({**_config(src), **top}, src, lambda *_: None)
    inside = os.path.join(src, "conf")
    os.makedirs(inside)
    ok = _config(src, volumes=[{"type": "bind", "source": inside, "target": "/c"}])
    compose._check(ok, src, lambda *_: None)


def test_compose_rewrite_publishes_one_service():
    config = {
        "services": {
            "web": {
                "build": {"context": "/x"},
                "ports": [{"target": 80, "published": "8080"}],
                "container_name": "fixed",
                "networks": {"default": None},
                "environment": {"A": "1"},
            },
            "db": {"image": "postgres:16", "ports": [{"target": 5432}]},
        },
    }
    warnings = []
    spec = {
        "app": "shop",
        "deployment_id": "e" * 32,
        "container_port": 3000,
        "host_port": 20005,
        "env": {"SECRET": "s"},
    }
    out = compose._rewrite(
        config, spec, "abc-eeeeee", "web", lambda _l, m: warnings.append(m)
    )
    web, db = out["services"]["web"], out["services"]["db"]
    assert out["name"] == "vp-shop"
    assert web["ports"] == [
        {
            "target": 3000,
            "published": "20005",
            "host_ip": "0.0.0.0",
            "protocol": "tcp",
            "mode": "host",
        }
    ]
    assert "ports" not in db and "container_name" not in web
    assert web["networks"] == {"default": None, "vpspilot": {"aliases": ["vp-shop"]}}
    assert out["networks"]["vpspilot"] == {"name": "vpspilot", "external": True}
    assert web["environment"] == {"A": "1", "SECRET": "s"}
    assert web["image"] == "vpspilot/shop.web:abc-eeeeee"
    assert db["labels"]["vpspilot.app"] == "shop"
    assert len(warnings) == 3


def test_proxy_routes_host_upstreams_to_the_gateway():
    sites = proxy._sites(
        {
            "sites": [
                {"host": "api.example.com", "tls": "auto", "upstream": "host:20001"}
            ]
        }
    )
    text = proxy.render(sites, None, "172.18.0.1")
    assert "reverse_proxy 172.18.0.1:20001" in text
    with pytest.raises(proxy.Rejected):
        proxy._sites(
            {"sites": [{"host": "a.example.com", "tls": "auto", "upstream": "evil:1"}]}
        )
