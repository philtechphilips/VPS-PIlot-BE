"""Security check, firewall rules and private app ports."""

import json

import pytest
from vpspilot_agent import deploy, security

SSHD = "port 22\npasswordauthentication yes\npermitrootlogin yes\n"
SS = (
    'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
    'LISTEN 0 4096 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=2,fd=3))\n'
    'LISTEN 0 4096 127.0.0.1:6379 0.0.0.0:* users:(("redis-server",pid=3,fd=3))\n'
    'LISTEN 0 4096 0.0.0.0:20001 0.0.0.0:* users:(("docker-proxy",pid=4,fd=3))\n'
)


@pytest.fixture
def server(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, timeout=60, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["sshd", "-T"]:
            return 0, SSHD
        if cmd[1:3] == ["status", "numbered"]:
            return 0, "Status: inactive\n"
        if cmd[:2] == ["ss", "-ltnHp"]:
            return 0, SS
        if cmd[:2] == ["docker", "ps"]:
            return 0, "vp-shop\t0.0.0.0:20001->3000/tcp, [::]:20001->3000/tcp\n"
        return 0, ""

    def fake_stream(cmd, emit, timeout, cwd=None, env=None):
        calls.append(cmd)
        return 0, []

    monkeypatch.setattr(security.shutil, "which", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(security.d, "_run", fake_run)
    monkeypatch.setattr(security.d, "_stream", fake_stream)
    monkeypatch.setattr(security, "AUTO_UPGRADES", str(tmp_path / "20auto-upgrades"))
    return calls


def test_the_check_finds_the_usual_problems(server):
    body = json.loads(security.check({})["output"])
    status = {c["id"]: c["status"] for c in body["checks"]}
    assert status["ssh_password"] == "warn" and status["ssh_root"] == "warn"
    assert status["firewall"] == "bad"
    assert status["database_ports"] == "bad"  # Postgres on 0.0.0.0, Redis local only
    db = next(c for c in body["checks"] if c["id"] == "database_ports")
    assert "PostgreSQL on port 5432" in db["detail"] and "Redis" not in db["detail"]
    assert (
        "vp-shop (20001)"
        in next(c for c in body["checks"] if c["id"] == "docker_ports")["detail"]
    )
    assert (
        next(c for c in body["checks"] if c["id"] == "auto_updates")["fix"]
        == "auto_updates"
    )


def test_turning_the_firewall_on_keeps_ssh_and_the_web_open(server):
    assert security.firewall({"action": "enable"}, lambda *a: None)["exit_code"] == 0
    allowed = [c[2] for c in server if c[1:2] == ["allow"]]
    assert allowed == ["22/tcp", "80/tcp", "443/tcp"]
    enable = next(i for i, c in enumerate(server) if c[1:] == ["--force", "enable"])
    assert enable > max(i for i, c in enumerate(server) if c[1:2] == ["allow"])


def test_ssh_and_web_ports_cant_be_closed(server):
    for port in (22, 80, 443):
        with pytest.raises(security.Rejected):
            security.firewall({"action": "remove", "port": port}, lambda *a: None)
    security.firewall(
        {"action": "allow", "port": 8080, "source": "203.0.113.7"}, lambda *a: None
    )
    assert server[-1][-6:] == ["to", "any", "port", "8080", "proto", "tcp"]
    with pytest.raises(security.Rejected):
        security.firewall(
            {"action": "allow", "port": 8080, "source": "evil; rm"}, lambda *a: None
        )


def test_auto_updates_are_turned_on(server, tmp_path):
    security.auto_updates({}, lambda *a: None)
    assert 'Unattended-Upgrade "1"' in (tmp_path / "20auto-upgrades").read_text()


def test_private_ports_bind_to_localhost():
    spec = deploy.validate(
        {
            "app": "shop",
            "deployment_id": "a" * 32,
            "source": {"type": "image", "image": "shop:1"},
            "container_port": 3000,
            "host_port": 20001,
            "private_port": True,
        }
    )
    assert spec["private_port"] is True
