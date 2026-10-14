import json

import pytest
from sqlalchemy.orm import Session

from app.apps.models import Application, Deployment
from app.jobs.models import Job
from tests.test_jobs import act, claim
from tests.test_servers import enrolled_agent

APPS = "/api/v1/applications"


def git_app(server_id, **extra):
    return {
        "name": "shop",
        "server_id": server_id,
        "source": {
            "type": "git",
            "url": "https://github.com/acme/shop",
            "branch": "main",
        },
        "container_port": 3000,
        "health_path": "/health",
        "env": [
            {"key": "NODE_ENV", "value": "production"},
            {
                "key": "DATABASE_URL",
                "value": "postgres://u:hunter2@db/x",
                "secret": True,
            },
        ],
        **extra,
    }


def complete(client, agent, job_id, ok=True, result=None, error=None):
    return client.post(
        f"/agent/v1/jobs/{job_id}/complete",
        json={
            "status": "succeeded" if ok else "failed",
            "exit_code": 0 if ok else 1,
            "output": "log",
            "error": error,
            "result": result or {},
        },
        headers=agent,
    )


@pytest.fixture
def setup(client, admin_headers):
    server_id, agent = enrolled_agent(client, admin_headers)
    response = client.post(APPS, json=git_app(server_id), headers=admin_headers)
    assert response.status_code == 201, response.text
    return server_id, agent, response.json()


def test_create_queues_a_deploy_without_secrets_in_the_job(
    client, admin_headers, db: Session, setup
):
    _, _, app = setup
    assert app["host_port"] == 20000
    assert app["latest_deployment"]["status"] == "queued"
    assert app["latest_deployment"]["trigger"] == "create"
    # Secrets are write-only; plain values are shown.
    env = {e["key"]: e for e in app["env"]}
    assert env["DATABASE_URL"]["value"] is None
    assert env["NODE_ENV"]["value"] == "production"

    job = db.query(Job).one()
    assert job.type == "app.deploy"
    assert job.payload["has_env"] is True
    assert "hunter2" not in json.dumps(job.payload)
    assert job.payload["source"] == {
        "type": "git",
        "url": "https://github.com/acme/shop",
        "ref": "main",
    }
    # ...and the stored value is encrypted.
    stored = db.query(Application).one()
    assert "hunter2" not in json.dumps(stored.env)


def test_create_validation(client, admin_headers):
    server_id, _ = enrolled_agent(client, admin_headers)
    bad = [
        git_app(server_id, name="Shop!"),
        git_app(server_id, source={"type": "git", "url": "http://x.io/a"}),
        git_app(server_id, source={"type": "git", "url": "file:///etc"}),
        git_app(server_id, dockerfile="../../etc/passwd"),
        git_app(server_id, env=[{"key": "PORT", "value": "1"}]),
        git_app(server_id, env=[{"key": "A-B", "value": "1"}]),
        git_app(server_id, env=[{"key": "A", "value": "x\ny"}]),
        git_app(server_id, env=[{"key": "A"}]),
        git_app(server_id, container_port=70000),
    ]
    for body in bad:
        response = client.post(APPS, json=body, headers=admin_headers)
        assert response.status_code == 422, body
    assert client.post(APPS, json=git_app(server_id), headers=admin_headers).is_success
    dup = client.post(APPS, json=git_app(server_id), headers=admin_headers)
    assert dup.status_code == 409


def test_deploy_types_are_not_available_as_raw_actions(client, admin_headers):
    server_id, _ = enrolled_agent(client, admin_headers)
    payload = {"app": "x", "deployment_id": "0" * 32}
    for type_ in ("app.deploy", "app.remove"):
        response = act(client, admin_headers, server_id, type_, payload)
        assert response.status_code == 422


def test_secrets_only_for_the_running_job_on_its_agent(client, admin_headers, setup):
    _, agent, _ = setup
    _, other_agent = enrolled_agent(client, admin_headers, name="web-2")
    job = claim(client, agent)
    url = f"/agent/v1/jobs/{job['id']}/secrets"
    assert client.get(url, headers=other_agent).status_code == 404
    env = client.get(url, headers=agent).json()["env"]
    assert env == {
        "NODE_ENV": "production",
        "DATABASE_URL": "postgres://u:hunter2@db/x",
        "PORT": "3000",
    }
    assert client.get(url, headers=agent).json()["secret_keys"] == ["DATABASE_URL"]
    complete(client, agent, job["id"])
    assert client.get(url, headers=agent).status_code == 404


def test_success_promotes_the_deployment(client, admin_headers, db: Session, setup):
    _, agent, app = setup
    job = claim(client, agent)
    result = {
        "commit_sha": "a" * 40,
        "commit_message": "Fix checkout",
        "image_ref": "vpspilot/shop:aaaaaaaaaaaa",
    }
    assert complete(client, agent, job["id"], result=result).status_code == 202
    body = client.get(f"{APPS}/{app['id']}", headers=admin_headers).json()
    current = body["current_deployment"]
    assert current["status"] == "succeeded" and current["is_current"]
    assert current["commit_sha"] == "a" * 40
    assert current["image_ref"] == "vpspilot/shop:aaaaaaaaaaaa"

    detail = client.get(f"/api/v1/deployments/{current['id']}", headers=admin_headers)
    assert detail.json()["output"] == "log"


def test_failed_deploy_keeps_current_and_rollback_reuses_image(
    client, admin_headers, db: Session, setup
):
    _, agent, app = setup
    first = claim(client, agent)
    complete(client, agent, first["id"], result={"image_ref": "vpspilot/shop:1"})
    first_dep = db.query(Deployment).filter(Deployment.job_id == first["id"]).one()

    redeploy = client.post(
        f"{APPS}/{app['id']}/deployments", json={"ref": "v2"}, headers=admin_headers
    )
    assert redeploy.status_code == 202
    second = claim(client, agent)
    assert second["payload"]["source"]["ref"] == "v2"
    complete(client, agent, second["id"], ok=False, error="health check failed")

    body = client.get(f"{APPS}/{app['id']}", headers=admin_headers).json()
    assert body["current_deployment"]["id"] == first_dep.id
    assert body["latest_deployment"]["status"] == "failed"
    assert body["latest_deployment"]["error"] == "health check failed"

    # Already live: nothing to roll back to.
    again = client.post(
        f"/api/v1/deployments/{first_dep.id}/rollback", headers=admin_headers
    )
    assert again.status_code == 409
    failed_id = body["latest_deployment"]["id"]
    bad = client.post(
        f"/api/v1/deployments/{failed_id}/rollback", headers=admin_headers
    )
    assert bad.status_code == 409


def test_rollback_releases_the_old_image_without_pulling(
    client, admin_headers, db: Session, setup
):
    _, agent, app = setup
    first = claim(client, agent)
    complete(client, agent, first["id"], result={"image_ref": "vpspilot/shop:1"})
    first_dep = db.query(Deployment).filter(Deployment.job_id == first["id"]).one()
    client.post(f"{APPS}/{app['id']}/deployments", json={}, headers=admin_headers)
    second = claim(client, agent)
    complete(client, agent, second["id"], result={"image_ref": "vpspilot/shop:2"})

    response = client.post(
        f"/api/v1/deployments/{first_dep.id}/rollback", headers=admin_headers
    )
    assert response.status_code == 202
    assert response.json()["trigger"] == "rollback"
    job = claim(client, agent)
    assert job["payload"]["source"] == {
        "type": "image",
        "image": "vpspilot/shop:1",
        "pull": False,
    }


def test_env_update_keeps_secret_values_and_audits_names_only(
    client, admin_headers, db: Session, setup
):
    from app.apps import service
    from app.audit.models import AuditLog

    _, _, app = setup
    response = client.patch(
        f"{APPS}/{app['id']}",
        json={
            "env": [
                {"key": "NODE_ENV", "value": "staging"},
                {"key": "DATABASE_URL", "secret": True},
            ]
        },
        headers=admin_headers,
    )
    assert response.status_code == 200
    stored = db.get(Application, app["id"])
    db.refresh(stored)
    assert service.env_values(stored)["DATABASE_URL"] == "postgres://u:hunter2@db/x"
    assert service.env_values(stored)["NODE_ENV"] == "staging"
    entry = db.query(AuditLog).filter(AuditLog.action == "app.update").one()
    assert "staging" not in (entry.detail or "")


def test_delete_queues_container_removal(client, admin_headers, db: Session, setup):
    _, agent, app = setup
    claim(client, agent)  # the initial deploy
    response = client.delete(f"{APPS}/{app['id']}", headers=admin_headers)
    assert response.status_code == 204
    assert db.query(Application).count() == 0
    job = claim(client, agent)
    assert job["type"] == "app.remove" and job["payload"] == {"app": "shop"}


# ---------------------------------------------------------------------------
# Agent side
# ---------------------------------------------------------------------------

from vpspilot_agent import deploy, executor, helper  # noqa: E402


def deploy_args(**extra):
    return {
        "app": "shop",
        "deployment_id": "0" * 32,
        "source": {"type": "git", "url": "https://github.com/acme/shop", "ref": "main"},
        "container_port": 3000,
        "host_port": 20000,
        "env": {"TOKEN": "s3cret-value"},
        **extra,
    }


def test_helper_revalidates_deploy_arguments():
    bad = [
        {"app": "../x"},
        {"source": {"type": "git", "url": "ssh://git@x/y", "ref": "main"}},
        {"source": {"type": "git", "url": "https://x.io/y", "ref": "--upload-pack=x"}},
        {"source": {"type": "git", "url": "https://x.io/y", "ref": "a/../../b"}},
        {"dockerfile": "../Dockerfile"},
        {"host_port": 22},
        {"env": {"A": "x\ny"}},
        {"env": {"BAD-KEY": "x"}},
        {"secret_keys": ["NOT_IN_ENV"]},
        {"memory": "1t"},
    ]
    for extra in bad:
        result = helper.handle({"op": "app.deploy", "args": deploy_args(**extra)})
        assert result["ok"] is False and "invalid" in result["error"], extra
    assert deploy.validate(deploy_args())["env"] == {"TOKEN": "s3cret-value"}


def test_redactor_masks_env_values():
    redact = deploy.Redactor(["s3cret-value", "ab"])
    assert redact("token=s3cret-value ab") == "token=•••••• ab"


def test_build_paths_cannot_escape_the_checkout(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "link").symlink_to("/etc")
    with pytest.raises(deploy.Failed):
        deploy._inside(str(tmp_path / "src"), "link/passwd")
    assert deploy._inside(str(tmp_path / "src"), ".") == str(
        (tmp_path / "src").resolve()
    )


class StreamingClient:
    def __init__(self, env):
        self.calls = []
        self.env = env

    def post(self, path, body):
        self.calls.append((path, body))
        return {}

    def get(self, path):
        self.calls.append((path, None))
        return {"env": self.env, "secret_keys": ["TOKEN"]}


def test_executor_streams_deploy_progress_and_reports_result():
    client = StreamingClient({"TOKEN": "s3cret-value", "PORT": "3000"})
    seen = {}

    def fake_call(op, args, timeout=None, on_event=None):
        seen.update(op=op, args=args)
        on_event("step", "Building vpspilot/shop:abc")
        for i in range(5):
            on_event("output", f"step {i}")
        return {
            "ok": True,
            "exit_code": 0,
            "result": {"commit_sha": "abc", "image_ref": "vpspilot/shop:abc"},
        }

    job = {
        "id": "j9",
        "type": "app.deploy",
        "version": 1,
        "payload": {**deploy_args(), "has_env": True, "env": None},
    }
    del job["payload"]["env"]
    assert executor.run_job(client, job, call=fake_call) == "succeeded"
    assert seen["op"] == "app.deploy"
    assert seen["args"]["env"] == {"TOKEN": "s3cret-value", "PORT": "3000"}
    assert seen["args"]["secret_keys"] == ["TOKEN"]
    assert "has_env" not in seen["args"]

    paths = [path for path, _ in client.calls]
    assert paths[0] == "/agent/v1/jobs/j9/secrets"
    events = [
        e for path, b in client.calls if path.endswith("/events") for e in b["events"]
    ]
    assert events[0]["message"] == "==> Building vpspilot/shop:abc"
    # Output lines are batched into one event.
    assert events[1]["message"] == "step 0\nstep 1\nstep 2\nstep 3\nstep 4"
    path, body = client.calls[-1]
    assert path == "/agent/v1/jobs/j9/complete"
    assert body["result"] == {"commit_sha": "abc", "image_ref": "vpspilot/shop:abc"}
    assert "step 4" in body["output"]
    # The secret never travels back to the control plane.
    assert "s3cret-value" not in json.dumps(client.calls[1:])
