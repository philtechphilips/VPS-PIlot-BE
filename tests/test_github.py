import hashlib
import hmac
import json
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.orm import Session

from app.apps.models import Application, Deployment
from app.core.config import settings
from app.github import client, service
from app.github.models import GitHubApp
from tests.test_jobs import claim
from tests.test_servers import enrolled_agent

GH = "/api/v1/github"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()
REPO = {
    "id": 4242,
    "name": "shop",
    "full_name": "acme/shop",
    "owner": {"login": "acme"},
    "private": True,
    "default_branch": "main",
    "html_url": "https://github.com/acme/shop",
    "description": "The shop",
    "language": "TypeScript",
    "pushed_at": "2026-10-14T10:00:00Z",
}


class FakeGitHub:
    def __init__(self):
        self.calls = []
        self.installations = {
            77: {
                "id": 77,
                "account": {"login": "acme", "type": "Organization"},
                "repository_selection": "selected",
            }
        }

    def __call__(self, method, path, token=None, json=None, params=None):
        self.calls.append((method, path, token, json))
        if path.startswith("/app-manifests/"):
            return {
                "id": 9001,
                "slug": "vpspilot-abc123",
                "name": "VPSPilot abc123",
                "owner": {"login": "acme", "type": "Organization"},
                "html_url": "https://github.com/apps/vpspilot-abc123",
                "client_id": "Iv1.client",
                "client_secret": "client-secret-value",
                "pem": PEM,
                "webhook_secret": "hook-secret",
            }
        if path.startswith("/app/"):
            # App-level calls must be signed with the app's private key.
            claims = jwt.decode(token, KEY.public_key(), algorithms=["RS256"])
            assert claims["iss"] == "9001"
        if path == "/app/installations":
            return list(self.installations.values())
        if path.startswith("/app/installations/") and path.endswith("/access_tokens"):
            scoped = "repo" if json and json.get("repository_ids") else "all"
            return {"token": f"ghs_{scoped}token0123456789abcdef"}
        if path.startswith("/app/installations/"):
            inst = self.installations.get(int(path.rsplit("/", 1)[1]))
            if inst is None:
                raise client.GitHubError(404, "Not Found")
            return inst
        if path == "/installation/repositories":
            return {"repositories": [REPO]}
        if path == f"/repositories/{REPO['id']}":
            return REPO
        if path == "/repos/acme/shop/branches":
            return [{"name": "dev"}, {"name": "main"}]
        raise AssertionError(f"unexpected call {method} {path}")


@pytest.fixture
def fake(monkeypatch):
    gh = FakeGitHub()
    monkeypatch.setattr(client, "request", gh)
    monkeypatch.setattr(settings, "public_api_url", "https://pilot.example.com")
    service._tokens.clear()
    return gh


def connect(client_, headers):
    start = client_.post(f"{GH}/manifest", json={}, headers=headers).json()
    state = parse_qs(urlparse(start["post_url"]).query)["state"][0]
    return client_.post(
        f"{GH}/manifest/complete", json={"code": "abc", "state": state}, headers=headers
    )


def test_manifest_asks_for_read_only_access_and_push_events(
    client, admin_headers, fake
):
    body = client.post(
        f"{GH}/manifest", json={"organization": "acme"}, headers=admin_headers
    ).json()
    assert body["post_url"].startswith(
        "https://github.com/organizations/acme/settings/apps/new?state="
    )
    manifest = body["manifest"]
    # Read-only everywhere: code, metadata, and pull requests for previews.
    assert manifest["default_permissions"] == {
        "contents": "read",
        "metadata": "read",
        "pull_requests": "read",
    }
    assert manifest["default_events"] == ["push", "pull_request"]
    assert (
        manifest["hook_attributes"]["url"]
        == "https://pilot.example.com/api/v1/github/webhook"
    )
    assert manifest["public"] is False
    bad = client.post(
        f"{GH}/manifest", json={"organization": "a/b"}, headers=admin_headers
    )
    assert bad.status_code == 422


def test_no_webhooks_without_a_public_url(client, admin_headers, fake, monkeypatch):
    monkeypatch.setattr(settings, "public_api_url", "")
    monkeypatch.setattr(settings, "agent_api_url", "http://host.lima.internal:8000")
    body = client.post(f"{GH}/manifest", json={}, headers=admin_headers).json()
    assert body["webhooks"] is False and "hook_attributes" not in body["manifest"]


def test_connect_stores_encrypted_credentials(client, admin_headers, fake, db: Session):
    response = connect(client, admin_headers)
    assert response.status_code == 200, response.text
    status = response.json()
    assert (
        status["connected"]
        and status["app"]["install_url"]
        == "https://github.com/apps/vpspilot-abc123/installations/new"
    )
    stored = db.query(GitHubApp).one()
    assert "PRIVATE KEY" not in stored.private_key
    assert stored.client_secret != "client-secret-value"
    # Only once per install.
    assert (
        client.post(f"{GH}/manifest", json={}, headers=admin_headers).status_code == 409
    )


def test_state_is_checked(client, admin_headers, fake):
    response = client.post(
        f"{GH}/manifest/complete",
        json={"code": "abc", "state": "forged"},
        headers=admin_headers,
    )
    assert response.status_code == 400


def test_install_list_repos_and_branches(client, admin_headers, fake):
    connect(client, admin_headers)
    missing = client.post(
        f"{GH}/installations", json={"installation_id": 5}, headers=admin_headers
    )
    assert missing.status_code == 409
    status = client.post(
        f"{GH}/installations", json={"installation_id": 77}, headers=admin_headers
    ).json()
    assert status["installations"][0]["account_login"] == "acme"
    repos = client.get(f"{GH}/repositories", headers=admin_headers).json()
    assert repos[0]["full_name"] == "acme/shop" and repos[0]["private"] is True
    assert repos[0]["clone_url"] == "https://github.com/acme/shop"
    branches = client.get(
        f"{GH}/repositories/77/4242/branches", headers=admin_headers
    ).json()
    assert branches == ["main", "dev"]


@pytest.fixture
def linked_app(client, admin_headers, fake):
    connect(client, admin_headers)
    client.post(
        f"{GH}/installations", json={"installation_id": 77}, headers=admin_headers
    )
    server_id, agent = enrolled_agent(client, admin_headers)
    response = client.post(
        "/api/v1/applications",
        json={
            "name": "shop",
            "server_id": server_id,
            "source": {
                "type": "git",
                "branch": "main",
                "installation_id": 77,
                "repo_id": 4242,
            },
            "container_port": 3000,
        },
        headers=admin_headers,
    )
    assert response.status_code == 201, response.text
    return response.json(), agent


def test_private_repo_deploy_gets_a_repo_scoped_token(client, linked_app, fake):
    app, agent = linked_app
    assert app["github_repo"] == "acme/shop" and app["auto_deploy"] is True
    job = claim(client, agent)
    assert job["payload"]["source"] == {
        "type": "git",
        "url": "https://github.com/acme/shop",
        "ref": "main",
        "auth": True,
    }
    secrets = client.get(f"/agent/v1/jobs/{job['id']}/secrets", headers=agent).json()
    assert secrets["git_token"] == "ghs_repotoken0123456789abcdef"
    minted = [c for c in fake.calls if c[3] and c[3].get("repository_ids")]
    assert minted[-1][3] == {
        "repository_ids": [4242],
        "permissions": {"contents": "read"},
    }
    # The token never lands in the job record.
    assert "ghs_" not in json.dumps(job)


def sign(body: bytes, secret: str = "hook-secret") -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def push(client, body: dict, secret: str = "hook-secret"):
    raw = json.dumps(body).encode()
    return client.post(
        f"{GH}/webhook",
        content=raw,
        headers={
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": sign(raw, secret),
            "Content-Type": "application/json",
        },
    )


PUSH = {
    "ref": "refs/heads/main",
    "after": "a" * 40,
    "repository": {"id": 4242},
    "pusher": {"name": "ada"},
    "head_commit": {"message": "Fix checkout\n\nlonger body"},
}


def test_push_deploys_linked_apps(client, linked_app, db: Session):
    app, agent = linked_app
    claim(client, agent)  # the initial deploy
    assert push(client, PUSH, secret="wrong").status_code == 401
    response = push(client, PUSH)
    assert response.json() == {"deployments": 1}
    dep = db.query(Deployment).filter(Deployment.trigger == "push").one()
    assert dep.requested_ref == "a" * 40 and dep.commit_message == "Fix checkout"
    assert dep.created_by == "GitHub push by ada"
    # Other branches, deleted branches and disabled auto-deploy are ignored.
    assert push(client, {**PUSH, "ref": "refs/heads/dev"}).json() == {"deployments": 0}
    assert push(client, {**PUSH, "deleted": True}).json() == {"deployments": 0}
    client_app = db.get(Application, app["id"])
    client_app.auto_deploy = False
    db.commit()
    assert push(client, PUSH).json() == {"deployments": 0}


def test_installation_removed_on_github(client, linked_app, db: Session):
    raw = json.dumps(
        {"action": "deleted", "installation": {"id": 77, "account": {"login": "acme"}}}
    ).encode()
    response = client.post(
        f"{GH}/webhook",
        content=raw,
        headers={"X-GitHub-Event": "installation", "X-Hub-Signature-256": sign(raw)},
    )
    assert response.status_code == 202
    from app.github.models import GitHubInstallation

    assert db.query(GitHubInstallation).count() == 0


def test_agent_validates_git_tokens():
    from vpspilot_agent import deploy

    base = {
        "app": "shop",
        "deployment_id": "0" * 32,
        "source": {"type": "git", "url": "https://github.com/acme/shop", "ref": "main"},
        "container_port": 3000,
        "host_port": 20000,
    }
    assert deploy.validate({**base, "git_token": "ghs_" + "a" * 36})["git_token"]
    # Current GitHub installation tokens: ~390 chars with "." and "-".
    modern = "ghs_" + "Ab9_.-" * 64
    assert deploy.validate({**base, "git_token": modern})["git_token"] == modern
    for bad in (
        "short",
        "ghs_x;rm -rf /" + "a" * 20,
        "ghs_" + "a" * 30 + "\n",
        "x" * 3000,
    ):
        with pytest.raises(deploy.Rejected):
            deploy.validate({**base, "git_token": bad})
    image = {**base, "source": {"type": "image", "image": "nginx:1"}}
    with pytest.raises(deploy.Rejected):
        deploy.validate({**image, "git_token": "ghs_" + "a" * 36})
    token = "ghs_" + "b" * 36
    assert token not in deploy.Redactor([token])(f"fatal: auth {token}")


def test_agent_rejects_trailing_newlines():
    from vpspilot_agent import deploy, helper

    base = {
        "app": "shop",
        "deployment_id": "0" * 32,
        "source": {"type": "git", "url": "https://github.com/acme/shop", "ref": "main"},
        "container_port": 3000,
        "host_port": 20000,
    }
    for bad in (
        {"app": "shop\n"},
        {"source": {**base["source"], "ref": "main\n"}},
        {"source": {**base["source"], "url": "https://github.com/acme/shop\n"}},
    ):
        with pytest.raises(deploy.Rejected):
            deploy.validate({**base, **bad})
    result = helper.handle(
        {"op": "service.restart", "args": {"unit": "cron.service\n"}}
    )
    assert result["ok"] is False
