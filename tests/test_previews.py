"""Preview deployments for pull requests."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.apps import previews
from app.apps import service as apps
from app.apps.models import Application, Deployment
from app.domains.models import Domain
from tests.test_apps import APPS, git_app
from tests.test_servers import enrolled_agent

REPO = 81723


def _event(action, number=12, sha="a" * 40, branch="feature/cart", fork=False):
    return {
        "action": action,
        "number": number,
        "repository": {"id": REPO, "full_name": "acme/shop"},
        "pull_request": {
            "number": number,
            "head": {"sha": sha, "ref": branch, "repo": {"id": 999 if fork else REPO}},
        },
    }


def _parent(client, admin_headers, db):
    server_id, agent = enrolled_agent(client, admin_headers)
    app = client.post(
        APPS, json=git_app(server_id, deploy=False), headers=admin_headers
    ).json()
    row = db.get(Application, app["id"])
    row.github_repo_id = REPO
    db.commit()
    res = client.patch(
        f"{APPS}/{app['id']}",
        json={
            "preview_domain": "preview.example.com",
            "preview_env": [
                {"key": "DATABASE_URL", "value": "postgresql://staging", "secret": True}
            ],
        },
        headers=admin_headers,
    )
    assert res.status_code == 200, res.text
    return app, agent


def test_pull_requests_get_previews(client, admin_headers, db: Session):
    app, agent = _parent(client, admin_headers, db)
    assert previews.handle(db, _event("opened")) == 1
    preview = db.scalars(
        select(Application).where(Application.preview_of == app["id"])
    ).one()
    assert preview.name == "shop-pr-12" and preview.branch == "feature/cart"
    assert preview.private_port and not preview.auto_deploy
    env = apps.env_values(preview)
    assert (
        env["DATABASE_URL"] == "postgresql://staging"
        and env["NODE_ENV"] == "production"
    )
    domain = db.scalars(select(Domain).where(Domain.application_id == preview.id)).one()
    assert domain.hostname == "pr-12.preview.example.com"
    deploys = db.scalars(
        select(Deployment).where(Deployment.application_id == preview.id)
    ).all()
    assert [d.requested_ref for d in deploys] == ["a" * 40]

    # A push to the pull request redeploys the same preview.
    previews.handle(db, _event("synchronize", sha="b" * 40))
    assert (
        db.scalars(select(Application).where(Application.preview_of == app["id"]))
        .one()
        .id
        == preview.id
    )
    listed = client.get(f"{APPS}/{app['id']}", headers=admin_headers).json()
    assert listed["previews"] == [{"id": preview.id, "name": "shop-pr-12", "pr": 12}]

    # Closed: the preview and its domain go.
    previews.handle(db, _event("closed"))
    assert (
        db.scalars(
            select(Application).where(Application.preview_of == app["id"])
        ).first()
        is None
    )
    assert (
        db.scalars(
            select(Domain).where(Domain.hostname == "pr-12.preview.example.com")
        ).first()
        is None
    )


def test_forks_get_no_preview(client, admin_headers, db: Session):
    app, _ = _parent(client, admin_headers, db)
    assert previews.handle(db, _event("opened", fork=True)) == 0
    assert (
        db.scalars(
            select(Application).where(Application.preview_of == app["id"])
        ).first()
        is None
    )


def test_previews_need_github(client, admin_headers):
    server_id, _ = enrolled_agent(client, admin_headers)
    app = client.post(
        APPS, json=git_app(server_id, deploy=False), headers=admin_headers
    ).json()
    res = client.patch(
        f"{APPS}/{app['id']}",
        json={"preview_domain": "preview.example.com"},
        headers=admin_headers,
    )
    assert res.status_code == 422 and "GitHub" in res.json()["detail"]
