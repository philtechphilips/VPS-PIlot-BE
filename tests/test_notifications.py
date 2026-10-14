from sqlalchemy.orm import Session

from tests.test_apps import APPS, complete, git_app
from tests.test_jobs import claim
from tests.test_servers import enrolled_agent

INBOX = "/api/v1/notifications"


def deploy_once(client, headers, ok=True, name="shop"):
    server_id, agent = enrolled_agent(client, headers, name=f"srv-{name}")
    app = client.post(APPS, json=git_app(server_id, name=name), headers=headers).json()
    job = claim(client, agent)
    result = {
        "commit_sha": "a" * 40,
        "commit_message": "Fix checkout",
        "image_ref": "vpspilot/shop:1",
        "build_plan": "Next.js · npm · Node 22",
    }
    complete(
        client,
        agent,
        job["id"],
        ok=ok,
        result=result,
        error=None if ok else "The image build failed",
    )
    return app, agent


def deployment_mail(outbox):
    return [m for m in outbox if "deploy" in m.subject]


def test_success_emails_and_inbox(client, admin_headers, outbox):
    deploy_once(client, admin_headers)
    mails = deployment_mail(outbox)
    assert len(mails) == 1
    assert mails[0].subject == "shop deployed · aaaaaaa"
    assert "Next.js · npm · Node 22" in mails[0].text
    assert "/dashboard/deployments/" in mails[0].text
    inbox = client.get(INBOX, headers=admin_headers).json()
    assert inbox["unread"] == 1
    item = inbox["items"][0]
    assert item["level"] == "ok" and item["title"] == "shop deployed to srv-shop"
    assert item["link"].startswith("/dashboard/deployments/")


def test_failure_email_says_previous_is_live(client, admin_headers, outbox):
    app, agent = deploy_once(client, admin_headers)
    client.post(f"{APPS}/{app['id']}/deployments", json={}, headers=admin_headers)
    job = claim(client, agent)
    complete(client, agent, job["id"], ok=False, error="Health check failed")
    failed = deployment_mail(outbox)[-1]
    assert failed.subject == "shop deployment failed"
    assert "Health check failed. The previous version is still live." in failed.text


def test_failure_notification(client, admin_headers, outbox):
    deploy_once(client, admin_headers, ok=False)
    mails = deployment_mail(outbox)
    assert mails[0].subject == "shop deployment failed"
    assert "The image build failed" in mails[0].text
    inbox = client.get(INBOX, headers=admin_headers).json()
    assert inbox["items"][0]["level"] == "err"
    assert inbox["items"][0]["body"] == "The image build failed"


def test_email_preferences(client, admin_headers, outbox):
    prefs = client.get(f"{INBOX}/settings", headers=admin_headers).json()
    assert (
        prefs["email_deploy_success"] is True and prefs["email_deploy_failure"] is True
    )
    updated = client.put(
        f"{INBOX}/settings", json={"email_deploy_success": False}, headers=admin_headers
    ).json()
    assert (
        updated["email_deploy_success"] is False
        and updated["email_deploy_failure"] is True
    )
    deploy_once(client, admin_headers)
    assert deployment_mail(outbox) == []
    # The inbox still records it.
    assert client.get(INBOX, headers=admin_headers).json()["unread"] == 1


def test_mark_read(client, admin_headers, outbox, db: Session):
    deploy_once(client, admin_headers, name="one")
    deploy_once(client, admin_headers, name="two")
    items = client.get(INBOX, headers=admin_headers).json()["items"]
    assert (
        client.post(
            f"{INBOX}/read", json={"ids": [items[0]["id"]]}, headers=admin_headers
        ).status_code
        == 204
    )
    assert client.get(INBOX, headers=admin_headers).json()["unread"] == 1
    client.post(f"{INBOX}/read", json={}, headers=admin_headers)
    assert client.get(INBOX, headers=admin_headers).json()["unread"] == 0


def test_inbox_is_per_user(client, admin_headers, user_headers, outbox):
    deploy_once(client, admin_headers)
    # Regular users aren't admins, so they don't get deployment notifications.
    assert client.get(INBOX, headers=user_headers).json() == {"items": [], "unread": 0}
