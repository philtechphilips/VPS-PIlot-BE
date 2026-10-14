"""Alert channels: webhook (signed), Slack, Telegram."""

import hashlib
import hmac
import json
import socket

import pytest
from sqlalchemy.orm import Session

from app.notifications import channels
from app.notifications.models import AlertChannel
from tests.conftest import TestingSessionLocal

CH = "/api/v1/notifications/channels"
TOKEN = "123456789:AAH" + "x" * 32


@pytest.fixture
def sent(monkeypatch, outbox):
    """Captures what channels would POST (and resolves hosts without DNS)."""
    calls = []

    def resolve(host, *args, **kwargs):
        ip = {"internal.test": "127.0.0.1", "meta.test": "169.254.169.254"}.get(
            host, "93.184.216.34"
        )
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]

    class Response:
        def __init__(self, status=200, text="ok"):
            self.status_code, self.text = status, text

        def json(self):
            return json.loads(self.text)

    def post(url, **kwargs):
        channels.check_url(url)
        calls.append({"url": url, **kwargs})
        if "fail.test" in url:
            return Response(500, "boom")
        return Response()

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(channels, "_post", post)
    monkeypatch.setattr(channels, "SessionLocal", TestingSessionLocal)
    return calls


def test_channels_validate_destinations(client, admin_headers, sent):
    bad = [
        {"kind": "slack", "config": {"url": "ftp://hooks.slack.com/x"}},
        {"kind": "slack", "config": {"url": "https://internal.test/hook"}},
        {"kind": "webhook", "config": {"url": "http://meta.test/latest"}},
        {"kind": "webhook", "config": {"url": "https://user:pw@example.com/"}},
        {"kind": "telegram", "config": {"bot_token": "nope", "chat_id": "1"}},
        {"kind": "telegram", "config": {"bot_token": TOKEN, "chat_id": "chat"}},
        {"kind": "slack", "config": {"url": "https://x.example/"}, "events": []},
    ]
    for body in bad:
        response = client.post(CH, json=body, headers=admin_headers)
        assert response.status_code == 422, body


def test_webhook_is_signed_and_secret_shown_once(
    client, admin_headers, db: Session, sent
):
    response = client.post(
        CH,
        json={
            "kind": "webhook",
            "name": "Ops",
            "config": {"url": "https://ops.example/hook"},
        },
        headers=admin_headers,
    )
    assert response.status_code == 201, response.text
    body = response.json()
    secret, channel = body["secret"], body["channel"]
    assert secret and channel["target_label"] == "ops.example"
    assert "secret" not in json.dumps(client.get(CH, headers=admin_headers).json())
    stored = db.get(AlertChannel, channel["id"])
    assert "ops.example/hook" not in stored.config  # encrypted

    tested = client.post(f"{CH}/{channel['id']}/test", headers=admin_headers)
    assert tested.status_code == 200 and tested.json()["last_sent_at"]
    call = sent[-1]
    signature = hmac.new(secret.encode(), call["content"], hashlib.sha256).hexdigest()
    assert call["headers"]["X-VPSPilot-Signature"] == f"sha256={signature}"
    assert json.loads(call["content"])["event"] == "alert.firing"


def test_alerts_and_deployments_reach_subscribed_channels(
    client, admin_headers, db: Session, sent
):
    slack = client.post(
        CH,
        json={"kind": "slack", "name": "#ops", "config": {"url": "https://hooks.slack.example/T1/B2/abc"},
              "events": ["alert.firing", "deployment.failed"]},
        headers=admin_headers,
    ).json()["channel"]  # fmt: skip
    telegram = client.post(
        CH,
        json={"kind": "telegram", "config": {"bot_token": TOKEN, "chat_id": "-100123"},
              "events": ["deployment.succeeded"]},
        headers=admin_headers,
    ).json()["channel"]  # fmt: skip
    from datetime import UTC, datetime

    from app.notifications import service

    service.alert_changed(
        db, firing=True, severity="critical", title="CPU high on web-1",
        detail="97% for 5 minutes", email=False, started_at=datetime.now(UTC),
    )  # fmt: skip
    assert len(sent) == 1 and "CPU high on web-1" in sent[0]["json"]["text"]
    service.alert_changed(
        db, firing=False, severity="critical", title="CPU high on web-1",
        detail=None, email=False, started_at=datetime.now(UTC),
    )  # fmt: skip
    assert len(sent) == 1  # nobody subscribed to resolved

    channels.dispatch(
        db, "deployment.succeeded", {"title": "shop deployed", "detail": "<b>x</b>"}
    )
    call = sent[-1]
    assert call["url"] == f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    assert call["json"]["chat_id"] == "-100123" and "&lt;b&gt;" in call["json"]["text"]
    assert db.get(AlertChannel, telegram["id"]).last_sent_at is not None
    assert db.get(AlertChannel, slack["id"]).last_error is None


def test_failures_are_recorded_and_disabled_channels_skip(
    client, admin_headers, db: Session, sent
):
    channel = client.post(
        CH, json={"kind": "slack", "config": {"url": "https://fail.test/x"}}, headers=admin_headers
    ).json()["channel"]  # fmt: skip
    tested = client.post(f"{CH}/{channel['id']}/test", headers=admin_headers)
    assert tested.status_code == 502 and "500" in tested.json()["detail"]
    row = db.get(AlertChannel, channel["id"])
    db.refresh(row)
    assert row.last_error.startswith("It answered 500")

    off = client.patch(
        f"{CH}/{channel['id']}", json={"enabled": False}, headers=admin_headers
    )
    assert off.json()["enabled"] is False
    count = len(sent)
    channels.dispatch(db, "alert.firing", {"title": "x"})
    assert len(sent) == count
    moved = client.patch(
        f"{CH}/{channel['id']}", json={"config": {"url": "https://ok.example/y"}},
        headers=admin_headers,
    )  # fmt: skip
    assert moved.json()["target_label"] == "ok.example"
    assert (
        client.delete(f"{CH}/{channel['id']}", headers=admin_headers).status_code == 204
    )


def test_channels_are_admin_only(client, user_headers):
    assert client.get(CH, headers=user_headers).status_code == 403
