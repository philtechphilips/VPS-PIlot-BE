"""Telegram commands: read-only answers, only in the channel's own chat."""

import json

import httpx
from sqlalchemy.orm import Session

from app.notifications import telegram
from app.notifications.models import AlertChannel
from tests.test_apps import APPS, git_app
from tests.test_servers import enrolled_agent

TOKEN = "123456789:" + "A" * 35


def _channel(client, admin_headers, commands=True):
    made = client.post(
        "/api/v1/notifications/channels",
        json={
            "kind": "telegram",
            "name": "On call",
            "config": {"bot_token": TOKEN, "chat_id": "-1001"},
            "commands": commands,
        },
        headers=admin_headers,
    )
    assert made.status_code == 201, made.text
    return made.json()["channel"]


def _fake_telegram(monkeypatch, updates):
    sent = []
    offsets = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/getUpdates"):
            offsets.append(request.url.params.get("offset"))
            return httpx.Response(200, json={"ok": True, "result": updates})
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"ok": True})

    real = httpx.Client
    monkeypatch.setattr(
        telegram.httpx,
        "Client",
        lambda **kw: real(transport=httpx.MockTransport(handler), **kw),
    )
    return sent, offsets


def _message(update_id, text, chat_id=-1001):
    return {
        "update_id": update_id,
        "message": {"message_id": update_id, "chat": {"id": chat_id}, "text": text},
    }


def test_commands_answer_in_the_channels_chat_only(
    client, admin_headers, db: Session, monkeypatch
):
    server_id, _ = enrolled_agent(client, admin_headers)
    client.post(APPS, json=git_app(server_id), headers=admin_headers)
    channel = _channel(client, admin_headers)
    assert channel["commands"] is True
    sent, offsets = _fake_telegram(
        monkeypatch,
        [
            _message(10, "/status"),
            _message(11, "/apps@my_bot"),
            _message(12, "/alerts"),
            _message(13, "hello there"),  # not a command: no reply
            _message(14, "/status", chat_id=999),  # a stranger: ignored
        ],
    )
    assert telegram.poll_once(db) == 3
    assert [m["chat_id"] for m in sent] == [-1001, -1001, -1001]
    assert "web-1" in sent[0]["text"]
    assert "shop" in sent[1]["text"] and "not deployed yet" in sent[1]["text"]
    assert sent[2]["text"] == "✅ No open alerts."
    row = db.get(AlertChannel, channel["id"])
    db.refresh(row)
    assert row.update_offset == 15  # next poll starts after what we've read
    telegram.poll_once(db)
    assert offsets[-1] == "15"


def test_commands_are_off_unless_turned_on(
    client, admin_headers, db: Session, monkeypatch
):
    _channel(client, admin_headers, commands=False)
    sent, offsets = _fake_telegram(monkeypatch, [_message(1, "/status")])
    assert telegram.poll_once(db) == 0 and offsets == [] and sent == []


def test_help_for_unknown_commands(db: Session):
    assert "/status" in telegram.answer(db, "/restart everything")
    assert telegram.answer(db, "just chatting") is None
