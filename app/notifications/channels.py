"""Alert channels: webhooks, Slack and Telegram.

Messages are sent from the control plane, off the request path. A channel
can't be pointed at the control plane's own host or link-local addresses
(cloud metadata), and redirects aren't followed, so channels can't be used
to reach internal services. Private network addresses are allowed (a chat
server on your LAN).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import socket
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.security import decrypt_secret, encrypt_secret, new_id
from app.notifications.models import AlertChannel

logger = logging.getLogger(__name__)

PURPOSE = "alert-channels"
KINDS = ("webhook", "slack", "telegram")
EVENTS = (
    "alert.firing",
    "alert.resolved",
    "deployment.failed",
    "deployment.succeeded",
    "job.failed",
    "report.weekly",
)
DEFAULT_EVENTS = [
    "alert.firing",
    "alert.resolved",
    "deployment.failed",
    "job.failed",
    "report.weekly",
]
TIMEOUT = 10
TELEGRAM_TOKEN_RE = re.compile(r"\d{5,12}:[A-Za-z0-9_-]{30,50}")
TELEGRAM_CHAT_RE = re.compile(r"-?\d{1,20}|@[A-Za-z0-9_]{5,32}")
EMOJI = {
    "alert.firing": "🔴",
    "alert.resolved": "✅",
    "deployment.failed": "❌",
    "deployment.succeeded": "🚀",
    "job.failed": "⏰",
    "report.weekly": "📊",
}


class ChannelError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Destination checks
# ---------------------------------------------------------------------------


def check_url(url: str) -> str:
    """http(s) URL whose host isn't this machine or link-local."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ChannelError(422, "Use an http:// or https:// URL")
    if parts.username or parts.password:
        raise ChannelError(
            422, "Put credentials in the URL path or headers, not user:pass@"
        )
    host = parts.hostname
    try:
        infos = socket.getaddrinfo(host, parts.port or 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        raise ChannelError(422, f"{host} doesn't resolve") from None
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%")[0])
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if (
            address.is_loopback
            or address.is_link_local
            or address.is_unspecified
            or address.is_multicast
            or address.is_reserved
        ):
            raise ChannelError(
                422, f"{host} resolves to {address}, which channels can't reach"
            )
    return url


def _post(url: str, **kwargs: Any) -> httpx.Response:
    check_url(url)
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as client:
        return client.post(url, **kwargs)


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


def _limit(event: str) -> int:
    """Detail length: the weekly report is long, alerts aren't."""
    return 3500 if event == "report.weekly" else 500


def _text(event: str, data: dict[str, Any]) -> str:
    lines = [f"{EMOJI.get(event, '•')} {data['title']}"]
    if data.get("detail"):
        lines.append(str(data["detail"])[: _limit(event)])
    if data.get("url"):
        lines.append(str(data["url"]))
    return "\n".join(lines)


def _html_escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def deliver(
    kind: str, config: dict[str, Any], event: str, data: dict[str, Any]
) -> None:
    """Send one message; raises ChannelError with a readable reason."""
    try:
        if kind == "slack":
            text = _text(event, data)
            response = _post(config["url"], json={"text": text})
        elif kind == "telegram":
            body = f"{EMOJI.get(event, '•')} <b>{_html_escape(data['title'])}</b>"
            if data.get("detail"):
                body += f"\n{_html_escape(str(data['detail'])[: _limit(event)])}"
            if data.get("url"):
                body += f"\n{_html_escape(str(data['url']))}"
            response = _post(
                f"https://api.telegram.org/bot{config['bot_token']}/sendMessage",
                json={
                    "chat_id": config["chat_id"],
                    "text": body,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
            )
        else:
            payload = json.dumps(
                {"event": event, "sent_at": _now().isoformat(), **data}, default=str
            ).encode()
            signature = hmac.new(
                config["secret"].encode(), payload, hashlib.sha256
            ).hexdigest()
            response = _post(
                config["url"],
                content=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "VPSPilot",
                    "X-VPSPilot-Event": event,
                    "X-VPSPilot-Signature": f"sha256={signature}",
                },
            )
    except httpx.HTTPError as error:
        raise ChannelError(502, f"Couldn't reach it: {type(error).__name__}") from None
    if response.status_code >= 300:
        detail = response.text[:150].strip()
        if kind == "telegram":
            try:
                detail = response.json().get("description", detail)
            except ValueError:
                pass
        raise ChannelError(
            502, f"It answered {response.status_code}{': ' + detail if detail else ''}"
        )


# ---------------------------------------------------------------------------
# Channels
# ---------------------------------------------------------------------------


def _config(channel: AlertChannel) -> dict[str, Any]:
    return json.loads(decrypt_secret(channel.config, PURPOSE))


def _validate(kind: str, config: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Normalised config and the label shown in lists."""
    if kind in ("webhook", "slack"):
        url = str(config.get("url") or "").strip()
        if len(url) > 1000:
            raise ChannelError(422, "That URL is too long")
        check_url(url)
        out = {"url": url}
        return out, urlsplit(url).hostname or url
    token = str(config.get("bot_token") or "").strip()
    chat = str(config.get("chat_id") or "").strip()
    if not TELEGRAM_TOKEN_RE.fullmatch(token):
        raise ChannelError(422, "That doesn't look like a bot token (123456:ABC…)")
    if not TELEGRAM_CHAT_RE.fullmatch(chat):
        raise ChannelError(422, "The chat ID is a number (or @channelname)")
    return {"bot_token": token, "chat_id": chat}, f"chat {chat}"


def _events(events: list[str] | None) -> list[str]:
    chosen = [e for e in (DEFAULT_EVENTS if events is None else events) if e in EVENTS]
    if not chosen:
        raise ChannelError(422, "Pick at least one event")
    return list(dict.fromkeys(chosen))


def list_channels(db: Session) -> list[AlertChannel]:
    return list(db.scalars(select(AlertChannel).order_by(AlertChannel.created_at)))


def create(
    db: Session,
    kind: str,
    name: str,
    config: dict[str, Any],
    events: list[str] | None,
    label: str,
    commands: bool = False,
) -> tuple[AlertChannel, str | None]:
    """Returns the channel and, for webhooks, its signing secret (shown once)."""
    if kind not in KINDS:
        raise ChannelError(422, "Unknown channel type")
    clean, target = _validate(kind, config)
    secret = None
    if kind == "webhook":
        secret = clean["secret"] = secrets.token_urlsafe(32)
    channel = AlertChannel(
        id=new_id(),
        kind=kind,
        name=name.strip()[:60] or kind.title(),
        config=encrypt_secret(json.dumps(clean), PURPOSE),
        target_label=target[:120],
        events=_events(events),
        enabled=True,
        commands=commands and kind == "telegram",
        created_by=label[:64],
        created_at=_now(),
    )
    db.add(channel)
    db.commit()
    return channel, secret


def update(db: Session, channel: AlertChannel, data: dict[str, Any]) -> AlertChannel:
    if data.get("name") is not None:
        channel.name = data["name"].strip()[:60] or channel.name
    if data.get("events") is not None:
        channel.events = _events(data["events"])
    if data.get("enabled") is not None:
        channel.enabled = bool(data["enabled"])
    if data.get("commands") is not None:
        channel.commands = bool(data["commands"]) and channel.kind == "telegram"
    if data.get("config"):
        clean, target = _validate(channel.kind, data["config"])
        if channel.kind == "webhook":
            clean["secret"] = _config(channel)["secret"]
        channel.config = encrypt_secret(json.dumps(clean), PURPOSE)
        channel.target_label = target[:120]
    db.commit()
    return channel


def test(db: Session, channel: AlertChannel) -> None:
    """Send a test message now; records the outcome like a real one."""
    data = {
        "title": f"Test message from VPSPilot ({channel.name})",
        "detail": "Alerts and deployment results you picked will arrive here.",
        "severity": "info",
    }
    _record(db, channel, "alert.firing", data)
    if channel.last_error:
        raise ChannelError(502, channel.last_error)


def _record(
    db: Session, channel: AlertChannel, event: str, data: dict[str, Any]
) -> None:
    try:
        deliver(channel.kind, _config(channel), event, data)
        channel.last_sent_at = _now()
        channel.last_error = None
    except ChannelError as error:
        channel.last_error = error.detail[:300]
    except Exception as error:  # noqa: BLE001 - one channel must not break others
        logger.exception("alert channel %s failed", channel.id)
        channel.last_error = f"Failed: {type(error).__name__}"
    db.commit()


def _send_all(channel_ids: list[str], event: str, data: dict[str, Any]) -> None:
    with SessionLocal() as db:
        for channel_id in channel_ids:
            channel = db.get(AlertChannel, channel_id)
            if channel is not None and channel.enabled:
                _record(db, channel, event, data)


def dispatch(db: Session, event: str, data: dict[str, Any]) -> int:
    """Queue a message to every enabled channel that wants this event."""
    from app.notifications import service

    ids = [
        c.id
        for c in db.scalars(select(AlertChannel).where(AlertChannel.enabled.is_(True)))
        if event in (c.events or [])
    ]
    if ids:
        service._background(_send_all, ids, event, data)
    return len(ids)
