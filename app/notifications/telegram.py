"""Telegram commands: /status, /apps, /alerts and /help, answered by the bot
of a Telegram alert channel that has commands turned on.

Read-only by design: nothing here changes anything. Only messages from the
channel's own chat are answered; anyone else who finds the bot is ignored.
Updates are fetched with long polling by one thread in one API process (a
PostgreSQL advisory lock decides which), so no public webhook is needed.
"""

import html
import logging
import threading
import time
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.notifications import channels
from app.notifications.models import AlertChannel

logger = logging.getLogger(__name__)
API = "https://api.telegram.org"
POLL_SECONDS = 20
LOCK_ID = 7413002
_stop = threading.Event()

HELP = (
    "<b>VPSPilot</b> answers:\n"
    "/status: servers, with CPU, memory and disk\n"
    "/apps: which apps are up\n"
    "/alerts: open alerts\n"
    "/help: this list"
)


def _ago(when: datetime | None) -> str:
    if when is None:
        return "never"
    seconds = (
        datetime.now(UTC) - (when if when.tzinfo else when.replace(tzinfo=UTC))
    ).total_seconds()
    if seconds < 90:
        return "just now"
    if seconds < 5400:
        return f"{int(seconds // 60)} min ago"
    if seconds < 172800:
        return f"{int(seconds // 3600)} h ago"
    return f"{int(seconds // 86400)} days ago"


def status_text(db: Session) -> str:
    from app.servers import service as servers
    from app.servers.models import Server

    rows = list(
        db.scalars(
            select(Server)
            .where(Server.enrolled_at.is_not(None), Server.revoked_at.is_(None))
            .order_by(Server.name)
        )
    )
    if not rows:
        return "No servers enrolled yet."
    samples = servers.latest_samples(db, [s.id for s in rows])
    lines = ["<b>Servers</b>"]
    for server in rows:
        name = html.escape(server.name)
        if servers.status_of(server) != "online":
            lines.append(
                f"🔴 {name}: offline, last seen {_ago(server.last_heartbeat_at)}"
            )
            continue
        sample = samples.get(server.id)
        if sample is None:
            lines.append(f"🟢 {name}")
            continue
        lines.append(
            f"🟢 {name}: CPU {sample.cpu_percent:.0f}% · memory "
            f"{sample.memory_percent:.0f}% · disk {sample.disk_percent:.0f}%"
        )
    return "\n".join(lines)


def apps_text(db: Session) -> str:
    from app.apps.models import Application
    from app.monitoring import service as monitoring
    from app.servers.models import Server

    apps = list(db.scalars(select(Application).order_by(Application.name)))
    if not apps:
        return "No apps yet."
    now = datetime.now(UTC)
    lines = ["<b>Apps</b>"]
    for app in apps:
        server = db.get(Server, app.server_id)
        where = f" on {html.escape(server.name)}" if server else ""
        check = monitoring._check_app(app, server, now)
        if app.current_deployment_id is None:
            lines.append(f"⚪ {html.escape(app.name)}{where}: not deployed yet")
        elif check.breached:
            reason = html.escape(check.detail or "down")
            lines.append(f"❌ {html.escape(app.name)}{where}: {reason}")
        elif check.breached is None:
            lines.append(f"❔ {html.escape(app.name)}{where}: no recent report")
        else:
            lines.append(f"✅ {html.escape(app.name)}{where}")
    return "\n".join(lines)


def alerts_text(db: Session) -> str:
    from app.monitoring import service as monitoring

    alerts = monitoring.list_alerts(db, "open", 15)
    if not alerts:
        return "✅ No open alerts."
    lines = ["<b>Open alerts</b>"]
    for alert in alerts:
        icon = "🔴" if alert.state == "firing" else "👀"
        line = f"{icon} {html.escape(alert.title)}: {html.escape(alert.target_label)}"
        if alert.detail:
            line += f"\n    {html.escape(alert.detail[:200])}"
        lines.append(line)
    return "\n".join(lines)


ANSWERS = {"/status": status_text, "/apps": apps_text, "/alerts": alerts_text}


def answer(db: Session, message_text: str) -> str | None:
    """The reply to a message, or None for anything that isn't a command."""
    if not message_text.startswith("/"):
        return None
    command = message_text.split()[0].split("@")[0].lower()
    if command in ("/help", "/start"):
        return HELP
    handler = ANSWERS.get(command)
    return handler(db) if handler else HELP


def _same_chat(configured: str, chat: dict[str, Any]) -> bool:
    if configured.startswith("@"):
        return f"@{chat.get('username', '')}".lower() == configured.lower()
    return str(chat.get("id")) == configured


def poll_once(db: Session, timeout: int = 0) -> int:
    """Fetch new messages for every channel with commands on, and answer
    them. Returns the number of replies sent."""
    replies = 0
    command_channels = list(
        db.scalars(
            select(AlertChannel).where(
                AlertChannel.kind == "telegram",
                AlertChannel.enabled.is_(True),
                AlertChannel.commands.is_(True),
            )
        )
    )
    for channel in command_channels:
        config = channels._config(channel)
        base = f"{API}/bot{config['bot_token']}"
        try:
            with httpx.Client(timeout=timeout + 10) as client:
                response = client.get(
                    f"{base}/getUpdates",
                    params={
                        "offset": channel.update_offset or 0,
                        "timeout": timeout,
                        "allowed_updates": '["message","channel_post"]',
                    },
                )
                updates = (
                    response.json().get("result") or []
                    if response.status_code == 200
                    else []
                )
                for update in updates:
                    channel.update_offset = int(update["update_id"]) + 1
                    message = update.get("message") or update.get("channel_post") or {}
                    chat = message.get("chat") or {}
                    if not _same_chat(config["chat_id"], chat):
                        continue  # not our chat: say nothing
                    reply = answer(db, str(message.get("text") or ""))
                    if reply is None:
                        continue
                    client.post(
                        f"{base}/sendMessage",
                        json={
                            "chat_id": chat["id"],
                            "text": reply[:4000],
                            "parse_mode": "HTML",
                            "disable_web_page_preview": True,
                            "reply_to_message_id": message.get("message_id"),
                        },
                    )
                    replies += 1
        except (httpx.HTTPError, ValueError, KeyError) as error:
            logger.debug("telegram commands for %s: %s", channel.id, error)
        db.commit()
    return replies


def _loop() -> None:
    from app.core.database import SessionLocal

    while not _stop.is_set():
        with SessionLocal() as db:
            if db.bind.dialect.name == "postgresql":
                # One poller across API processes: Telegram allows one getUpdates.
                got = db.execute(
                    text("SELECT pg_try_advisory_lock(:id)"), {"id": LOCK_ID}
                )
                if not got.scalar():
                    db.rollback()
                    _stop.wait(60)
                    continue
            try:
                while not _stop.is_set():
                    if poll_once(db, POLL_SECONDS) == 0:
                        has_any = db.scalar(
                            select(AlertChannel.id)
                            .where(AlertChannel.commands.is_(True))
                            .limit(1)
                        )
                        if not has_any:
                            _stop.wait(30)
            except Exception:  # noqa: BLE001 - keep answering after a hiccup
                logger.exception("telegram commands failed")
                time.sleep(5)
            finally:
                if db.bind.dialect.name == "postgresql":
                    db.rollback()
                    db.execute(text("SELECT pg_advisory_unlock_all()"))
                    db.commit()


def start() -> threading.Thread:
    _stop.clear()
    thread = threading.Thread(target=_loop, name="telegram", daemon=True)
    thread.start()
    return thread


def stop() -> None:
    _stop.set()
