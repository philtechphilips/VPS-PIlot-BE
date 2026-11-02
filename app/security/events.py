"""Account and team changes worth knowing about as they happen: a sign-in
from a new address, a recovery code used, a password changed or reset, an
account locked, an authenticator set up, a role changed or an admin added.

Each one goes to the audit log, every admin's inbox, alert channels that
take the "security" event and, by email, to the account it's about.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import service as audit
from app.core.config import settings

logger = logging.getLogger(__name__)

KNOWN_FOR = timedelta(days=180)


def _url(path: str) -> str:
    return f"{settings.frontend_url.rstrip('/')}{path}"


def _send(to: str, data: dict) -> None:
    from app.notifications import emails

    try:
        emails.send_security_email(to, data)
    except Exception:  # noqa: BLE001 - an email must never break a sign-in
        logger.exception("security email to %s failed", to)


def record(
    db: Session,
    action: str,
    title: str,
    detail: str,
    *,
    user=None,
    actor: tuple[str, str] = ("system", "system"),
    request=None,
    email: bool = True,
) -> None:
    """Report one event. Commits."""
    from app.notifications import channels
    from app.notifications import service as notifications

    audit.record(
        db,
        action=f"security.{action}",
        result="success",
        actor=actor[0],
        actor_label=actor[1],
        target_type="user" if user is not None else None,
        target_id=str(user.id) if user is not None else None,
        target_label=user.email if user is not None else None,
        detail=detail,
        request=request,
        commit=False,
    )
    notifications.notify(db, "security", "warn", title, detail, "/dashboard/security")
    link = _url("/dashboard/settings#sessions")
    channels.dispatch(db, "security", {"title": title, "detail": detail, "url": link})
    if email and user is not None:
        notifications._background(
            _send, user.email, {"title": title, "detail": detail, "url": link}
        )
    db.commit()


def device(user_agent: str | None) -> str:
    """ "Chrome on macOS" from a User-Agent, good enough for a notification."""
    ua = user_agent or ""
    browser = next(
        (
            name
            for pattern, name in (
                (r"Edg/", "Edge"),
                (r"OPR/|Opera", "Opera"),
                (r"Firefox/", "Firefox"),
                (r"Chrome/", "Chrome"),
                (r"Safari/", "Safari"),
                (r"curl/", "curl"),
            )
            if re.search(pattern, ua)
        ),
        "an unknown browser",
    )
    system = next(
        (
            name
            for pattern, name in (
                (r"iPhone|iPad", "iOS"),
                (r"Android", "Android"),
                (r"Mac OS X|Macintosh", "macOS"),
                (r"Windows", "Windows"),
                (r"Linux", "Linux"),
            )
            if re.search(pattern, ua)
        ),
        None,
    )
    return f"{browser} on {system}" if system else browser


def is_new_address(db: Session, user, ip: str | None) -> bool:
    """True when the account has signed in before, but not from this address
    lately. Call before creating the new session."""
    from app.auth.models import AuthSession

    if not ip:
        return False
    since = datetime.now(UTC) - KNOWN_FOR
    earlier = db.scalars(
        select(AuthSession.ip_address).where(AuthSession.user_id == user.id)
    ).all()
    if not earlier:
        return False  # first sign-in ever
    seen = db.scalar(
        select(AuthSession.id).where(
            AuthSession.user_id == user.id,
            AuthSession.ip_address == ip,
            AuthSession.created_at >= since,
        )
    )
    return seen is None


def new_sign_in(
    db: Session, user, ip: str, user_agent: str | None, request=None
) -> None:
    record(
        db,
        "new_sign_in",
        f"New sign-in to {user.email}",
        f"From {ip} using {device(user_agent)}, an address this account hasn't "
        "used in the last 180 days.",
        user=user,
        actor=(f"user:{user.id}", user.email),
        request=request,
    )
