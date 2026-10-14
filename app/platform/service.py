"""Control-plane identity: name, public URL and version."""

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app import __version__
from app.core.config import settings
from app.platform.models import PlatformSettings


def get(db: Session) -> PlatformSettings:
    row = db.get(PlatformSettings, 1)
    if row is None:
        row = PlatformSettings(id=1, name="VPSPilot")
        db.add(row)
        db.commit()
    return row


def update(
    db: Session, name: str | None, public_url: str | None, clear_url: bool = False
) -> PlatformSettings:
    row = get(db)
    if name is not None:
        row.name = name
    if clear_url:
        row.public_url = None
    elif public_url is not None:
        row.public_url = public_url.rstrip("/")
    row.updated_at = datetime.now(UTC)
    db.commit()
    return row


def agent_url(db: Session) -> str:
    """What agents (and install commands) use to reach this API."""
    row = db.get(PlatformSettings, 1)
    return (
        row.public_url if row and row.public_url else settings.agent_api_url
    ).rstrip("/")


def webhook_base(db: Session) -> str | None:
    """A public https base for webhooks, if there is one."""
    row = db.get(PlatformSettings, 1)
    if row and row.public_url and row.public_url.startswith("https://"):
        return row.public_url.rstrip("/")
    return settings.webhook_base_url


def version() -> str:
    return __version__
