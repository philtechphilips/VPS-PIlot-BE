from typing import Annotated

from fastapi import APIRouter, Request
from pydantic import BaseModel, StringConstraints
from sqlalchemy import text

from app.agent_version import AGENT_VERSION
from app.audit import service as audit
from app.auth.dependencies import AdminUser
from app.core.database import DbSession
from app.platform import service

router = APIRouter(prefix="/api/v1/platform", tags=["Platform"])


class PlatformIn(BaseModel):
    name: (
        Annotated[
            str, StringConstraints(strip_whitespace=True, min_length=1, max_length=32)
        ]
        | None
    ) = None
    # Empty string clears it (fall back to the configured AGENT_API_URL).
    public_url: (
        Annotated[
            str,
            StringConstraints(
                strip_whitespace=True,
                pattern=r"^(|https?://[A-Za-z0-9.-]+(:\d{1,5})?/?)$",
            ),
        ]
        | None
    ) = None


def _schema(db) -> str | None:
    try:
        return db.execute(text("SELECT version_num FROM alembic_version")).scalar()
    except Exception:  # noqa: BLE001 - e.g. tests create tables directly
        db.rollback()
        return None


def _out(db, row) -> dict:
    return {
        "name": row.name,
        "public_url": row.public_url,
        "agent_url": service.agent_url(db),
        "webhook_url": (service.webhook_base(db) or "")
        and f"{service.webhook_base(db)}/api/v1/github/webhook",
        "version": service.version(),
        "agent_version": AGENT_VERSION,
        "schema": _schema(db),
        "updated_at": row.updated_at,
    }


@router.get("")
def get_platform(db: DbSession, _: AdminUser):
    return _out(db, service.get(db))


@router.put("")
def put_platform(body: PlatformIn, request: Request, db: DbSession, user: AdminUser):
    row = service.update(
        db, body.name, body.public_url or None, clear_url=body.public_url == ""
    )
    actor, label = audit.user_actor(user)
    audit.record(
        db,
        action="platform.update",
        result="success",
        actor=actor,
        actor_label=label,
        target_type="platform",
        target_id="1",
        target_label=row.name,
        detail=f"public URL {row.public_url or 'unset'}",
        request=request,
    )
    return _out(db, row)
