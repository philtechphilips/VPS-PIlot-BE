from typing import Annotated

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, StringConstraints
from sqlalchemy import text

from app.agent_version import AGENT_VERSION
from app.audit import service as audit
from app.auth.dependencies import AdminUser
from app.core.database import DbSession
from app.core.security import verify_password
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
    weekly_report: bool | None = None
    report_timezone: (
        Annotated[
            str,
            StringConstraints(pattern=r"^[A-Za-z_]+(/[A-Za-z0-9_+-]+){0,2}$"),
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
        "recovery_kit_at": row.recovery_kit_at,
        "weekly_report": row.weekly_report,
        "report_timezone": row.report_timezone or "UTC",
    }


@router.get("")
def get_platform(db: DbSession, _: AdminUser):
    return _out(db, service.get(db))


@router.put("")
def put_platform(body: PlatformIn, request: Request, db: DbSession, user: AdminUser):
    from app.core import cron

    try:
        row = service.update(
            db,
            body.name,
            body.public_url or None,
            clear_url=body.public_url == "",
            weekly_report=body.weekly_report,
            report_timezone=body.report_timezone,
        )
    except cron.CronError as error:
        raise HTTPException(422, str(error)) from None
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


@router.post("/weekly-report", status_code=202)
def send_weekly_report(db: DbSession, _: AdminUser):
    """Send this week's report now (to check what it looks like)."""
    from app.notifications import weekly

    report = weekly.send(db)
    return {"title": report["title"], "text": weekly.as_text(report)}


class RecoveryKitIn(BaseModel):
    password: Annotated[str, StringConstraints(min_length=1, max_length=128)]


@router.post("/recovery-kit", response_class=PlainTextResponse)
def recovery_kit(body: RecoveryKitIn, request: Request, db: DbSession, user: AdminUser):
    """The keys that decrypt stored secrets and backups, as a text file.
    Asks for the password again; every download is audited."""
    valid, _ = verify_password(body.password, user.password)
    actor, label = audit.user_actor(user)
    if not valid:
        audit.record(
            db, action="platform.recovery_kit", result="denied", actor=actor,
            actor_label=label, target_type="platform", target_id="1",
            detail="wrong password", request=request,
        )  # fmt: skip
        raise HTTPException(status.HTTP_403_FORBIDDEN, "That password isn't right")
    kit = service.recovery_kit(db, label)
    audit.record(
        db, action="platform.recovery_kit", result="success", actor=actor,
        actor_label=label, target_type="platform", target_id="1", request=request,
    )  # fmt: skip
    return PlainTextResponse(
        kit,
        headers={
            "Content-Disposition": 'attachment; filename="vpspilot-recovery-kit.txt"',
            "Cache-Control": "no-store",
        },
    )
