from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.audit import service as audit
from app.auth.dependencies import AdminUser, CurrentUser
from app.core.database import DbSession
from app.notifications import channels, service
from app.notifications.models import AlertChannel

router = APIRouter(prefix="/api/v1/notifications", tags=["Notifications"])


class NotificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: str
    level: str
    title: str
    body: str | None
    link: str | None
    created_at: datetime
    read_at: datetime | None


class Inbox(BaseModel):
    items: list[NotificationOut]
    unread: int


class ReadRequest(BaseModel):
    # Omit to mark everything read.
    ids: Annotated[list[str], Field(max_length=200)] | None = None


class SettingsOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email: str
    email_deploy_success: bool
    email_deploy_failure: bool
    email_alerts: bool


class SettingsIn(BaseModel):
    email_deploy_success: bool | None = None
    email_deploy_failure: bool | None = None
    email_alerts: bool | None = None


@router.get("", response_model=Inbox)
def inbox(
    db: DbSession, user: CurrentUser, limit: Annotated[int, Query(ge=1, le=100)] = 30
):
    items, unread = service.list_for(db, user.id, limit)
    return Inbox(items=items, unread=unread)


@router.post("/read", status_code=status.HTTP_204_NO_CONTENT)
def read(body: ReadRequest, db: DbSession, user: CurrentUser):
    service.mark_read(db, user.id, body.ids)


def _settings_out(user, prefs) -> SettingsOut:
    return SettingsOut(
        email=user.email,
        email_deploy_success=prefs.email_deploy_success,
        email_deploy_failure=prefs.email_deploy_failure,
        email_alerts=prefs.email_alerts,
    )


@router.get("/settings", response_model=SettingsOut)
def get_settings(db: DbSession, user: CurrentUser):
    prefs = service.get_settings(db, user.id)
    db.commit()
    return _settings_out(user, prefs)


@router.put("/settings", response_model=SettingsOut)
def put_settings(body: SettingsIn, db: DbSession, user: CurrentUser):
    prefs = service.update_settings(db, user.id, body.model_dump(exclude_unset=True))
    return _settings_out(user, prefs)


# ---------------------------------------------------------------------------
# Alert channels (shared; admins only)
# ---------------------------------------------------------------------------

Event = Literal[
    "alert.firing", "alert.resolved", "deployment.failed", "deployment.succeeded"
]


class ChannelConfig(BaseModel):
    # webhook / slack
    url: Annotated[str, StringConstraints(max_length=1000)] | None = None
    # telegram
    bot_token: Annotated[str, StringConstraints(max_length=100)] | None = None
    chat_id: Annotated[str, StringConstraints(max_length=40)] | None = None


class ChannelIn(BaseModel):
    kind: Literal["webhook", "slack", "telegram"]
    name: Annotated[str, StringConstraints(strip_whitespace=True, max_length=60)] = ""
    config: ChannelConfig
    events: Annotated[list[Event], Field(max_length=4)] | None = None


class ChannelUpdate(BaseModel):
    name: (
        Annotated[str, StringConstraints(strip_whitespace=True, max_length=60)] | None
    ) = None
    # Omit to keep the stored destination (it's never sent back).
    config: ChannelConfig | None = None
    events: Annotated[list[Event], Field(max_length=4)] | None = None
    enabled: bool | None = None


class ChannelOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: str
    name: str
    target_label: str
    events: list[str]
    enabled: bool
    created_by: str
    created_at: datetime
    last_sent_at: datetime | None
    last_error: str | None


def _channel(db, channel_id: str) -> AlertChannel:
    channel = db.get(AlertChannel, channel_id)
    if channel is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Channel not found")
    return channel


def _channel_audit(db, user, request, action: str, channel: AlertChannel) -> None:
    actor, label = audit.user_actor(user)
    audit.record(
        db,
        action=action,
        result="success",
        actor=actor,
        actor_label=label,
        target_type="alert_channel",
        target_id=channel.id,
        target_label=f"{channel.kind}: {channel.name}",
        request=request,
    )


@router.get("/channels", response_model=list[ChannelOut])
def list_channels(db: DbSession, _: AdminUser):
    return channels.list_channels(db)


@router.post("/channels", status_code=status.HTTP_201_CREATED)
def create_channel(body: ChannelIn, request: Request, db: DbSession, user: AdminUser):
    """Webhooks get a signing secret, returned once: verify the
    X-VPSPilot-Signature header (HMAC-SHA256 of the body) with it."""
    _, label = audit.user_actor(user)
    try:
        channel, secret = channels.create(
            db, body.kind, body.name, body.config.model_dump(), body.events, label
        )
    except channels.ChannelError as error:
        raise HTTPException(error.status_code, error.detail) from None
    _channel_audit(db, user, request, "alert_channel.create", channel)
    return {"channel": ChannelOut.model_validate(channel), "secret": secret}


@router.patch("/channels/{channel_id}", response_model=ChannelOut)
def update_channel(
    channel_id: str,
    body: ChannelUpdate,
    request: Request,
    db: DbSession,
    user: AdminUser,
):
    channel = _channel(db, channel_id)
    data = body.model_dump(exclude_unset=True)
    if body.config is not None:
        data["config"] = body.config.model_dump()
    try:
        channels.update(db, channel, data)
    except channels.ChannelError as error:
        raise HTTPException(error.status_code, error.detail) from None
    _channel_audit(db, user, request, "alert_channel.update", channel)
    return channel


@router.delete("/channels/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_channel(channel_id: str, request: Request, db: DbSession, user: AdminUser):
    channel = _channel(db, channel_id)
    _channel_audit(db, user, request, "alert_channel.delete", channel)
    db.delete(channel)
    db.commit()


@router.post("/channels/{channel_id}/test", response_model=ChannelOut)
def test_channel(channel_id: str, db: DbSession, _: AdminUser):
    """Send a test message now and report what happened."""
    channel = _channel(db, channel_id)
    try:
        channels.test(db, channel)
    except channels.ChannelError as error:
        raise HTTPException(error.status_code, error.detail) from None
    return channel
