from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app.auth.dependencies import CurrentUser
from app.core.database import DbSession
from app.notifications import service

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


class SettingsIn(BaseModel):
    email_deploy_success: bool | None = None
    email_deploy_failure: bool | None = None


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
