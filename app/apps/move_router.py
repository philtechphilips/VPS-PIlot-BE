"""Moving an app to another server."""

from datetime import datetime
from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, StringConstraints

from app.apps import moves, service
from app.apps.models import Application, AppMove
from app.audit import service as audit
from app.auth.dependencies import AdminUser
from app.core.database import DbSession
from app.servers.models import Server

router = APIRouter(prefix="/api/v1/applications", tags=["Applications"])


class MoveIn(BaseModel):
    server_id: Annotated[str, StringConstraints(max_length=32)]
    include_files: bool = True


class MoveOut(BaseModel):
    id: str
    status: str
    step: str
    include_files: bool
    source_server: str | None
    target_server: str | None
    target_ips: list[str]
    databases: list[dict[str, Any]]
    error: str | None
    created_at: datetime
    finished_at: datetime | None


def _raise(error: moves.MoveError) -> NoReturn:
    raise HTTPException(status_code=error.status_code, detail=error.detail)


def _app(db, app_id: str) -> Application:
    app = service.get_app(db, app_id)
    if app is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Application not found")
    return app


def _out(db, move: AppMove) -> MoveOut:
    source = db.get(Server, move.source_server_id)
    target = db.get(Server, move.target_server_id)
    return MoveOut(
        id=move.id,
        status=move.status,
        step=move.step,
        include_files=move.include_files,
        source_server=source.name if source else None,
        target_server=target.name if target else None,
        target_ips=(target.ip_addresses or []) if target else [],
        databases=[
            {
                "from": d["source_name"],
                "to": d.get("target_name"),
                "engine": d["engine"],
                "stage": d["stage"],
            }
            for d in (move.state or {}).get("databases", [])
        ],
        error=move.error,
        created_at=move.created_at,
        finished_at=move.finished_at,
    )


def _audit(db, user, request, action: str, app: Application, detail: str) -> None:
    actor, label = audit.user_actor(user)
    audit.record(
        db,
        action=action,
        result="success",
        actor=actor,
        actor_label=label,
        target_type="application",
        target_id=app.id,
        target_label=app.name,
        detail=detail,
        request=request,
    )


@router.get("/{app_id}/move")
def move_status(app_id: str, db: DbSession, _: AdminUser):
    """What a move would copy, and the latest move if there is one."""
    app = _app(db, app_id)
    latest = moves.latest_for(db, app.id)
    return {
        "plan": moves.plan(db, app),
        "move": _out(db, latest) if latest else None,
    }


@router.post("/{app_id}/move", status_code=202)
def start_move(
    app_id: str, body: MoveIn, request: Request, db: DbSession, user: AdminUser
):
    app = _app(db, app_id)
    target = db.get(Server, body.server_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    actor, label = audit.user_actor(user)
    try:
        move = moves.start(db, app, target, body.include_files, actor, label)
    except moves.MoveError as error:
        _raise(error)
    _audit(db, user, request, "app.move", app, f"to {target.name}")
    return _out(db, move)


@router.post("/{app_id}/move/finish")
def finish_move(app_id: str, request: Request, db: DbSession, user: AdminUser):
    app = _app(db, app_id)
    move = moves.active_for(db, app.id)
    if move is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No move in progress")
    actor, label = audit.user_actor(user)
    try:
        move = moves.finish(db, move, actor, label)
    except moves.MoveError as error:
        _raise(error)
    _audit(db, user, request, "app.move_finish", app, "old copy removed")
    return _out(db, move)


@router.post("/{app_id}/move/cancel")
def cancel_move(app_id: str, request: Request, db: DbSession, user: AdminUser):
    app = _app(db, app_id)
    move = moves.active_for(db, app.id)
    if move is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No move in progress")
    try:
        move = moves.cancel(db, move)
    except moves.MoveError as error:
        _raise(error)
    _audit(db, user, request, "app.move_cancel", app, "back on the old server")
    return _out(db, move)
