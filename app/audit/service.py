"""Audit trail. Call record() for every privileged or security-relevant
action. Pass identifiers and short descriptions only, never secrets."""

from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.models import AuditLog
from app.core.security import new_id


def client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:45]
    return request.client.host if request.client else None


def record(
    db: Session,
    *,
    action: str,
    result: str,
    actor: str = "system",
    actor_label: str = "system",
    target_type: str | None = None,
    target_id: str | None = None,
    target_label: str | None = None,
    detail: str | None = None,
    request: Request | None = None,
    correlation_id: str | None = None,
    meta: dict[str, Any] | None = None,
    commit: bool = True,
) -> AuditLog:
    entry = AuditLog(
        actor=actor[:64],
        actor_label=actor_label[:255],
        action=action[:64],
        target_type=target_type,
        target_id=target_id,
        target_label=(target_label or "")[:255] or None,
        result=result,
        detail=(detail or "")[:500] or None,
        correlation_id=correlation_id or new_id(),
        ip_address=client_ip(request),
        meta=meta or {},
    )
    db.add(entry)
    if commit:
        db.commit()
    return entry


def user_actor(user) -> tuple[str, str]:
    return f"user:{user.id}", user.email


def list_entries(
    db: Session,
    limit: int = 50,
    before_id: int | None = None,
    action_prefix: str | None = None,
) -> list[AuditLog]:
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    if before_id is not None:
        query = query.where(AuditLog.id < before_id)
    if action_prefix:
        query = query.where(AuditLog.action.startswith(action_prefix))
    return list(db.scalars(query))
