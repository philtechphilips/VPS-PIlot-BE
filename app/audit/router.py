from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict

from app.audit import service
from app.auth.dependencies import AdminUser
from app.core.database import DbSession

router = APIRouter(prefix="/api/v1", tags=["Audit"])


class AuditEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor: str
    actor_label: str
    action: str
    target_type: str | None
    target_id: str | None
    target_label: str | None
    result: str
    detail: str | None
    correlation_id: str
    ip_address: str | None
    meta: dict[str, Any]
    created_at: datetime


@router.get("/audit-logs", response_model=list[AuditEntry])
def audit_logs(
    db: DbSession,
    _: AdminUser,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before: int | None = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
):
    """Newest first. Page with ?before=<id of the last entry>."""
    return service.list_entries(db, limit, before, action)
