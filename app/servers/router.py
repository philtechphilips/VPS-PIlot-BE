from typing import Annotated, NoReturn

from fastapi import APIRouter, HTTPException, Query, status

from app.auth.dependencies import AdminUser
from app.core.database import DbSession
from app.servers import service
from app.servers.models import MetricSample, Server
from app.servers.schemas import (
    EnrollmentCreate,
    EnrollmentResponse,
    MetricPoint,
    MetricsSnapshot,
    ServerDetail,
    ServerSummary,
)

router = APIRouter(prefix="/api/v1/servers", tags=["Servers"])


def _raise(error: service.ServerError) -> NoReturn:
    raise HTTPException(status_code=error.status_code, detail=error.detail)


def _summary_fields(server: Server, latest: MetricSample | None) -> dict:
    return {
        "id": server.id,
        "name": server.name,
        "tags": server.tags or [],
        "status": service.status_of(server),
        "is_control_plane": server.is_control_plane,
        "hostname": server.hostname,
        "os_name": server.os_name,
        "os_version": server.os_version,
        "arch": server.arch,
        "cpu_count": server.cpu_count,
        "memory_total": server.memory_total,
        "disk_total": server.disk_total,
        "ip_addresses": server.ip_addresses or [],
        "agent_version": server.agent_version,
        "last_heartbeat_at": server.last_heartbeat_at,
        "enrolled_at": server.enrolled_at,
        "created_at": server.created_at,
        "latest": MetricsSnapshot.model_validate(latest) if latest else None,
    }


def to_summary(server: Server, latest: MetricSample | None = None) -> ServerSummary:
    return ServerSummary(**_summary_fields(server, latest))


def to_detail(server: Server, latest: MetricSample | None) -> ServerDetail:
    return ServerDetail(
        **_summary_fields(server, latest),
        kernel=server.kernel,
        uptime_seconds=server.uptime_seconds,
        capabilities=server.capabilities or {},
        inventory=server.inventory or {},
        inventory_at=server.inventory_at,
        agent_token_rotated_at=server.agent_token_rotated_at,
        revoked_at=server.revoked_at,
    )


def _get(db, server_id: str) -> Server:
    server = service.get_server(db, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    return server


@router.get("", response_model=list[ServerSummary])
def list_servers(db: DbSession, _: AdminUser):
    servers = service.list_servers(db)
    latest = service.latest_samples(db, [s.id for s in servers])
    return [to_summary(s, latest.get(s.id)) for s in servers]


@router.post(
    "/enrollments",
    response_model=EnrollmentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_enrollment(body: EnrollmentCreate, db: DbSession, _: AdminUser):
    """Register a server and issue a single-use install token."""
    try:
        server, token, expires_at = service.create_enrollment(db, body.name, body.tags)
    except service.ServerError as error:
        _raise(error)
    return EnrollmentResponse(
        server=to_summary(server),
        token=token,
        install_command=service.install_command(token),
        expires_at=expires_at,
    )


@router.get("/{server_id}", response_model=ServerDetail)
def get_server(server_id: str, db: DbSession, _: AdminUser):
    server = _get(db, server_id)
    return to_detail(server, service.latest_sample(db, server.id))


@router.get("/{server_id}/metrics", response_model=list[MetricPoint])
def get_metrics(
    server_id: str,
    db: DbSession,
    _: AdminUser,
    range: Annotated[str, Query(pattern="^(1h|24h|7d)$")] = "1h",  # noqa: A002
):
    _get(db, server_id)
    return service.metric_series(db, server_id, range)


@router.post("/{server_id}/enrollments", response_model=EnrollmentResponse)
def reissue_enrollment(server_id: str, db: DbSession, _: AdminUser):
    """New token for a server that hasn't enrolled yet (e.g. the old one expired)."""
    server = _get(db, server_id)
    try:
        token, expires_at = service.reissue_enrollment(db, server)
    except service.ServerError as error:
        _raise(error)
    return EnrollmentResponse(
        server=to_summary(server),
        token=token,
        install_command=service.install_command(token),
        expires_at=expires_at,
    )


@router.post("/{server_id}/revoke", response_model=ServerDetail)
def revoke_server(server_id: str, db: DbSession, _: AdminUser):
    server = service.revoke(db, _get(db, server_id))
    return to_detail(server, service.latest_sample(db, server.id))


@router.delete("/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_server(server_id: str, db: DbSession, _: AdminUser):
    try:
        service.remove(db, _get(db, server_id))
    except service.ServerError as error:
        _raise(error)
