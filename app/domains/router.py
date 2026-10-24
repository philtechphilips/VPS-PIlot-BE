from datetime import UTC, datetime
from typing import Annotated, Literal, NoReturn

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field, StringConstraints

from app.apps.models import Application
from app.audit import service as audit
from app.auth.dependencies import AdminUser
from app.core.database import DbSession
from app.domains import service, uptime
from app.domains.models import Domain
from app.jobs import service as jobs
from app.servers.models import Server

router = APIRouter(prefix="/api/v1/domains", tags=["Domains"])

TlsMode = Literal["auto", "internal", "off"]


def _raise(error: service.DomainError) -> NoReturn:
    raise HTTPException(status_code=error.status_code, detail=error.detail)


class DomainCreate(BaseModel):
    hostname: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=3, max_length=253)
    ]
    application_id: Annotated[str, StringConstraints(max_length=32)]
    tls_mode: TlsMode = "auto"
    redirect_www: bool = False


class DomainUpdate(BaseModel):
    tls_mode: TlsMode


class AccessIn(BaseModel):
    # Password: set user + password, or password null to remove it.
    user: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._@-]{1,64}$")] = (
        "admin"
    )
    password: Annotated[str, StringConstraints(min_length=8, max_length=72)] | None = (
        None
    )
    remove_password: bool = False
    # IP addresses or ranges allowed in; [] lets everyone in.
    allow: (
        Annotated[
            list[Annotated[str, StringConstraints(max_length=43)]], Field(max_length=50)
        ]
        | None
    ) = None


def _out(db, d: Domain) -> dict:
    app = db.get(Application, d.application_id) if d.application_id else None
    server = db.get(Server, d.server_id)
    days = None
    if d.cert_expires_at:
        expires = (
            d.cert_expires_at
            if d.cert_expires_at.tzinfo
            else d.cert_expires_at.replace(tzinfo=UTC)
        )
        days = (expires - datetime.now(UTC)).days
    return {
        "id": d.id,
        "hostname": d.hostname,
        "server_id": d.server_id,
        "server_name": server.name if server else None,
        "server_ips": (server.ip_addresses or []) if server else [],
        "application_id": d.application_id,
        "application_name": app.name if app else None,
        "redirect_to": d.redirect_to,
        "tls_mode": d.tls_mode,
        "status": d.status,
        "error": d.error,
        "dns_status": d.dns_status,
        "dns_addresses": d.dns_addresses or [],
        "dns_checked_at": d.dns_checked_at,
        "cert_issuer": d.cert_issuer,
        "cert_expires_at": d.cert_expires_at,
        "cert_days_left": days,
        "cert_error": d.cert_error,
        "cert_checked_at": d.cert_checked_at,
        "uptime": uptime.summary(db, d.id) if d.application_id else None,
        "access": {
            "user": ((d.access or {}).get("auth") or {}).get("user"),
            "password": bool((d.access or {}).get("auth")),
            "allow": (d.access or {}).get("allow") or [],
        },
        "created_at": d.created_at,
    }


def _get(db, domain_id: str) -> Domain:
    d = db.get(Domain, domain_id)
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Domain not found")
    return d


def _audit(
    db, user, request, action: str, d_host: str, detail: str | None = None
) -> None:
    actor, label = audit.user_actor(user)
    audit.record(
        db,
        action=action,
        result="accepted",
        actor=actor,
        actor_label=label,
        target_type="domain",
        target_id=d_host,
        target_label=d_host,
        detail=detail,
        request=request,
    )


@router.get("")
def list_domains(db: DbSession, _: AdminUser, application_id: str | None = None):
    jobs.reap(db)
    return [_out(db, d) for d in service.list_domains(db, application_id)]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_domain(body: DomainCreate, request: Request, db: DbSession, user: AdminUser):
    actor, label = audit.user_actor(user)
    try:
        created = service.create(db, body.model_dump(), actor, label, request)
    except service.DomainError as error:
        _raise(error)
    for d in created:
        _audit(
            db,
            user,
            request,
            "domain.add",
            d.hostname,
            f"→ {d.redirect_to}" if d.redirect_to else f"TLS {d.tls_mode}",
        )
    return [_out(db, d) for d in created]


@router.patch("/{domain_id}")
def update_domain(
    domain_id: str, body: DomainUpdate, request: Request, db: DbSession, user: AdminUser
):
    d = _get(db, domain_id)
    actor, label = audit.user_actor(user)
    try:
        service.update(db, d, body.tls_mode, actor, label, request)
    except service.DomainError as error:
        _raise(error)
    _audit(db, user, request, "domain.update", d.hostname, f"TLS {body.tls_mode}")
    return _out(db, d)


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_domain(domain_id: str, request: Request, db: DbSession, user: AdminUser):
    d = _get(db, domain_id)
    host = d.hostname
    actor, label = audit.user_actor(user)
    try:
        service.remove(db, d, actor, label, request)
    except service.DomainError as error:
        _raise(error)
    _audit(db, user, request, "domain.remove", host)


@router.put("/{domain_id}/access")
def set_access(
    domain_id: str, body: AccessIn, request: Request, db: DbSession, user: AdminUser
):
    """Password-protect a site and/or limit it to some IP addresses."""
    domain = _get(db, domain_id)
    data: dict = {"allow": body.allow}
    if body.remove_password:
        data["password"] = None
    elif body.password:
        data["user"], data["password"] = body.user, body.password
    actor, label = audit.user_actor(user)
    try:
        service.set_access(db, domain, data, actor, label, request)
    except service.DomainError as error:
        _raise(error)
    _audit(
        db,
        user,
        request,
        "domain.access",
        domain.hostname,
        f"password {'on' if (domain.access or {}).get('auth') else 'off'}, "
        f"{len((domain.access or {}).get('allow') or [])} allowed ranges",
    )
    return _out(db, domain)


@router.get("/{domain_id}/uptime")
def domain_uptime(
    domain_id: str,
    db: DbSession,
    _: AdminUser,
    range: Literal["24h", "7d", "30d"] = "24h",  # noqa: A002 - query name
):
    """Uptime checks of a domain: availability and response time."""
    domain = _get(db, domain_id)
    app = db.get(Application, domain.application_id) if domain.application_id else None
    return {
        "url": uptime.url_for(domain, app),
        **uptime.series(db, domain.id, range),
    }


@router.post("/{domain_id}/check")
def check_domain(domain_id: str, db: DbSession, user: AdminUser):
    """Re-check DNS now and ask the server for the certificate."""
    d = _get(db, domain_id)
    actor, label = audit.user_actor(user)
    job = service.check(db, d, actor, label)
    return {"domain": _out(db, d), "job_id": job.id if job else None}


@router.post("/servers/{server_id}/apply", status_code=status.HTTP_202_ACCEPTED)
def reapply(server_id: str, request: Request, db: DbSession, user: AdminUser):
    """Push the server's proxy config again (e.g. after fixing a port clash)."""
    actor, label = audit.user_actor(user)
    try:
        job = service.apply(db, server_id, actor, label, request)
    except service.DomainError as error:
        _raise(error)
    if job is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "This server has no active agent")
    return {"job_id": job.id}
