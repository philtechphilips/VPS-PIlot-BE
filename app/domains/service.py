"""Domains: hostnames served by each server's VPSPilot proxy (Caddy).

The control plane holds the desired state; every change re-applies the
server's whole proxy config (validated by Caddy before reload). DNS is
checked from here; certificates are read from the server by the agent.
"""

import re
import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.apps.models import Application
from app.core.security import new_id
from app.domains.models import Domain
from app.jobs import service as jobs
from app.jobs.models import Job
from app.servers.models import Server
from app.users.models import Role, User

HOST_RE = re.compile(
    r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
STATUS_EVERY = timedelta(hours=6)
_dns_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns")


class DomainError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> datetime:
    return datetime.now(UTC)


def normalise(hostname: str) -> str:
    host = hostname.strip().lower().rstrip(".")
    if host.startswith(("http://", "https://")) or "/" in host:
        raise DomainError(422, "Enter just the hostname, like shop.example.com")
    if not HOST_RE.fullmatch(host):
        raise DomainError(422, "That isn't a valid hostname")
    return host


def list_domains(db: Session, application_id: str | None = None) -> list[Domain]:
    query = select(Domain).order_by(Domain.hostname)
    if application_id:
        query = query.where(Domain.application_id == application_id)
    return list(db.scalars(query))


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def _resolve(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def check_dns(db: Session, domain: Domain) -> None:
    server = db.get(Server, domain.server_id)
    try:
        addresses = _dns_pool.submit(_resolve, domain.hostname).result(timeout=4)
    except (OSError, FutureTimeout):
        addresses = []
    server_ips = set((server.ip_addresses or []) if server else [])
    public = set((domain.meta or {}).get("public_ips") or [])
    domain.dns_addresses = addresses
    domain.dns_status = (
        "missing"
        if not addresses
        else "ok"
        if set(addresses) & (server_ips | public)
        else "elsewhere"
    )
    domain.dns_checked_at = _now()


# ---------------------------------------------------------------------------
# Desired state -> proxy.apply
# ---------------------------------------------------------------------------


def _acme_email(db: Session) -> str | None:
    owner = db.scalar(select(User).where(User.role == Role.ADMIN).order_by(User.id))
    return (
        owner.email
        if owner and "@" in owner.email and not owner.email.endswith("@example.com")
        else None
    )


def desired_sites(db: Session, server_id: str) -> list[dict[str, Any]]:
    sites = []
    for d in db.scalars(
        select(Domain).where(Domain.server_id == server_id).order_by(Domain.hostname)
    ):
        if d.redirect_to:
            sites.append(
                {"host": d.hostname, "tls": d.tls_mode, "redirect_to": d.redirect_to}
            )
            continue
        app = db.get(Application, d.application_id) if d.application_id else None
        if app is None:
            continue
        sites.append(
            {
                "host": d.hostname,
                "tls": d.tls_mode,
                "upstream": f"vp-{app.name}:{app.container_port}",
            }
        )
    return sites


def apply(
    db: Session, server_id: str, actor: str, label: str, request=None
) -> Job | None:
    """Send the server's full domain list to its proxy."""
    server = db.get(Server, server_id)
    if server is None or server.enrolled_at is None or server.revoked_at is not None:
        return None
    payload: dict[str, Any] = {"sites": desired_sites(db, server_id)}
    email = _acme_email(db)
    if email:
        payload["email"] = email
    try:
        job, _ = jobs.create(
            db, server, "proxy.apply", payload, actor, label, request=request
        )
    except jobs.JobError as error:
        raise DomainError(error.status_code, error.detail) from None
    for d in db.scalars(select(Domain).where(Domain.server_id == server_id)):
        d.apply_job_id = job.id
        if d.status != "active":
            d.status = "pending"
    db.commit()
    return job


def create(
    db: Session, data: dict[str, Any], actor: str, label: str, request=None
) -> list[Domain]:
    host = normalise(data["hostname"])
    if db.scalar(select(Domain).where(Domain.hostname == host)):
        raise DomainError(409, f"{host} is already added")
    app = db.get(Application, data["application_id"])
    if app is None:
        raise DomainError(404, "Application not found")
    created = []
    domain = Domain(
        id=new_id(),
        hostname=host,
        server_id=app.server_id,
        application_id=app.id,
        tls_mode=data.get("tls_mode") or "auto",
        status="pending",
        created_by=label[:64],
        created_at=_now(),
    )
    db.add(domain)
    created.append(domain)
    if data.get("redirect_www"):
        www = host[4:] if host.startswith("www.") else f"www.{host}"
        if not db.scalar(select(Domain).where(Domain.hostname == www)):
            # www.example.com -> example.com (or the other way round).
            created.append(
                Domain(
                    id=new_id(),
                    hostname=www,
                    server_id=app.server_id,
                    application_id=app.id,
                    redirect_to=host,
                    tls_mode=domain.tls_mode,
                    status="pending",
                    created_by=label[:64],
                    created_at=_now(),
                )
            )
            db.add(created[-1])
    db.flush()
    for d in created:
        check_dns(db, d)
    apply(db, app.server_id, actor, label, request)
    return created


def update(
    db: Session, domain: Domain, tls_mode: str, actor: str, label: str, request=None
) -> Domain:
    domain.tls_mode = tls_mode
    db.flush()
    apply(db, domain.server_id, actor, label, request)
    return domain


def remove(db: Session, domain: Domain, actor: str, label: str, request=None) -> None:
    server_id = domain.server_id
    # Redirects to it go too.
    for other in db.scalars(
        select(Domain).where(Domain.redirect_to == domain.hostname)
    ):
        db.delete(other)
    db.delete(domain)
    db.flush()
    apply(db, server_id, actor, label, request)


def check(db: Session, domain: Domain, actor: str, label: str) -> Job | None:
    """DNS now; certificate via the agent."""
    check_dns(db, domain)
    db.commit()
    return queue_status(db, domain.server_id, actor, label)


def queue_status(
    db: Session, server_id: str, actor: str = "system", label: str = "VPSPilot"
) -> Job | None:
    server = db.get(Server, server_id)
    hosts = [
        d.hostname
        for d in db.scalars(
            select(Domain).where(
                Domain.server_id == server_id, Domain.tls_mode != "off"
            )
        )
    ]
    if (
        not hosts
        or server is None
        or server.enrolled_at is None
        or server.revoked_at is not None
    ):
        return None
    try:
        job, _ = jobs.create(
            db,
            server,
            "proxy.status",
            {"hosts": hosts[:200]},
            actor,
            label,
            audited=False,
        )
    except jobs.JobError:
        return None
    return job


def refresh_due(db: Session) -> int:
    """Called by the monitoring loop: re-check certificates and DNS every
    few hours so expiry alerts have fresh data."""
    queued = 0
    cutoff = _now() - STATUS_EVERY
    servers = set()
    for d in db.scalars(select(Domain)):
        checked = d.cert_checked_at
        if (
            checked is None
            or (checked.tzinfo is None and checked.replace(tzinfo=UTC) < cutoff)
            or (checked.tzinfo and checked < cutoff)
        ):
            servers.add(d.server_id)
            check_dns(db, d)
    db.commit()
    for server_id in servers:
        if queue_status(db, server_id):
            queued += 1
    return queued


# ---------------------------------------------------------------------------
# Job outcomes
# ---------------------------------------------------------------------------


def _parse_not_after(value: str) -> datetime | None:
    # openssl prints e.g. "Jan 12 10:00:00 2027 GMT"
    try:
        return datetime.strptime(
            value.replace("  ", " "), "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=UTC)
    except ValueError:
        try:
            return parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None


def on_job_finished(db: Session, job: Job) -> None:
    if job.type == "proxy.apply":
        for d in db.scalars(select(Domain).where(Domain.apply_job_id == job.id)):
            if job.status == "succeeded":
                d.status, d.error = "active", None
            else:
                d.status = "error"
                d.error = (job.error or f"Job {job.status}")[:500]
    elif job.type == "proxy.status" and job.status == "succeeded":
        import json

        try:
            body = json.loads(jobs.job_output(job) or "{}")
        except ValueError:
            return
        by_host = {c.get("host"): c for c in body.get("certificates") or []}
        for d in db.scalars(select(Domain).where(Domain.server_id == job.server_id)):
            cert = by_host.get(d.hostname)
            if cert is None:
                continue
            d.cert_checked_at = _now()
            if cert.get("ok"):
                d.cert_issuer = (cert.get("issuer") or "")[:120] or None
                d.cert_expires_at = _parse_not_after(cert.get("not_after") or "")
                d.cert_error = None
            else:
                d.cert_error = (cert.get("error") or "No certificate")[:300]


jobs.on_finished.append(on_job_finished)
