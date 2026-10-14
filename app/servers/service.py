"""Server inventory, agent enrollment, heartbeats and metrics."""

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core import crud
from app.core.config import settings
from app.core.security import generate_token, hash_token, new_id
from app.servers.models import EnrollmentToken, MetricSample, Server

NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ENROLLMENT_PREFIX = "ept_"
AGENT_TOKEN_PREFIX = "agt_"


class ServerError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def status_of(server: Server, now: datetime | None = None) -> str:
    """pending | online | offline | revoked, derived from timestamps."""
    if server.revoked_at is not None:
        return "revoked"
    if server.enrolled_at is None:
        return "pending"
    if server.last_heartbeat_at is None:
        return "offline"
    age = ((now or _now()) - _aware(server.last_heartbeat_at)).total_seconds()
    return "online" if age <= settings.agent_offline_after_seconds else "offline"


# ---------------------------------------------------------------------------
# Owner actions
# ---------------------------------------------------------------------------


def list_servers(db: Session) -> list[Server]:
    return list(db.scalars(select(Server).order_by(Server.created_at)))


def get_server(db: Session, server_id: str) -> Server | None:
    return db.get(Server, server_id)


def _issue_enrollment_token(db: Session, server: Server) -> tuple[str, datetime]:
    """Replace any unused token for this server with a fresh one."""
    db.execute(
        delete(EnrollmentToken).where(
            EnrollmentToken.server_id == server.id, EnrollmentToken.used_at.is_(None)
        )
    )
    raw, _ = generate_token()
    token = ENROLLMENT_PREFIX + raw
    expires_at = _now() + timedelta(minutes=settings.enrollment_token_expire_minutes)
    db.add(
        EnrollmentToken(
            server_id=server.id, token_hash=hash_token(token), expires_at=expires_at
        )
    )
    db.commit()
    return token, expires_at


def create_enrollment(
    db: Session, name: str, tags: list[str]
) -> tuple[Server, str, datetime]:
    """Register a pending server and return (server, token, expires_at)."""
    name = name.strip().lower()
    if not NAME_RE.match(name):
        raise ServerError(
            422,
            "Use lowercase letters, numbers and dashes (e.g. web-prod-01), "
            "up to 63 characters.",
        )
    if db.scalar(select(Server).where(Server.name == name)):
        raise ServerError(409, f"A server named {name} already exists")
    server = crud.create(
        db,
        Server,
        {
            "id": new_id(),
            "name": name,
            "tags": sorted({t.strip().lower() for t in tags if t.strip()})[:10],
            "ip_addresses": [],
            "capabilities": {},
            "inventory": {},
        },
    )
    token, expires_at = _issue_enrollment_token(db, server)
    return server, token, expires_at


def reissue_enrollment(db: Session, server: Server) -> tuple[str, datetime]:
    if server.enrolled_at is not None:
        raise ServerError(409, "This server is already enrolled")
    return _issue_enrollment_token(db, server)


def revoke(db: Session, server: Server) -> Server:
    """Invalidate the agent's credential immediately. The host keeps running."""
    if server.revoked_at is None:
        server.revoked_at = _now()
        server.agent_token_hash = None
        db.execute(
            delete(EnrollmentToken).where(EnrollmentToken.server_id == server.id)
        )
        db.commit()
        db.refresh(server)
    return server


def remove(db: Session, server: Server) -> None:
    """Delete a server record. Only allowed once it can't talk to us."""
    if status_of(server) not in ("pending", "revoked"):
        raise ServerError(409, "Revoke the agent before removing this server")
    db.delete(server)
    db.commit()


def install_command(token: str, db: Session | None = None) -> str:
    from app.platform import service as platform

    base = (
        platform.agent_url(db) if db is not None else settings.agent_api_url.rstrip("/")
    )
    return f"curl -fsSL {base}/agent/install.sh | sudo bash -s -- --token {token}"


# ---------------------------------------------------------------------------
# Agent protocol
# ---------------------------------------------------------------------------


def enroll(db: Session, token: str, facts: dict[str, Any]) -> tuple[Server, str]:
    """Redeem a single-use enrollment token. Returns (server, agent_token)."""
    row = db.scalar(
        select(EnrollmentToken).where(EnrollmentToken.token_hash == hash_token(token))
    )
    if row is None or row.used_at is not None:
        raise ServerError(401, "Enrollment token is invalid or already used")
    if _aware(row.expires_at) <= _now():
        raise ServerError(401, "Enrollment token has expired; create a new one")
    server = db.get(Server, row.server_id)
    if server is None or server.revoked_at is not None:
        raise ServerError(401, "This server can no longer be enrolled")

    raw, _ = generate_token()
    agent_token = AGENT_TOKEN_PREFIX + raw
    now = _now()
    row.used_at = now
    server.agent_token_hash = hash_token(agent_token)
    server.agent_token_rotated_at = now
    server.enrolled_at = now
    server.last_heartbeat_at = now
    apply_facts(server, facts)
    db.commit()
    db.refresh(server)
    return server, agent_token


def authenticate_agent(db: Session, agent_token: str) -> Server | None:
    server = db.scalar(
        select(Server).where(Server.agent_token_hash == hash_token(agent_token))
    )
    if server is None or server.revoked_at is not None:
        return None
    return server


def apply_facts(server: Server, facts: dict[str, Any]) -> None:
    """Copy host facts reported by the agent onto the server row."""
    for key in (
        "hostname",
        "os_name",
        "os_version",
        "kernel",
        "arch",
        "cpu_count",
        "memory_total",
        "disk_total",
        "agent_version",
        "uptime_seconds",
    ):
        if facts.get(key) is not None:
            setattr(server, key, facts[key])
    if facts.get("ip_addresses") is not None:
        server.ip_addresses = list(facts["ip_addresses"])[:16]
    if facts.get("capabilities") is not None:
        server.capabilities = dict(facts["capabilities"])


def heartbeat(db: Session, server: Server, facts: dict[str, Any]) -> None:
    server.last_heartbeat_at = _now()
    apply_facts(server, facts)
    db.commit()


def store_inventory(db: Session, server: Server, inventory: dict[str, Any]) -> None:
    server.inventory = inventory
    names = {str(c.get("name")) for c in inventory.get("containers") or []}
    # The host running VPSPilot itself (deploy/compose.yaml) gets a badge and
    # extra care in the UI.
    server.is_control_plane = "vpspilot-api" in names
    server.inventory_at = _now()
    db.commit()


def store_metrics(db: Session, server: Server, samples: list[dict[str, Any]]) -> int:
    """Insert samples (bounded by the schema) and prune expired history."""
    rows = [MetricSample(server_id=server.id, **sample) for sample in samples]
    db.add_all(rows)
    cutoff = _now() - timedelta(days=settings.metrics_retention_days)
    db.execute(
        delete(MetricSample).where(
            MetricSample.server_id == server.id, MetricSample.ts < cutoff
        )
    )
    db.commit()
    return len(rows)


# ---------------------------------------------------------------------------
# Metrics reads
# ---------------------------------------------------------------------------

RANGES = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7)}


def latest_sample(db: Session, server_id: str) -> MetricSample | None:
    return db.scalar(
        select(MetricSample)
        .where(MetricSample.server_id == server_id)
        .order_by(MetricSample.ts.desc())
        .limit(1)
    )


def latest_samples(db: Session, server_ids: list[str]) -> dict[str, MetricSample]:
    if not server_ids:
        return {}
    newest = (
        select(MetricSample.server_id, func.max(MetricSample.ts).label("ts"))
        .where(MetricSample.server_id.in_(server_ids))
        .group_by(MetricSample.server_id)
        .subquery()
    )

    rows = db.scalars(
        select(MetricSample).join(
            newest,
            (MetricSample.server_id == newest.c.server_id)
            & (MetricSample.ts == newest.c.ts),
        )
    )
    return {row.server_id: row for row in rows}


def metric_series(
    db: Session, server_id: str, range_key: str, points: int = 60
) -> list[dict[str, Any]]:
    """Downsample samples in the range into at most `points` buckets."""
    span = RANGES[range_key]
    since = _now() - span
    samples = list(
        db.scalars(
            select(MetricSample)
            .where(MetricSample.server_id == server_id, MetricSample.ts >= since)
            .order_by(MetricSample.ts)
        )
    )
    if not samples:
        return []
    bucket = span / points
    out: list[dict[str, Any]] = []
    current: list[MetricSample] = []
    current_start = None
    fields = (
        "cpu_percent",
        "memory_percent",
        "swap_percent",
        "disk_percent",
        "load_1",
        "net_rx_bps",
        "net_tx_bps",
    )

    def flush() -> None:
        if not current:
            return
        point = {"ts": _aware(current[-1].ts).isoformat()}
        for f in fields:
            point[f] = round(sum(getattr(s, f) for s in current) / len(current), 2)
        out.append(point)

    for sample in samples:
        ts = _aware(sample.ts)
        index = int((ts - since) / bucket)
        if current_start is None or index != current_start:
            flush()
            current = []
            current_start = index
        current.append(sample)
    flush()
    return out
