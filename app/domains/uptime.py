"""Uptime: every live domain is requested once a minute from the control plane.

The app's health path is fetched over the domain, the way a visitor would
reach it (DNS, the proxy, TLS, the app), so it catches what the container
inventory can't: a 502 from the proxy, an expired certificate, wrong DNS, an
app that hangs. Connection errors, timeouts, bad certificates and 5xx answers
count as down; 4xx answers are up (a login page is still a working site).
"""

import socket
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, delete, func, select
from sqlalchemy.orm import Session

from app.apps.models import Application
from app.domains.models import Domain, UptimeCheck

CHECK_EVERY = timedelta(seconds=55)  # the worker ticks every 30 s
TIMEOUT = 10
RETENTION = timedelta(days=30)
RANGES = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="uptime")


@dataclass
class Probe:
    ok: bool
    status: int | None
    ms: float | None
    error: str | None


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def url_for(domain: Domain, app: Application | None) -> str:
    scheme = "http" if domain.tls_mode == "off" else "https"
    path = app.health_path if app and app.health_path else "/"
    return f"{scheme}://{domain.hostname}{path}"


def probe(url: str, verify: bool = True) -> Probe:
    context = ssl.create_default_context()
    if not verify:  # Caddy's internal CA: reachable, but not publicly trusted
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(
        url, headers={"User-Agent": "VPSPilot-Uptime/1.0"}, method="GET"
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT, context=context) as resp:
            resp.read(1024)
            status = resp.status
    except urllib.error.HTTPError as error:
        status = error.code
    except urllib.error.URLError as error:
        reason = error.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            message = f"Certificate problem: {reason.verify_message or reason}"
        elif isinstance(reason, socket.gaierror):
            message = "The hostname doesn't resolve"
        elif isinstance(reason, TimeoutError):
            message = f"No answer within {TIMEOUT} s"
        elif isinstance(reason, ConnectionRefusedError):
            message = "Connection refused"
        else:
            message = str(reason)[:200]
        return Probe(False, None, None, message)
    except TimeoutError:
        return Probe(False, None, None, f"No answer within {TIMEOUT} s")
    except (OSError, ValueError) as error:
        return Probe(False, None, None, str(error)[:200])
    ms = round((time.monotonic() - started) * 1000, 1)
    if status >= 500:
        return Probe(False, status, ms, f"HTTP {status}")
    return Probe(True, status, ms, None)


def watched(db: Session) -> list[tuple[Domain, Application | None]]:
    """Live domains that serve an app (redirects follow their target)."""
    out = []
    for domain in db.scalars(
        select(Domain).where(
            Domain.status == "active", Domain.application_id.is_not(None)
        )
    ):
        out.append((domain, db.get(Application, domain.application_id)))
    return out


def check_due(db: Session, now: datetime | None = None) -> int:
    """Probe every watched domain not checked in the last minute."""
    now = now or _now()
    last = dict(
        db.execute(
            select(UptimeCheck.domain_id, func.max(UptimeCheck.ts)).group_by(
                UptimeCheck.domain_id
            )
        ).all()
    )
    due = [
        (d, app)
        for d, app in watched(db)
        if d.id not in last or now - _aware(last[d.id]) >= CHECK_EVERY
    ]
    if not due:
        return 0
    results = list(
        _pool.map(lambda i: probe(url_for(*i), i[0].tls_mode != "internal"), due)
    )
    for (domain, _), result in zip(due, results, strict=True):
        db.add(
            UptimeCheck(
                domain_id=domain.id,
                ts=now,
                ok=result.ok,
                status_code=result.status,
                ms=result.ms,
                error=result.error,
            )
        )
    db.execute(
        delete(UptimeCheck)
        .where(UptimeCheck.ts < now - RETENTION)
        .execution_options(synchronize_session=False)
    )
    db.commit()
    return len(due)


def summary(db: Session, domain_id: str, now: datetime | None = None) -> dict[str, Any]:
    """Latest result and 24-hour uptime, for the domain list."""
    now = now or _now()
    latest = db.scalar(
        select(UptimeCheck)
        .where(UptimeCheck.domain_id == domain_id)
        .order_by(UptimeCheck.ts.desc())
        .limit(1)
    )
    total, up = db.execute(
        select(func.count(), func.sum(case((UptimeCheck.ok, 1), else_=0))).where(
            UptimeCheck.domain_id == domain_id,
            UptimeCheck.ts >= now - RANGES["24h"],
        )
    ).one()
    return {
        "up": latest.ok if latest else None,
        "checked_at": latest.ts if latest else None,
        "ms": latest.ms if latest else None,
        "error": latest.error if latest else None,
        "uptime_24h": round(100 * (up or 0) / total, 2) if total else None,
    }


def series(
    db: Session, domain_id: str, range_key: str, points: int = 60
) -> dict[str, Any]:
    span = RANGES[range_key]
    now = _now()
    since = now - span
    rows = list(
        db.scalars(
            select(UptimeCheck)
            .where(UptimeCheck.domain_id == domain_id, UptimeCheck.ts >= since)
            .order_by(UptimeCheck.ts)
        )
    )
    step = span / points
    buckets: list[dict[str, Any]] = [
        {"t": since + step * i, "checks": 0, "up": 0, "ms": []} for i in range(points)
    ]
    for row in rows:
        index = min(points - 1, int((_aware(row.ts) - since) / step))
        bucket = buckets[index]
        bucket["checks"] += 1
        bucket["up"] += 1 if row.ok else 0
        if row.ms is not None:
            bucket["ms"].append(row.ms)
    out = []
    for b in buckets:
        ms = b.pop("ms")
        out.append(
            {
                "t": b["t"],
                "uptime": (
                    round(100 * b["up"] / b["checks"], 2) if b["checks"] else None
                ),
                "ms": round(sum(ms) / len(ms), 1) if ms else None,
            }
        )
    up = sum(1 for r in rows if r.ok)
    outages = [
        {"ts": r.ts, "status": r.status_code, "error": r.error}
        for r in rows
        if not r.ok
    ][-20:]
    return {
        "range": range_key,
        "uptime": round(100 * up / len(rows), 3) if rows else None,
        "checks": len(rows),
        "points": out,
        "recent_failures": outages[::-1],
    }
