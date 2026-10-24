"""Public status pages built from uptime checks.

What's public is only what the page shows: each component's label, whether
it's up, its daily uptime for 30 days and recent outages. No hostnames
unless used as labels, no servers, no addresses.
"""

import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.core.security import new_id
from app.domains.models import Domain, StatusPage, UptimeCheck

SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")
DAYS = 30
CACHE_SECONDS = 60
_cache: dict[str, tuple[float, dict[str, Any]]] = {}


class StatusPageError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _components(db: Session, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for item in items[:30]:
        domain = db.get(Domain, item["domain_id"])
        if domain is None:
            raise StatusPageError(404, "One of the domains doesn't exist")
        label = (item.get("label") or domain.hostname).strip()[:60]
        out.append({"domain_id": domain.id, "label": label})
    return out


def save(
    db: Session, page: StatusPage | None, data: dict[str, Any], label: str
) -> StatusPage:
    slug = data.get("slug") or (page.slug if page else "")
    if not SLUG_RE.fullmatch(slug):
        raise StatusPageError(
            422, "The address uses lowercase letters, digits and dashes"
        )
    clash = db.scalar(select(StatusPage).where(StatusPage.slug == slug))
    if clash is not None and (page is None or clash.id != page.id):
        raise StatusPageError(409, "That address is taken")
    if page is None:
        page = StatusPage(
            id=new_id(), slug=slug, title="", components=[], created_by=label[:64]
        )
        db.add(page)
    page.slug = slug
    if data.get("title") is not None:
        page.title = data["title"].strip()[:80]
    if "description" in data:
        page.description = (data["description"] or "").strip()[:300] or None
    if data.get("components") is not None:
        page.components = _components(db, data["components"])
    page.title = page.title or "Status"
    db.commit()
    _cache.pop(slug, None)
    return page


def _day(column):
    return func.date(column)


def public(db: Session, slug: str) -> dict[str, Any] | None:
    hit = _cache.get(slug)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    page = db.scalar(select(StatusPage).where(StatusPage.slug == slug))
    if page is None:
        return None
    now = datetime.now(UTC)
    since = (now - timedelta(days=DAYS - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    ids = [c["domain_id"] for c in page.components]
    daily: dict[tuple[str, str], tuple[int, int]] = {}
    if ids:
        for domain_id, day, total, up in db.execute(
            select(
                UptimeCheck.domain_id,
                _day(UptimeCheck.ts),
                func.count(),
                func.sum(case((UptimeCheck.ok, 1), else_=0)),
            )
            .where(UptimeCheck.domain_id.in_(ids), UptimeCheck.ts >= since)
            .group_by(UptimeCheck.domain_id, _day(UptimeCheck.ts))
        ):
            daily[(domain_id, str(day)[:10])] = (int(total), int(up or 0))
    days = [(since + timedelta(days=i)).date().isoformat() for i in range(DAYS)]
    components = []
    for item in page.components:
        latest = db.scalar(
            select(UptimeCheck)
            .where(UptimeCheck.domain_id == item["domain_id"])
            .order_by(UptimeCheck.ts.desc())
            .limit(1)
        )
        fresh = latest is not None and now - (
            latest.ts if latest.ts.tzinfo else latest.ts.replace(tzinfo=UTC)
        ) < timedelta(minutes=10)
        bars = []
        total_all = up_all = 0
        for day in days:
            total, up = daily.get((item["domain_id"], day), (0, 0))
            total_all, up_all = total_all + total, up_all + up
            bars.append(
                {"day": day, "uptime": round(100 * up / total, 2) if total else None}
            )
        components.append(
            {
                "label": item["label"],
                "status": ("up" if latest.ok else "down") if fresh else "unknown",
                "uptime": round(100 * up_all / total_all, 3) if total_all else None,
                "days": bars,
            }
        )
    from app.monitoring.models import Alert, AlertRule

    labels = {c["domain_id"]: c["label"] for c in page.components}
    incidents = []
    if ids:
        for alert in db.scalars(
            select(Alert)
            .join(AlertRule, AlertRule.id == Alert.rule_id)
            .where(
                AlertRule.kind == "site_down",
                Alert.target_id.in_(ids),
                Alert.state != "pending",
                Alert.started_at >= now - timedelta(days=14),
            )
            .order_by(Alert.started_at.desc())
            .limit(20)
        ):
            incidents.append(
                {
                    "component": labels.get(alert.target_id),
                    "started_at": alert.fired_at or alert.started_at,
                    "resolved_at": alert.resolved_at,
                }
            )
    statuses = [c["status"] for c in components]
    overall = (
        "down"
        if statuses and all(s == "down" for s in statuses)
        else "degraded"
        if "down" in statuses
        else "up"
    )
    body = {
        "title": page.title,
        "description": page.description,
        "overall": overall,
        "components": components,
        "incidents": incidents,
        "updated_at": now,
    }
    _cache[slug] = (time.monotonic(), body)
    return body
