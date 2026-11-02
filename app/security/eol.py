"""When runtimes and distros stop getting security fixes, from
endoflife.date (refreshed once a day)."""

from __future__ import annotations

import logging
import re
from datetime import UTC, date, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.security.models import SecurityCache

logger = logging.getLogger(__name__)

API = "https://endoflife.date/api"
REFRESH = timedelta(days=1)
# Our name -> endoflife.date's product, and how people call it.
PRODUCTS = {
    "nodejs": ("nodejs", "Node.js"),
    "python": ("python", "Python"),
    "debian": ("debian", "Debian"),
    "ubuntu": ("ubuntu", "Ubuntu"),
    "alpine": ("alpine-linux", "Alpine"),
}


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def runtimes_from_plan(plan: str | None) -> list[tuple[str, str]]:
    """[(product, cycle)] from a build plan such as "Next.js · pnpm 10 · Node 22"."""
    out = []
    if not plan:
        return out
    if m := re.search(r"\bNode (\d{1,3})\b", plan):
        out.append(("nodejs", m.group(1)))
    if m := re.search(r"\bPython (\d\.\d{1,2})\b", plan):
        out.append(("python", m.group(1)))
    return out


def os_cycle(os_id: str | None, version: str | None) -> tuple[str, str] | None:
    if not os_id or not version:
        return None
    if os_id == "debian" and re.fullmatch(r"\d{1,3}", version):
        return "debian", version
    if os_id == "ubuntu" and re.fullmatch(r"\d{2}\.\d{2}", version):
        return "ubuntu", version
    if os_id == "alpine" and re.fullmatch(r"\d+\.\d+(\.\d+)?", version):
        return "alpine", ".".join(version.split(".")[:2])
    return None


def _table(db: Session, product: str) -> list[dict[str, Any]]:
    key = f"eol:{product}"
    row = db.get(SecurityCache, key)
    if row is not None and _now() - _aware(row.fetched_at) < REFRESH:
        return row.data.get("cycles") or []
    try:
        response = httpx.get(
            f"{API}/{PRODUCTS[product][0]}.json",
            timeout=20,
            headers={"User-Agent": "VPSPilot"},
        )
        response.raise_for_status()
        cycles = [
            {"cycle": str(c.get("cycle")), "eol": c.get("eol")}
            for c in response.json()
            if isinstance(c, dict)
        ]
    except (httpx.HTTPError, ValueError) as error:
        logger.warning("end-of-life data for %s not fetched: %s", product, error)
        return (row.data.get("cycles") or []) if row is not None else []
    if row is None:
        db.add(SecurityCache(key=key, data={"cycles": cycles}, fetched_at=_now()))
    else:
        row.data, row.fetched_at = {"cycles": cycles}, _now()
    db.flush()
    return cycles


def end_of_life(db: Session, product: str, cycle: str) -> date | None:
    """The date `cycle` stops getting security fixes (None: unknown/never)."""
    for row in _table(db, product):
        if row["cycle"] == cycle and isinstance(row["eol"], str):
            try:
                return date.fromisoformat(row["eol"])
            except ValueError:
                return None
    return None


def label(product: str, cycle: str) -> str:
    return f"{PRODUCTS[product][1]} {cycle}"
