"""Known vulnerabilities from OSV.dev (https://osv.dev), the open database
behind GitHub's Dependabot alerts, Go's and PyPI's advisories and the
Debian, Ubuntu and Alpine security trackers.

Packages go in batches of up to 1000 (name, version, ecosystem); advisory
details are fetched once and cached until OSV reports a change.
"""

from __future__ import annotations

import logging
import math
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.security.models import SecurityCache

logger = logging.getLogger(__name__)

API = "https://api.osv.dev/v1"
BATCH = 1000
TIMEOUT = 30
WORKERS = 8
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
GHSA = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "LOW": "low"}


class OsvError(Exception):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


# ---------------------------------------------------------------------------
# Versions and severity
# ---------------------------------------------------------------------------


def version_key(version: str) -> tuple:
    """A rough ordering that holds for semver, PEP 440 and Debian/Alpine
    versions: numbers compare as numbers; '~' (Debian) and letters
    (pre-releases: rc1, -beta) sort before the end of a version. Only used to
    pick which fix to show."""
    rest, epoch = version.lstrip("v"), 0
    head, sep, tail = rest.partition(":")
    if sep and head.isdigit():
        rest, epoch = tail, int(head)
    parts: list[tuple[int, int | str]] = [(1, epoch)]
    for token in re.findall(r"\d+|~|[A-Za-z]+", rest):
        if token == "~":
            parts.append((-2, 0))
        elif token.isdigit():
            parts.append((1, int(token)))
        else:
            parts.append((-1, token.lower()))
    parts.append((0, 0))  # the end: below more numbers, above '~' and letters
    return tuple(parts)


def fixed_version(
    advisory: dict[str, Any], ecosystem: str, name: str, installed: str
) -> str | None:
    """The nearest release above `installed` that fixes this advisory."""
    have = version_key(installed)
    candidates = []
    for affected in advisory.get("affected") or []:
        package = affected.get("package") or {}
        if (
            package.get("ecosystem") != ecosystem
            or package.get("name", "").lower() != name.lower()
        ):
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                fix = event.get("fixed")
                if fix and version_key(fix) > have:
                    candidates.append(fix)
    return min(candidates, key=version_key) if candidates else None


CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(value: float) -> float:
    return math.ceil(value * 10 - 1e-9) / 10


def cvss3_score(vector: str) -> float | None:
    """Base score of a CVSS 3.x vector (FIRST's specification)."""
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope_changed = metrics["S"] == "C"
        pr = {
            "N": 0.85,
            "L": 0.68 if scope_changed else 0.62,
            "H": 0.5 if scope_changed else 0.27,
        }[metrics["PR"]]
        w = {k: CVSS3_WEIGHTS[k][metrics[k]] for k in CVSS3_WEIGHTS}
    except (KeyError, ValueError):
        return None
    iss = 1 - (1 - w["C"]) * (1 - w["I"]) * (1 - w["A"])
    impact = (
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        if scope_changed
        else 6.42 * iss
    )
    exploitability = 8.22 * w["AV"] * w["AC"] * pr * w["UI"]
    if impact <= 0:
        return 0.0
    total = (
        1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    )
    return _roundup(min(total, 10))


def _from_score(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low" if score > 0 else "unknown"


def severity(advisory: dict[str, Any]) -> str:
    rated = str((advisory.get("database_specific") or {}).get("severity") or "").upper()
    if rated in GHSA:
        return GHSA[rated]
    for entry in advisory.get("severity") or []:
        if entry.get("type") == "CVSS_V3":
            score = cvss3_score(str(entry.get("score") or ""))
            if score is not None:
                return _from_score(score)
    return "unknown"


# ---------------------------------------------------------------------------
# The API
# ---------------------------------------------------------------------------


def _client() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, headers={"User-Agent": "VPSPilot"})


def query(packages: list[tuple[str, str, str]]) -> list[list[dict[str, Any]]]:
    """For each (ecosystem, name, version): [{"id", "modified"}] of the
    advisories that affect it."""
    results: list[list[dict[str, Any]]] = []
    with _client() as client:
        for start in range(0, len(packages), BATCH):
            chunk = packages[start : start + BATCH]
            body = {
                "queries": [
                    {"package": {"ecosystem": eco, "name": name}, "version": version}
                    for eco, name, version in chunk
                ]
            }
            try:
                response = client.post(f"{API}/querybatch", json=body)
                response.raise_for_status()
                rows = response.json().get("results") or []
            except (httpx.HTTPError, ValueError) as error:
                raise OsvError(f"OSV.dev didn't answer: {error}") from None
            if len(rows) != len(chunk):
                raise OsvError("OSV.dev answered with the wrong number of results")
            results += [list(r.get("vulns") or []) for r in rows]
    return results


def _fetch(client: httpx.Client, advisory_id: str) -> dict[str, Any] | None:
    try:
        response = client.get(f"{API}/vulns/{advisory_id}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    except (httpx.HTTPError, ValueError) as error:
        logger.warning("OSV advisory %s not fetched: %s", advisory_id, error)
        return None


def _compact(data: dict[str, Any]) -> dict[str, Any]:
    """What we keep of an advisory: enough for severity, the fix and a title."""
    return {
        "id": data.get("id"),
        "summary": (data.get("summary") or (data.get("details") or "").split("\n")[0])[
            :300
        ],
        "aliases": (data.get("aliases") or [])[:10],
        "modified": data.get("modified"),
        "severity": data.get("severity") or [],
        "database_specific": {
            "severity": (data.get("database_specific") or {}).get("severity")
        },
        "affected": [
            {
                "package": a.get("package") or {},
                "ranges": [
                    {"events": r.get("events") or []} for r in (a.get("ranges") or [])
                ],
            }
            for a in (data.get("affected") or [])[:40]
        ],
    }


def _stamp(value: str | None) -> str:
    """OSV's `modified`, comparable: the batch query gives microseconds and
    the advisory itself nanoseconds."""
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?", value or "")
    return f"{m.group(1)}.{(m.group(2) or '').ljust(6, '0')[:6]}" if m else ""


def advisories(
    db: Session, wanted: dict[str, str | None], follow: bool = True
) -> dict[str, dict[str, Any]]:
    """Details for advisory ids, from the cache when it's as new as OSV's
    `modified` stamp. `wanted` maps id -> modified (or None)."""
    out: dict[str, dict[str, Any]] = {}
    missing = []
    for advisory_id, modified in wanted.items():
        cached = db.get(SecurityCache, f"osv:{advisory_id}")
        if cached is not None and (
            not modified or _stamp(cached.data.get("modified")) >= _stamp(modified)
        ):
            out[advisory_id] = cached.data
        else:
            missing.append(advisory_id)
    if missing:
        with _client() as client, ThreadPoolExecutor(WORKERS) as pool:
            fetched = list(pool.map(lambda i: (i, _fetch(client, i)), missing))
        for advisory_id, data in fetched:
            if data is None:
                continue
            compact = _compact(data)
            row = db.get(SecurityCache, f"osv:{advisory_id}")
            if row is None:
                db.add(
                    SecurityCache(
                        key=f"osv:{advisory_id}", data=compact, fetched_at=_now()
                    )
                )
            else:
                row.data, row.fetched_at = compact, _now()
            out[advisory_id] = compact
        db.flush()
    # Go and PyPI advisories often carry no rating of their own: use the
    # GitHub advisory they point to.
    unrated = (
        {}
        if not follow
        else {
            i: alias
            for i, data in out.items()
            if severity(data) == "unknown"
            for alias in data.get("aliases") or []
            if alias.startswith("GHSA-") and alias not in out
        }
    )
    if unrated:
        rated = advisories(db, {a: None for a in set(unrated.values())}, follow=False)
        for advisory_id, alias in unrated.items():
            if alias in rated and severity(rated[alias]) != "unknown":
                out[advisory_id] = {
                    **out[advisory_id],
                    "database_specific": rated[alias].get("database_specific") or {},
                }
    return out
