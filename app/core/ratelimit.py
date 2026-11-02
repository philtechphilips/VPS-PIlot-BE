"""Per-address limits for endpoints worth guessing at: sign-in, codes,
password resets and agent enrollment. They come on top of the per-account
lockout, which can't stop one address trying many accounts.

Counts live in memory: the API is a single process behind Caddy, which
sets X-Forwarded-For itself, so the address is the client's.
"""

import threading
import time
from collections import deque

from fastapi import Depends, HTTPException, Request, status

from app.audit.service import client_ip

_hits: dict[tuple[str, str], deque[float]] = {}
_lock = threading.Lock()
_swept = 0.0
SWEEP_EVERY = 300  # seconds between dropping idle addresses


def reset() -> None:
    """Forget every count (tests)."""
    with _lock:
        _hits.clear()


def _sweep(now: float, longest: int) -> None:
    global _swept
    if now - _swept < SWEEP_EVERY:
        return
    _swept = now
    for key in [k for k, hits in _hits.items() if not hits or hits[-1] < now - longest]:
        del _hits[key]


def limit(bucket: str, count: int, seconds: int):
    """A dependency allowing `count` requests per `seconds` from one address."""

    def check(request: Request) -> None:
        key = (bucket, client_ip(request) or "unknown")
        now = time.monotonic()
        with _lock:
            hits = _hits.setdefault(key, deque())
            while hits and hits[0] <= now - seconds:
                hits.popleft()
            if len(hits) >= count:
                wait = int(hits[0] + seconds - now) + 1
                minutes = max(1, -(-wait // 60))
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    f"Too many attempts from your address. Try again in {minutes} "
                    f"minute{'s' if minutes != 1 else ''}.",
                    headers={"Retry-After": str(wait)},
                )
            hits.append(now)
            _sweep(now, 3600)

    return Depends(check)
