"""Runs alert evaluation in the API process on a timer."""

import logging
import threading

from sqlalchemy import text

from app.core.config import settings
from app.core.database import SessionLocal
from app.monitoring import service

logger = logging.getLogger(__name__)
_stop = threading.Event()


def _tick() -> None:
    with SessionLocal() as db:
        if db.bind.dialect.name == "postgresql":
            # Several API workers: only one evaluates at a time.
            if not db.execute(
                text("SELECT pg_try_advisory_xact_lock(7413001)")
            ).scalar():
                return
        counts = service.evaluate(db)
        if counts["fired"] or counts["resolved"]:
            logger.info(
                "alerts: %s fired, %s resolved", counts["fired"], counts["resolved"]
            )


def _loop(interval: int) -> None:
    while not _stop.wait(interval):
        try:
            _tick()
        except Exception:  # noqa: BLE001 - keep evaluating on the next tick
            logger.exception("alert evaluation failed")


def start() -> threading.Thread | None:
    interval = settings.alerts_evaluate_seconds
    if interval <= 0:
        return None
    _stop.clear()
    thread = threading.Thread(
        target=_loop, args=(interval,), name="alerts", daemon=True
    )
    thread.start()
    return thread


def stop() -> None:
    _stop.set()
