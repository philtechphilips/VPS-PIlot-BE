"""The agent's main loop: heartbeat, metrics and inventory on their own
schedules, with buffering and backoff when the control plane is away."""

from __future__ import annotations

import logging
import signal
import threading
import time
from collections import deque
from typing import Any

from vpspilot_agent import collectors, executor
from vpspilot_agent.client import ApiError, Client, NotEnrolled
from vpspilot_agent.config import AgentConfig

log = logging.getLogger("vpspilot_agent")

INVENTORY_SECONDS = 60
CLAIM_SECONDS = 3  # how often to ask for queued jobs
MAX_BUFFERED_SAMPLES = 120  # ~30 minutes at the default 15 s interval
EXIT_NOT_ENROLLED = 78  # EX_CONFIG: systemd is told not to restart on this


class Runner:
    def __init__(self, config: AgentConfig, client: Client | None = None):
        self.config = config
        self.client = client or Client(config.api_url, config.agent_token)
        self.sampler = collectors.MetricsSampler()
        self.buffer: deque[dict[str, Any]] = deque(maxlen=MAX_BUFFERED_SAMPLES)
        self.stopping = False
        self.failures = 0
        now = time.monotonic()
        self.next_heartbeat = now
        self.next_metrics = now + 2  # let the CPU counter warm up
        self.next_inventory = now + 1
        self.next_claim = now + 1
        # One job at a time, off the main loop so heartbeats continue
        # through long deployments.
        self.worker: threading.Thread | None = None
        self.revoked = False

    def stop(self, *_: Any) -> None:
        log.info("Stopping")
        self.stopping = True

    def heartbeat(self) -> None:
        reply = self.client.post("/agent/v1/heartbeat", {"facts": collectors.facts()})
        self.config.heartbeat_seconds = int(
            reply.get("heartbeat_seconds", self.config.heartbeat_seconds)
        )
        self.config.metrics_seconds = int(
            reply.get("metrics_seconds", self.config.metrics_seconds)
        )
        if reply.get("jobs_pending"):
            self.next_claim = time.monotonic()

    def collect_and_send_metrics(self) -> None:
        self.buffer.append(self.sampler.sample())
        batch = list(self.buffer)
        self.client.post("/agent/v1/metrics", {"samples": batch})
        self.buffer.clear()

    def send_inventory(self) -> None:
        self.client.post("/agent/v1/inventory", collectors.inventory())

    def claim_and_run(self) -> bool:
        """Run one queued job if there is one. Returns True if a job ran."""
        if self.worker and self.worker.is_alive():
            return False
        reply = self.client.post("/agent/v1/jobs/claim", {})
        job = reply.get("job")
        if not job:
            return False
        self.worker = threading.Thread(
            target=self._run_job, args=(job,), name=f"job-{job['id']}", daemon=True
        )
        self.worker.start()
        return True

    def _run_job(self, job: dict[str, Any]) -> None:
        try:
            executor.run_job(self.client, job)
        except NotEnrolled:
            self.revoked = True
            self.stopping = True
        except (ApiError, OSError) as error:
            log.warning("job %s: couldn't report result (%s)", job.get("id"), error)
        except Exception:  # noqa: BLE001 - a job must never kill the agent
            log.exception("job %s crashed", job.get("id"))
        # Jobs change what's running; refresh the inventory soon.
        self.next_inventory = min(self.next_inventory, time.monotonic() + 2)
        self.next_claim = time.monotonic()

    def tick(self) -> None:
        now = time.monotonic()
        if now >= self.next_heartbeat:
            self.next_heartbeat = now + self.config.heartbeat_seconds
            self.heartbeat()
        if now >= self.next_metrics:
            self.next_metrics = now + self.config.metrics_seconds
            self.collect_and_send_metrics()
        if now >= self.next_inventory:
            self.next_inventory = now + INVENTORY_SECONDS
            self.send_inventory()
        if now >= self.next_claim:
            self.claim_and_run()
            self.next_claim = now + CLAIM_SECONDS

    def run(self) -> int:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        log.info(
            "Agent running for %s (%s), control plane %s",
            self.config.server_name,
            self.config.server_id,
            self.config.api_url,
        )
        while not self.stopping:
            try:
                self.tick()
                if self.failures:
                    log.info("Control plane reachable again")
                self.failures = 0
                time.sleep(1)
            except NotEnrolled as error:
                log.error(
                    "The control plane rejected this agent (%s). It was revoked or "
                    "removed; re-enroll with a new token to continue.",
                    error.message,
                )
                return EXIT_NOT_ENROLLED
            except (ApiError, OSError) as error:
                # Network or server error: keep sampling into the buffer and
                # back off up to a minute.
                self.failures += 1
                delay = min(60, 2 ** min(self.failures, 6))
                log.warning(
                    "Control plane unavailable (%s); retry in %ss, %s samples buffered",
                    error,
                    delay,
                    len(self.buffer),
                )
                self._sleep(delay)
        return EXIT_NOT_ENROLLED if self.revoked else 0

    def _sleep(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while not self.stopping and time.monotonic() < end:
            time.sleep(0.5)
