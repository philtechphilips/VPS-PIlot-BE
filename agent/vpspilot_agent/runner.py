"""The agent's main loop: heartbeat, metrics and inventory on their own
schedules, with buffering and backoff when the control plane is away."""

from __future__ import annotations

import logging
import signal
import time
from collections import deque
from typing import Any

from vpspilot_agent import collectors
from vpspilot_agent.client import ApiError, Client, NotEnrolled
from vpspilot_agent.config import AgentConfig

log = logging.getLogger("vpspilot_agent")

INVENTORY_SECONDS = 60
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

    def collect_and_send_metrics(self) -> None:
        self.buffer.append(self.sampler.sample())
        batch = list(self.buffer)
        self.client.post("/agent/v1/metrics", {"samples": batch})
        self.buffer.clear()

    def send_inventory(self) -> None:
        self.client.post("/agent/v1/inventory", collectors.inventory())

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
        return 0

    def _sleep(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while not self.stopping and time.monotonic() < end:
            time.sleep(0.5)
