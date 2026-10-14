"""Unit tests for the agent package (runs against the local host)."""

import os
import stat

import pytest
from vpspilot_agent import collectors
from vpspilot_agent.client import ApiError, NotEnrolled
from vpspilot_agent.config import AgentConfig, load, save
from vpspilot_agent.runner import EXIT_NOT_ENROLLED, Runner


def config(**kw):
    return AgentConfig(
        api_url="http://cp",
        server_id="s1",
        server_name="web-1",
        agent_token="agt_x",
        **kw,
    )


class FakeClient:
    def __init__(self, fail_with=None):
        self.calls = []
        self.fail_with = fail_with

    def post(self, path, body):
        self.calls.append((path, body))
        if self.fail_with:
            raise self.fail_with
        if path == "/agent/v1/heartbeat":
            return {"heartbeat_seconds": 7, "metrics_seconds": 9}
        return {}


def test_facts_shape():
    facts = collectors.facts()
    assert facts["cpu_count"] >= 1
    assert facts["memory_total"] > 0 and facts["disk_total"] > 0
    assert facts["agent_version"]
    assert set(facts["capabilities"]) == {"metrics", "systemd", "docker"}


def test_sample_is_within_schema_bounds():
    sample = collectors.MetricsSampler().sample()
    for key in ("cpu_percent", "memory_percent", "swap_percent", "disk_percent"):
        assert 0 <= sample[key] <= 100
    assert sample["net_rx_bps"] >= 0 and sample["net_tx_bps"] >= 0


def test_config_is_written_private(tmp_path):
    path = tmp_path / "agent.json"
    save(config(), str(path))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert load(str(path)).agent_token == "agt_x"


def test_tick_sends_heartbeat_metrics_inventory_and_adopts_intervals():
    client = FakeClient()
    runner = Runner(config(), client)
    runner.next_metrics = runner.next_inventory = 0
    runner.tick()
    paths = [c[0] for c in client.calls]
    assert paths == ["/agent/v1/heartbeat", "/agent/v1/metrics", "/agent/v1/inventory"]
    assert runner.config.heartbeat_seconds == 7 and runner.config.metrics_seconds == 9
    assert not runner.buffer


def test_samples_are_buffered_while_offline():
    runner = Runner(config(), FakeClient(fail_with=ApiError(503, "down")))
    runner.next_heartbeat = float("inf")
    for _ in range(3):
        runner.next_metrics = 0
        with pytest.raises(ApiError):
            runner.tick()
    assert len(runner.buffer) == 3


def test_revoked_agent_exits_without_retrying(monkeypatch):
    runner = Runner(
        config(), FakeClient(fail_with=NotEnrolled(401, "Agent is not enrolled"))
    )
    monkeypatch.setattr("signal.signal", lambda *a: None)
    assert runner.run() == EXIT_NOT_ENROLLED
