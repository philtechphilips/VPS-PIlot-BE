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


# ---------------------------------------------------------------------------
# Privileged helper and executor
# ---------------------------------------------------------------------------

from vpspilot_agent import executor, helper  # noqa: E402


def test_helper_rejects_anything_off_the_allowlist():
    assert helper.handle({"op": "shell", "args": {"cmd": "id"}})["ok"] is False
    assert (
        "invalid unit"
        in helper.handle({"op": "service.restart", "args": {"unit": "x; id"}})["error"]
    )
    assert (
        "managed by VPSPilot"
        in helper.handle(
            {"op": "service.stop", "args": {"unit": "vpspilot-agent.service"}}
        )["error"]
    )
    assert (
        "SSH"
        in helper.handle({"op": "service.stop", "args": {"unit": "ssh.service"}})[
            "error"
        ]
    )
    assert (
        "lines"
        in helper.handle(
            {"op": "service.logs", "args": {"unit": "cron.service", "lines": 9999}}
        )["error"]
    )
    assert helper.handle({"op": "ping"})["output"] == "pong"


def test_helper_runs_argument_lists(monkeypatch):
    seen = []
    monkeypatch.setattr(
        helper,
        "_run",
        lambda cmd, timeout=60: seen.append(cmd) or {"exit_code": 0, "output": "ok\n"},
    )
    result = helper.handle(
        {"op": "container.logs", "args": {"container": "web", "lines": 20}}
    )
    assert result["ok"] is True
    assert seen == [["docker", "logs", "--tail", "20", "--timestamps", "web"]]


class RecordingClient:
    def __init__(self):
        self.calls = []

    def post(self, path, body):
        self.calls.append((path, body))
        return {}


def test_executor_reports_helper_result():
    client = RecordingClient()
    job = {
        "id": "j1",
        "type": "service.restart",
        "version": 1,
        "payload": {"unit": "cron.service"},
    }
    status = executor.run_job(
        client,
        job,
        call=lambda op, args: {
            "ok": True,
            "exit_code": 0,
            "output": "cron.service: active",
        },
    )
    assert status == "succeeded"
    assert client.calls[-1] == (
        "/agent/v1/jobs/j1/complete",
        {
            "status": "succeeded",
            "exit_code": 0,
            "output": "cron.service: active",
            "error": None,
            "result": {},
        },
    )


def test_executor_refuses_unknown_jobs_and_handles_missing_helper():
    client = RecordingClient()
    assert (
        executor.run_job(client, {"id": "j2", "type": "shell.run", "payload": {}})
        == "failed"
    )

    def down(op, args):
        raise FileNotFoundError("no socket")

    job = {
        "id": "j3",
        "type": "service.logs",
        "version": 1,
        "payload": {"unit": "cron.service"},
    }
    assert executor.run_job(client, job, call=down) == "failed"
    assert "helper unavailable" in client.calls[-1][1]["error"]
