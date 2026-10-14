"""Agent configuration: the control plane URL and this agent's credential."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass

DEFAULT_PATH = "/etc/vpspilot/agent.json"


@dataclass
class AgentConfig:
    api_url: str
    server_id: str
    server_name: str
    agent_token: str
    heartbeat_seconds: int = 10
    metrics_seconds: int = 15


def load(path: str = DEFAULT_PATH) -> AgentConfig:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return AgentConfig(**data)


def save(config: AgentConfig, path: str = DEFAULT_PATH) -> None:
    """Write atomically with 0600 permissions: the token is a credential."""
    directory = os.path.dirname(path) or "."
    tmp = os.path.join(directory, ".agent.json.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(asdict(config), handle, indent=2)
    os.replace(tmp, path)
