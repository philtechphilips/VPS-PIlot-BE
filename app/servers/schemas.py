from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Short = Annotated[str, StringConstraints(max_length=64)]
Medium = Annotated[str, StringConstraints(max_length=255)]

ServerStatus = Literal["pending", "online", "offline", "revoked"]

# ---------------------------------------------------------------------------
# Agent → control plane (everything is bounded)
# ---------------------------------------------------------------------------


class HostFacts(BaseModel):
    hostname: Medium | None = None
    os_name: Short | None = None
    os_version: Short | None = None
    kernel: Annotated[str, StringConstraints(max_length=128)] | None = None
    arch: Annotated[str, StringConstraints(max_length=32)] | None = None
    cpu_count: Annotated[int, Field(ge=1, le=4096)] | None = None
    memory_total: Annotated[int, Field(ge=0)] | None = None
    disk_total: Annotated[int, Field(ge=0)] | None = None
    ip_addresses: (
        Annotated[
            list[Annotated[str, StringConstraints(max_length=45)]], Field(max_length=16)
        ]
        | None
    ) = None
    agent_version: Annotated[str, StringConstraints(max_length=32)] | None = None
    uptime_seconds: Annotated[int, Field(ge=0)] | None = None
    capabilities: Annotated[dict[Short, bool | Short], Field(max_length=32)] | None = (
        None
    )


class EnrollRequest(BaseModel):
    token: Annotated[str, StringConstraints(min_length=10, max_length=128)]
    facts: HostFacts


class EnrollResponse(BaseModel):
    server_id: str
    server_name: str
    agent_token: str
    heartbeat_seconds: int
    metrics_seconds: int


class HeartbeatRequest(BaseModel):
    facts: HostFacts = HostFacts()


class AgentConfig(BaseModel):
    heartbeat_seconds: int
    metrics_seconds: int
    server_time: datetime
    # Queued jobs waiting for this agent; it claims them right away.
    jobs_pending: int = 0


Percent = Annotated[float, Field(ge=0, le=100)]
NonNegative = Annotated[float, Field(ge=0)]


class MetricSampleIn(BaseModel):
    ts: datetime
    cpu_percent: Percent
    memory_percent: Percent
    memory_used: Annotated[int, Field(ge=0)]
    swap_percent: Percent
    disk_percent: Percent
    disk_used: Annotated[int, Field(ge=0)]
    inode_percent: Percent | None = None
    load_1: NonNegative
    load_5: NonNegative
    load_15: NonNegative
    net_rx_bps: NonNegative
    net_tx_bps: NonNegative


class MetricsRequest(BaseModel):
    samples: Annotated[list[MetricSampleIn], Field(min_length=1, max_length=120)]


class ServiceIn(BaseModel):
    name: Annotated[str, StringConstraints(max_length=128)]
    active: Short
    sub: Short
    description: Medium = ""


class ContainerIn(BaseModel):
    id: Short
    name: Annotated[str, StringConstraints(max_length=128)]
    image: Medium
    state: Short
    status: Annotated[str, StringConstraints(max_length=128)] = ""
    ports: Medium = ""


class InventoryRequest(BaseModel):
    services: Annotated[list[ServiceIn], Field(max_length=500)] = []
    containers: Annotated[list[ContainerIn], Field(max_length=200)] = []
    runtimes: Annotated[dict[Short, Short | None], Field(max_length=32)] = {}
    docker_access: bool = False
    listening_ports: Annotated[
        list[Annotated[int, Field(ge=1, le=65535)]], Field(max_length=2000)
    ] = []


# ---------------------------------------------------------------------------
# Owner API
# ---------------------------------------------------------------------------


class EnrollmentCreate(BaseModel):
    name: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=63)
    ]
    tags: Annotated[
        list[Annotated[str, StringConstraints(max_length=32)]], Field(max_length=10)
    ] = []


class MetricsSnapshot(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ts: datetime
    cpu_percent: float
    memory_percent: float
    memory_used: int
    swap_percent: float
    disk_percent: float
    disk_used: int
    inode_percent: float | None
    load_1: float
    load_5: float
    load_15: float
    net_rx_bps: float
    net_tx_bps: float


class ServerSummary(BaseModel):
    id: str
    name: str
    tags: list[str]
    status: ServerStatus
    is_control_plane: bool
    hostname: str | None
    os_name: str | None
    os_version: str | None
    arch: str | None
    cpu_count: int | None
    memory_total: int | None
    disk_total: int | None
    ip_addresses: list[str]
    agent_version: str | None
    last_heartbeat_at: datetime | None
    enrolled_at: datetime | None
    created_at: datetime
    latest: MetricsSnapshot | None = None


class ServerDetail(ServerSummary):
    kernel: str | None
    uptime_seconds: int | None
    capabilities: dict[str, Any]
    inventory: dict[str, Any]
    inventory_at: datetime | None
    agent_token_rotated_at: datetime | None
    revoked_at: datetime | None


class EnrollmentResponse(BaseModel):
    server: ServerSummary
    token: str
    install_command: str
    expires_at: datetime


class MetricPoint(BaseModel):
    ts: datetime
    cpu_percent: float
    memory_percent: float
    swap_percent: float
    disk_percent: float
    load_1: float
    net_rx_bps: float
    net_tx_bps: float
