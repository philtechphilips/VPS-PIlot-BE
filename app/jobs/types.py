"""The fixed set of operations an agent may be asked to run.

Every job type has a strict payload schema. The same allowlist is enforced
again by the agent and by the privileged helper on the server, so a bad
payload is rejected three times before anything executes.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Unit = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9@._:-]{1,200}\.service$")]
Container = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
]
Lines = Annotated[int, Field(ge=1, le=500)]

# Stopping or restarting these could cut VPSPilot (or you) off the server.
PROTECTED_UNITS = {"vpspilot-agent.service", "vpspilot-helper.service"}
NO_STOP_UNITS = {"ssh.service", "sshd.service"}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServicePayload(Strict):
    unit: Unit


class ServiceLogsPayload(Strict):
    unit: Unit
    lines: Lines = 200


class ContainerPayload(Strict):
    container: Container


class ContainerLogsPayload(Strict):
    container: Container
    lines: Lines = 200


JOB_TYPES: dict[str, type[Strict]] = {
    "service.restart": ServicePayload,
    "service.start": ServicePayload,
    "service.stop": ServicePayload,
    "service.logs": ServiceLogsPayload,
    "container.restart": ContainerPayload,
    "container.start": ContainerPayload,
    "container.stop": ContainerPayload,
    "container.logs": ContainerLogsPayload,
}

JobType = Literal[
    "service.restart",
    "service.start",
    "service.stop",
    "service.logs",
    "container.restart",
    "container.start",
    "container.stop",
    "container.logs",
]


class PolicyError(ValueError):
    pass


def validate(job_type: str, payload: dict) -> dict:
    """Return the normalised payload or raise PolicyError / ValidationError."""
    schema = JOB_TYPES.get(job_type)
    if schema is None:
        raise PolicyError(f"Unknown job type: {job_type}")
    data = schema.model_validate(payload).model_dump()
    unit = data.get("unit")
    if unit in PROTECTED_UNITS and job_type != "service.logs":
        raise PolicyError(f"{unit} is managed by VPSPilot and can't be changed here")
    if unit in NO_STOP_UNITS and job_type == "service.stop":
        raise PolicyError("Stopping SSH could lock you out of the server")
    return data
