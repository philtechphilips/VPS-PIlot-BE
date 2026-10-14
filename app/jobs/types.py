"""The fixed set of operations an agent may be asked to run.

Every job type has a strict payload schema. The same allowlist is enforced
again by the agent and by the privileged helper on the server, so a bad
payload is rejected three times before anything executes.
"""

from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

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


# ---------------------------------------------------------------------------
# Deployments (internal: created by app.apps.service, not the actions API)
# ---------------------------------------------------------------------------

AppName = Annotated[
    str, StringConstraints(pattern=r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")
]
HexId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
GitUrl = Annotated[
    str,
    StringConstraints(
        max_length=500, pattern=r"^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._~/-]+$"
    ),
]


def _no_parent(value: str) -> str:
    # No ".." anywhere: refs and paths must not climb out of the checkout.
    if ".." in value:
        raise ValueError("must not contain '..'")
    return value


# Pydantic's regex engine has no look-ahead, so the ".." rule is a validator.
GitRef = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9._/][A-Za-z0-9._/-]{0,199}$"),
    AfterValidator(_no_parent),
]
ImageRef = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._/:@-]{0,299}$")]
RelPath = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9._-][A-Za-z0-9._/-]{0,199}$"),
    AfterValidator(_no_parent),
]
HealthPath = Annotated[
    str, StringConstraints(pattern=r"^/[A-Za-z0-9._~/?=&%-]{0,199}$")
]
Port = Annotated[int, Field(ge=1, le=65535)]
HostPort = Annotated[int, Field(ge=1024, le=65535)]
Cpus = Annotated[str, StringConstraints(pattern=r"^\d{1,2}(\.\d{1,2})?$")]
Memory = Annotated[str, StringConstraints(pattern=r"^\d{1,6}[kmg]$")]
# A single-line shell command run inside the build/app container.
Command = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=1, max_length=500, pattern=r"^[^\r\n]+$"
    ),
]


class GitSource(Strict):
    type: Literal["git"]
    url: GitUrl
    ref: GitRef
    # Private GitHub repo: the agent fetches a short-lived token with the env.
    auth: bool = False


class ImageSource(Strict):
    type: Literal["image"]
    image: ImageRef
    # False for rollbacks: the image was built here earlier.
    pull: bool = True


class AppDeployPayload(Strict):
    app: AppName
    deployment_id: HexId
    source: GitSource | ImageSource = Field(discriminator="type")
    dockerfile: RelPath = "Dockerfile"
    context: RelPath = "."
    container_port: Port
    host_port: HostPort
    health_path: HealthPath = "/"
    health_timeout: Annotated[int, Field(ge=5, le=600)] = 60
    cpus: Cpus | None = None
    memory: Memory | None = None
    # The agent fetches env values for this job over its authenticated
    # channel; they are never stored in the job payload.
    has_env: bool = False
    # For repositories without a Dockerfile: override the detected commands.
    build_command: Command | None = None
    start_command: Command | None = None


class AppRemovePayload(Strict):
    app: AppName


JOB_TYPES: dict[str, type[Strict]] = {
    "app.deploy": AppDeployPayload,
    "app.remove": AppRemovePayload,
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
