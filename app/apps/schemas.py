from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.jobs.types import (
    Command,
    Cpus,
    GitRef,
    GitUrl,
    HealthPath,
    HostPort,
    ImageRef,
    Memory,
    Port,
    RelPath,
)


class EnvItem(BaseModel):
    key: Annotated[str, StringConstraints(max_length=128)]
    # None keeps the stored value (secrets are never sent back to the browser)
    value: Annotated[str, StringConstraints(max_length=8192)] | None = None
    secret: bool = False


class GitSourceIn(BaseModel):
    type: Literal["git"]
    url: GitUrl
    branch: GitRef = "main"


class ImageSourceIn(BaseModel):
    type: Literal["image"]
    image: ImageRef


class AppCreate(BaseModel):
    name: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=40)
    ]
    server_id: Annotated[str, StringConstraints(max_length=32)]
    source: GitSourceIn | ImageSourceIn = Field(discriminator="type")
    dockerfile: RelPath = "Dockerfile"
    build_context: RelPath = "."
    build_command: Command | None = None
    start_command: Command | None = None
    container_port: Port
    host_port: HostPort | None = None
    health_path: HealthPath = "/"
    health_timeout_seconds: Annotated[int, Field(ge=5, le=600)] = 60
    cpu_limit: Cpus | None = None
    memory_limit: Memory | None = None
    env: Annotated[list[EnvItem], Field(max_length=100)] = []
    deploy: bool = True


class AppUpdate(BaseModel):
    branch: GitRef | None = None
    image: ImageRef | None = None
    dockerfile: RelPath | None = None
    build_context: RelPath | None = None
    build_command: Command | None = None
    start_command: Command | None = None
    container_port: Port | None = None
    health_path: HealthPath | None = None
    health_timeout_seconds: Annotated[int, Field(ge=5, le=600)] | None = None
    cpu_limit: Cpus | None = None
    memory_limit: Memory | None = None
    env: Annotated[list[EnvItem], Field(max_length=100)] | None = None


class DeployRequest(BaseModel):
    # A branch, tag or commit for Git apps; an image reference for image apps.
    ref: GitRef | ImageRef | None = None


class EnvOut(BaseModel):
    key: str
    secret: bool
    value: str | None


class DeploymentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    application_id: str
    server_id: str
    job_id: str | None
    status: Literal["queued", "running", "succeeded", "failed", "canceled"]
    trigger: str
    requested_ref: str | None
    commit_sha: str | None
    commit_message: str | None
    image_ref: str | None
    rollback_of: str | None
    error: str | None
    created_by: str
    created_at: datetime
    finished_at: datetime | None
    app_name: str | None = None
    is_current: bool = False


class DeploymentDetail(DeploymentOut):
    spec: dict[str, Any]
    output: str | None
    events: list[dict[str, Any]]


class AppOut(BaseModel):
    id: str
    name: str
    server_id: str
    server_name: str | None
    runtime: str
    source_type: Literal["git", "image"]
    repo_url: str | None
    branch: str | None
    image: str | None
    dockerfile: str
    build_context: str
    build_command: str | None
    start_command: str | None
    container_port: int
    host_port: int
    health_path: str
    health_timeout_seconds: int
    cpu_limit: str | None
    memory_limit: str | None
    env: list[EnvOut]
    current_deployment: DeploymentOut | None
    latest_deployment: DeploymentOut | None
    created_at: datetime
