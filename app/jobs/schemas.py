from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.jobs.types import JobType

JobStatus = Literal["queued", "running", "succeeded", "failed", "expired", "canceled"]


class ActionRequest(BaseModel):
    type: JobType
    payload: dict[str, Any] = {}
    idempotency_key: (
        Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:-]{8,64}$")] | None
    ) = None


class JobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    server_id: str
    type: str
    payload: dict[str, Any]
    status: JobStatus
    created_by: str
    correlation_id: str
    created_at: datetime
    claimed_at: datetime | None
    finished_at: datetime | None
    exit_code: int | None
    error: str | None


class JobEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    level: str
    message: str
    created_at: datetime


class JobDetail(JobOut):
    output: str | None
    events: list[JobEventOut]


# Agent side --------------------------------------------------------------


class AgentJob(BaseModel):
    """What the agent receives: just enough to run the typed operation."""

    id: str
    type: str
    version: int
    payload: dict[str, Any]


class ClaimResponse(BaseModel):
    job: AgentJob | None


class JobEventIn(BaseModel):
    level: Literal["info", "warn", "error"] = "info"
    message: Annotated[str, StringConstraints(max_length=2000)]


class JobEventsRequest(BaseModel):
    events: Annotated[list[JobEventIn], Field(min_length=1, max_length=50)]


class JobCompleteRequest(BaseModel):
    status: Literal["succeeded", "failed"]
    exit_code: int | None = None
    # Bounded on the agent too; trimmed again server-side.
    output: Annotated[str, StringConstraints(max_length=256 * 1024)] = ""
    error: Annotated[str, StringConstraints(max_length=2000)] | None = None
    # Small structured outcome, e.g. {"commit_sha": ..., "image_ref": ...}
    result: Annotated[dict[str, str | int | bool | None], Field(max_length=16)] = {}
