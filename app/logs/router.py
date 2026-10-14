"""Logs page: read any server's journal or any container's output.

Reads are disposable jobs (output encrypted at rest like all job output),
removed after an hour; only the first read of a session is audited.
"""

import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import delete, select

from app.apps.models import Application
from app.audit import service as audit
from app.auth.dependencies import AdminUser
from app.core.database import DbSession
from app.databases.models import DatabaseInstance
from app.jobs import service as jobs
from app.jobs.models import Job, JobEvent
from app.servers.models import Server

router = APIRouter(prefix="/api/v1/logs", tags=["Logs"])

RETENTION = timedelta(hours=1)


class LogsRequest(BaseModel):
    server_id: Annotated[str, StringConstraints(max_length=32)]
    source: Literal["journal", "container"]
    unit: Annotated[str, StringConstraints(max_length=200)] | None = None
    container: Annotated[str, StringConstraints(max_length=128)] | None = None
    lines: Annotated[int, Field(ge=1, le=1000)] = 200
    since: Annotated[str, StringConstraints(max_length=40)] | None = None
    cursor: Annotated[str, StringConstraints(max_length=512)] | None = None
    priority: Annotated[int, Field(ge=0, le=7)] | None = None


@router.get("/sources")
def sources(
    db: DbSession, _: AdminUser, server_id: Annotated[str, Query(max_length=32)]
):
    """What can be read on a server, from the agent's last inventory."""
    server = db.get(Server, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    inventory = server.inventory or {}
    apps = {
        f"vp-{a.name}": a.name
        for a in db.scalars(
            select(Application).where(Application.server_id == server_id)
        )
    }
    dbs = {
        f"vpdb-{d.name}": d.name
        for d in db.scalars(
            select(DatabaseInstance).where(DatabaseInstance.server_id == server_id)
        )
    }
    containers = []
    for c in inventory.get("containers") or []:
        name = str(c.get("name") or "")
        kind, label = (
            ("app", apps[name])
            if name in apps
            else ("database", dbs[name])
            if name in dbs
            else ("container", name)
        )
        containers.append(
            {
                "name": name,
                "label": label,
                "kind": kind,
                "state": c.get("state"),
                "image": c.get("image"),
            }
        )
    units = sorted(
        {str(s.get("name")) for s in inventory.get("services") or [] if s.get("name")}
    )
    return {"units": units, "containers": containers, "has_journal": True}


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def request_logs(body: LogsRequest, request: Request, db: DbSession, user: AdminUser):
    server = db.get(Server, body.server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    if body.source == "container" and not body.container:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Pick a container")
    # Disposable: drop reads older than an hour.
    old = select(Job.id).where(
        Job.type == "logs.read",
        Job.finished_at.is_not(None),
        Job.finished_at < datetime.now(UTC) - RETENTION,
    )
    db.execute(delete(JobEvent).where(JobEvent.job_id.in_(old)))
    db.execute(delete(Job).where(Job.id.in_(old)))
    payload = body.model_dump(exclude={"server_id"}, exclude_none=True)
    actor, label = audit.user_actor(user)
    following = bool(body.since or body.cursor)
    try:
        job, _ = jobs.create(
            db,
            server,
            "logs.read",
            payload,
            actor,
            label,
            request=request,
            audited=not following,
        )
    except jobs.JobError as error:
        raise HTTPException(error.status_code, error.detail) from None
    return {"job_id": job.id}


@router.get("/{job_id}")
def read_logs(job_id: str, db: DbSession, _: AdminUser):
    jobs.reap(db)
    job = db.get(Job, job_id)
    if job is None or job.type != "logs.read":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Log request not found")
    out = {
        "status": job.status,
        "error": job.error,
        "source": job.payload.get("source"),
        "cursor": None,
        "lines": [],
    }
    if job.status == "succeeded":
        try:
            out.update(json.loads(jobs.job_output(job) or "{}"))
        except ValueError:
            out["error"] = "The agent returned unreadable logs"
    return out
