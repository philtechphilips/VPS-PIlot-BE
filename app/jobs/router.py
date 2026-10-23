from typing import Annotated, NoReturn

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from app.audit import service as audit
from app.auth.dependencies import AdminUser
from app.core.database import DbSession
from app.jobs import service
from app.jobs.schemas import ActionRequest, JobDetail, JobEventOut, JobOut
from app.servers import service as servers
from app.users.models import Role

router = APIRouter(prefix="/api/v1", tags=["Jobs"])


def _raise(error: service.JobError) -> NoReturn:
    raise HTTPException(status_code=error.status_code, detail=error.detail)


@router.post(
    "/servers/{server_id}/actions",
    response_model=JobOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def request_action(
    server_id: str,
    body: ActionRequest,
    request: Request,
    response: Response,
    db: DbSession,
    user: AdminUser,
):
    """Queue a typed operation for the server's agent. 202 means queued, not
    done: poll the job for its outcome."""
    server = servers.get_server(db, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    actor, label = audit.user_actor(user)
    try:
        job, created = service.create(
            db,
            server,
            body.type,
            body.payload,
            actor,
            label,
            body.idempotency_key,
            request,
        )
    except service.JobError as error:
        _raise(error)
    if not created:
        response.status_code = status.HTTP_200_OK
    return job


@router.get("/jobs", response_model=list[JobOut])
def list_jobs(
    db: DbSession,
    _: AdminUser,
    server_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 30,
):
    return service.list_jobs(db, server_id, limit)


@router.get("/jobs/{job_id}", response_model=JobDetail)
def get_job(job_id: str, db: DbSession, user: AdminUser):
    service.reap(db)
    job = service.get(db, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Job not found")
    if user.role == Role.VIEWER and job.type.startswith(("db.", "backup.")):
        # Query results and dumps can hold data a viewer shouldn't see.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only admins can open this job")
    return JobDetail(
        **JobOut.model_validate(job).model_dump(),
        output=service.job_output(job),
        events=[JobEventOut.model_validate(e) for e in service.events(db, job.id)],
    )


@router.post("/jobs/{job_id}/cancel", response_model=JobOut)
def cancel_job(job_id: str, db: DbSession, _: AdminUser):
    job = service.get(db, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Job not found")
    try:
        return service.cancel(db, job)
    except service.JobError as error:
        _raise(error)
