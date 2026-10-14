from typing import Annotated, NoReturn

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import select

from app.apps import service
from app.apps.models import Application, Deployment
from app.apps.schemas import (
    AppCreate,
    AppOut,
    AppUpdate,
    DeploymentDetail,
    DeploymentOut,
    DeployRequest,
    EnvOut,
)
from app.audit import service as audit
from app.auth.dependencies import AdminUser
from app.core.database import DbSession
from app.jobs import service as jobs
from app.servers.models import Server

router = APIRouter(prefix="/api/v1", tags=["Applications"])


def _raise(error: service.AppError) -> NoReturn:
    raise HTTPException(status_code=error.status_code, detail=error.detail)


def _deployment_out(db, d: Deployment, app: Application | None = None) -> DeploymentOut:
    app = app or db.get(Application, d.application_id)
    return DeploymentOut(
        **{k: getattr(d, k) for k in DeploymentOut.model_fields if hasattr(d, k)},
        app_name=app.name if app else None,
        is_current=bool(app and app.current_deployment_id == d.id),
    )


def _app_out(db, app: Application) -> AppOut:
    server = db.get(Server, app.server_id)
    current = (
        db.get(Deployment, app.current_deployment_id)
        if app.current_deployment_id
        else None
    )
    latest = db.scalar(
        select(Deployment)
        .where(Deployment.application_id == app.id)
        .order_by(Deployment.created_at.desc(), Deployment.id)
        .limit(1)
    )
    return AppOut(
        id=app.id,
        name=app.name,
        server_id=app.server_id,
        server_name=server.name if server else None,
        runtime=app.runtime,
        source_type=app.source_type,  # type: ignore[arg-type]
        repo_url=app.repo_url,
        branch=app.branch,
        image=app.image,
        dockerfile=app.dockerfile,
        build_context=app.build_context,
        container_port=app.container_port,
        host_port=app.host_port,
        health_path=app.health_path,
        health_timeout_seconds=app.health_timeout_seconds,
        cpu_limit=app.cpu_limit,
        memory_limit=app.memory_limit,
        env=[EnvOut(**e) for e in service.env_for_display(app)],
        current_deployment=_deployment_out(db, current, app) if current else None,
        latest_deployment=_deployment_out(db, latest, app) if latest else None,
        created_at=app.created_at,
    )


def _get_app(db, app_id: str) -> Application:
    app = service.get_app(db, app_id)
    if app is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Application not found")
    return app


@router.get("/applications", response_model=list[AppOut])
def list_apps(db: DbSession, _: AdminUser):
    jobs.reap(db)
    return [_app_out(db, a) for a in service.list_apps(db)]


@router.post(
    "/applications", response_model=AppOut, status_code=status.HTTP_201_CREATED
)
def create_app(body: AppCreate, request: Request, db: DbSession, user: AdminUser):
    server = db.get(Server, body.server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    data = body.model_dump()
    data["source"] = body.source.model_dump()
    actor, label = audit.user_actor(user)
    try:
        app = service.create_app(db, server, data)
        audit.record(
            db,
            action="app.create",
            result="success",
            actor=actor,
            actor_label=label,
            target_type="application",
            target_id=app.id,
            target_label=app.name,
            detail=f"on {server.name}",
            request=request,
        )
        if body.deploy:
            service.deploy(db, app, actor, label, trigger="create", request=request)
    except service.AppError as error:
        _raise(error)
    return _app_out(db, app)


@router.get("/applications/{app_id}", response_model=AppOut)
def get_app(app_id: str, db: DbSession, _: AdminUser):
    jobs.reap(db)
    return _app_out(db, _get_app(db, app_id))


@router.patch("/applications/{app_id}", response_model=AppOut)
def update_app(
    app_id: str, body: AppUpdate, request: Request, db: DbSession, user: AdminUser
):
    app = _get_app(db, app_id)
    data = body.model_dump(exclude_unset=True)
    if "env" in data and data["env"] is not None:
        data["env"] = [e.model_dump() for e in body.env or []]
    try:
        app = service.update_settings(db, app, data)
    except service.AppError as error:
        _raise(error)
    actor, label = audit.user_actor(user)
    audit.record(
        db,
        action="app.update",
        result="success",
        actor=actor,
        actor_label=label,
        target_type="application",
        target_id=app.id,
        target_label=app.name,
        # Field names only: never values (they may be secrets).
        detail="changed " + ", ".join(sorted(data)) if data else None,
        request=request,
    )
    return _app_out(db, app)


@router.delete("/applications/{app_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_app(app_id: str, request: Request, db: DbSession, user: AdminUser):
    app = _get_app(db, app_id)
    actor, label = audit.user_actor(user)
    name = app.name
    service.remove_app(db, app, actor, label, request)
    audit.record(
        db,
        action="app.remove",
        result="success",
        actor=actor,
        actor_label=label,
        target_type="application",
        target_id=app_id,
        target_label=name,
        request=request,
    )


@router.post(
    "/applications/{app_id}/deployments",
    response_model=DeploymentOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_deployment(
    app_id: str, body: DeployRequest, request: Request, db: DbSession, user: AdminUser
):
    """Queue a deployment. 202 means queued; follow the deployment for the outcome."""
    app = _get_app(db, app_id)
    actor, label = audit.user_actor(user)
    try:
        deployment = service.deploy(
            db, app, actor, label, ref=body.ref, request=request
        )
    except service.AppError as error:
        _raise(error)
    return _deployment_out(db, deployment, app)


@router.get("/applications/{app_id}/deployments", response_model=list[DeploymentOut])
def app_deployments(
    app_id: str,
    db: DbSession,
    _: AdminUser,
    limit: Annotated[int, Query(ge=1, le=100)] = 30,
):
    app = _get_app(db, app_id)
    return [
        _deployment_out(db, d, app) for d in service.list_deployments(db, app.id, limit)
    ]


@router.get("/deployments", response_model=list[DeploymentOut])
def all_deployments(
    db: DbSession, _: AdminUser, limit: Annotated[int, Query(ge=1, le=100)] = 50
):
    return [_deployment_out(db, d) for d in service.list_deployments(db, None, limit)]


@router.get("/deployments/{deployment_id}", response_model=DeploymentDetail)
def get_deployment(deployment_id: str, db: DbSession, _: AdminUser):
    jobs.reap(db)
    deployment = service.get_deployment(db, deployment_id)
    if deployment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Deployment not found")
    job = service.job_for(db, deployment)
    events = (
        [
            {"level": e.level, "message": e.message, "created_at": e.created_at}
            for e in jobs.events(db, job.id)
        ]
        if job
        else []
    )
    return DeploymentDetail(
        **_deployment_out(db, deployment).model_dump(),
        spec=deployment.spec or {},
        output=job.output if job else None,
        events=events,
    )


@router.post(
    "/deployments/{deployment_id}/rollback",
    response_model=DeploymentOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def rollback_deployment(
    deployment_id: str, request: Request, db: DbSession, user: AdminUser
):
    """Release this (earlier, successful) deployment's image again."""
    target = service.get_deployment(db, deployment_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Deployment not found")
    app = _get_app(db, target.application_id)
    actor, label = audit.user_actor(user)
    try:
        deployment = service.rollback(db, app, target, actor, label, request)
    except service.AppError as error:
        _raise(error)
    return _deployment_out(db, deployment, app)
