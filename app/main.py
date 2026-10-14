import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.apps.router import router as apps_router
from app.audit.router import router as audit_router
from app.auth.router import router as auth_router
from app.core.config import settings
from app.databases.router import router as databases_router
from app.domains.router import router as domains_router
from app.github.router import router as github_router
from app.jobs.router import router as jobs_router
from app.logs.router import router as logs_router
from app.monitoring import worker as monitoring_worker
from app.monitoring.router import router as monitoring_router
from app.notifications.router import router as notifications_router
from app.servers.agent_router import router as agent_router
from app.servers.router import router as servers_router
from app.users.router import router as users_router

# Uvicorn only configures its own loggers, so give the app's a handler too.
# Without it, warnings such as dev-mode emails (no RESEND_API_KEY) are lost.
_app_logger = logging.getLogger("app")
if not _app_logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(levelname)s:     %(name)s %(message)s"))
    _app_logger.addHandler(_handler)
    _app_logger.setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(_: FastAPI):
    monitoring_worker.start()
    yield
    monitoring_worker.stop()


app = FastAPI(title=settings.project_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(servers_router)
app.include_router(agent_router)
app.include_router(jobs_router)
app.include_router(audit_router)
app.include_router(apps_router)
app.include_router(github_router)
app.include_router(notifications_router)
app.include_router(monitoring_router)
app.include_router(databases_router)
app.include_router(logs_router)
app.include_router(domains_router)


@app.get("/")
def root():
    return {"name": settings.project_name, "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok"}
