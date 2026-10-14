"""Endpoints the agent calls. Agents only ever connect out to the control
plane; nothing here requires an inbound port on the managed server."""

import io
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.database import DbSession
from app.servers import service
from app.servers.models import Server
from app.servers.schemas import (
    AgentConfig,
    EnrollRequest,
    EnrollResponse,
    HeartbeatRequest,
    InventoryRequest,
    MetricsRequest,
)

router = APIRouter(prefix="/agent", tags=["Agent"])

AGENT_DIR = Path(__file__).resolve().parents[2] / "agent"
bearer = HTTPBearer(auto_error=False)


def current_agent(
    db: DbSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Server:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing agent token")
    server = service.authenticate_agent(db, credentials.credentials)
    if server is None:
        # Revoked or unknown: the agent should stop and ask to be re-enrolled.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent is not enrolled")
    return server


Agent = Annotated[Server, Depends(current_agent)]


def _config() -> AgentConfig:
    return AgentConfig(
        heartbeat_seconds=settings.agent_heartbeat_seconds,
        metrics_seconds=settings.agent_metrics_seconds,
        server_time=datetime.now(UTC),
    )


@router.post("/v1/enroll", response_model=EnrollResponse)
def enroll(body: EnrollRequest, db: DbSession):
    """Redeem a single-use enrollment token for a per-agent credential."""
    try:
        server, agent_token = service.enroll(
            db, body.token, body.facts.model_dump(exclude_none=True)
        )
    except service.ServerError as error:
        raise HTTPException(error.status_code, error.detail) from None
    return EnrollResponse(
        server_id=server.id,
        server_name=server.name,
        agent_token=agent_token,
        heartbeat_seconds=settings.agent_heartbeat_seconds,
        metrics_seconds=settings.agent_metrics_seconds,
    )


@router.post("/v1/heartbeat", response_model=AgentConfig)
def heartbeat(body: HeartbeatRequest, agent: Agent, db: DbSession):
    service.heartbeat(db, agent, body.facts.model_dump(exclude_none=True))
    return _config()


@router.post("/v1/metrics", status_code=status.HTTP_202_ACCEPTED)
def metrics(body: MetricsRequest, agent: Agent, db: DbSession):
    stored = service.store_metrics(db, agent, [s.model_dump() for s in body.samples])
    return {"stored": stored}


@router.post("/v1/inventory", status_code=status.HTTP_202_ACCEPTED)
def inventory(body: InventoryRequest, agent: Agent, db: DbSession):
    service.store_inventory(db, agent, body.model_dump())
    return {"ok": True}


# ---------------------------------------------------------------------------
# Installer
# ---------------------------------------------------------------------------

# The installer lives next to this file so it can be read and linted as shell.
INSTALL_SCRIPT = (Path(__file__).parent / "install.sh").read_text()


@router.get("/install.sh", response_class=PlainTextResponse)
def install_script():
    """The one-line installer referenced by enrollment commands."""
    return PlainTextResponse(
        INSTALL_SCRIPT.replace("__API_URL__", settings.agent_api_url.rstrip("/")),
        media_type="text/x-shellscript",
    )


def build_agent_package() -> bytes:
    """tar.gz of the agent's Python package (no compiled files)."""
    buffer = io.BytesIO()
    package = AGENT_DIR / "vpspilot_agent"
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path in sorted(package.rglob("*.py")):
            tar.add(path, arcname=str(path.relative_to(AGENT_DIR)))
    return buffer.getvalue()


@router.get("/package.tar.gz")
def agent_package():
    return Response(
        build_agent_package(),
        media_type="application/gzip",
        headers={"Content-Disposition": 'attachment; filename="vpspilot-agent.tar.gz"'},
    )
