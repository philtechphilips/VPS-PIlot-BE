"""No secret is ever stored in plain text, and keys can be rotated."""

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.apps import service as apps
from app.apps.models import Application
from app.core.config import settings
from app.core.database import Base
from app.core.security import _derive
from app.encryption import rotate
from app.jobs.models import Job
from app.jobs.service import OUTPUT_PURPOSE
from tests.conftest import PASSWORD
from tests.test_apps import APPS, complete, git_app
from tests.test_jobs import claim
from tests.test_servers import create_enrollment, enroll
from tests.test_two_factor_app import enable_totp

SECRET_ENV = "postgres://u:hunter2-very-secret@db/x"
PLAIN_ENV = "plain-but-still-encrypted-value"
JOB_OUTPUT = "job printed sk_live_runtime_secret_123"


def seed(client, headers):
    """Create one of every kind of secret through the API."""
    totp_secret, recovery_codes = enable_totp(client, headers)
    enrollment = create_enrollment(client, headers, "vault-1")
    agent_token = enroll(client, enrollment["token"]).json()["agent_token"]
    agent = {"Authorization": f"Bearer {agent_token}"}
    body = git_app(enrollment["server"]["id"])
    body["env"] = [
        {"key": "DATABASE_URL", "value": SECRET_ENV, "secret": True},
        {"key": "GREETING", "value": PLAIN_ENV},
    ]
    assert client.post(APPS, json=body, headers=headers).status_code == 201
    job = claim(client, agent)
    complete(client, agent, job["id"])
    return {
        "password": PASSWORD,
        "totp": totp_secret,
        "recovery": recovery_codes[0],
        "enrollment": enrollment["token"],
        "agent": agent_token,
        "env secret": SECRET_ENV,
        "env plain": PLAIN_ENV,
    }, agent


def dump(db: Session) -> str:
    rows = []
    for table in Base.metadata.sorted_tables:
        for row in db.execute(select(table)):
            rows.append(json.dumps([str(v) for v in row], default=str))
    return "\n".join(rows)


def test_nothing_secret_is_stored_in_plain_text(client, admin_headers, db: Session):
    secrets, agent = seed(client, admin_headers)
    # Job output (e.g. runtime logs) can contain secrets, so it's encrypted too.
    enrollment_server = db.scalar(select(Application)).server_id
    response = client.post(
        f"/api/v1/servers/{enrollment_server}/actions",
        json={"type": "container.logs", "payload": {"container": "web"}},
        headers=admin_headers,
    )
    job = claim(client, agent)
    client.post(
        f"/agent/v1/jobs/{job['id']}/complete",
        json={"status": "succeeded", "output": JOB_OUTPUT},
        headers=agent,
    )
    secrets["job output"] = JOB_OUTPUT
    assert response.status_code == 202

    everything = dump(db)
    leaked = [name for name, value in secrets.items() if value in everything]
    assert leaked == [], f"stored in plain text: {leaked}"

    # ...but they are all still usable.
    detail = client.get(f"/api/v1/jobs/{job['id']}", headers=admin_headers).json()
    assert detail["output"] == JOB_OUTPUT
    app = db.scalar(select(Application))
    assert apps.env_values(app)["DATABASE_URL"] == SECRET_ENV


def test_key_rotation(client, admin_headers, db: Session, monkeypatch):
    seed(client, admin_headers)
    old_key = settings.secret_key  # installs without ENCRYPTION_KEY used this
    monkeypatch.setattr(settings, "encryption_key", "brand-new-encryption-key")
    # Old data still decrypts through the fallback key.
    app = db.scalar(select(Application))
    assert apps.env_values(app)["DATABASE_URL"] == SECRET_ENV

    counts = rotate(db)
    assert counts["env"] == 2 and counts["totp"] == 1 and counts["job_output"] >= 1

    # Afterwards only the new key is needed.
    new_only = _derive("brand-new-encryption-key", apps.ENV_PURPOSE)
    db.refresh(app)
    secret = next(e for e in app.env if e["key"] == "DATABASE_URL")
    assert new_only.decrypt(secret["value"].encode()).decode() == SECRET_ENV
    old_only = _derive(old_key, apps.ENV_PURPOSE)
    try:
        old_only.decrypt(secret["value"].encode())
        raise AssertionError("still readable with the old key")
    except Exception as error:  # noqa: BLE001
        assert type(error).__name__ == "InvalidToken"
    job = db.scalar(select(Job).where(Job.output.is_not(None)))
    if job:
        _derive("brand-new-encryption-key", OUTPUT_PURPOSE).decrypt(job.output.encode())
