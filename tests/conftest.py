import os
import re
import secrets

# Settings are read at import time, so set them before importing the app.
# Real env vars take priority over .env, so tests never use your secrets
# and never send real email.
os.environ.update(
    DATABASE_HOSTNAME="localhost",
    DATABASE_PORT="5432",
    DATABASE_PASSWORD="test",
    DATABASE_NAME="test",
    DATABASE_USERNAME="test",
    SECRET_KEY=secrets.token_hex(32),
    RESEND_API_KEY="",
    EMAIL_OVERRIDE_TO="",
)

from dataclasses import dataclass  # noqa: E402
from datetime import UTC, datetime  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import StaticPool, create_engine  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402

from app.core import email as mailer  # noqa: E402
from app.core.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.notifications import service as notify_service  # noqa: E402
from app.users import service as users_service  # noqa: E402
from app.users.models import Role, User  # noqa: E402
from app.users.schemas import UserCreate  # noqa: E402

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False)

AUTH = "/api/v1/auth"
USERS = "/api/v1/users"
PASSWORD = "correct-horse-battery"


@dataclass
class SentEmail:
    to: str
    subject: str
    text: str

    @property
    def code(self) -> str:
        match = re.search(r"Code: (\d{6})", self.text)
        assert match, f"No code in email: {self.text}"
        return match.group(1)


@pytest.fixture
def outbox(monkeypatch) -> list[SentEmail]:
    """Captures every email instead of sending it."""
    sent: list[SentEmail] = []
    # Notification emails normally go out on a worker thread; run them inline.
    monkeypatch.setattr(notify_service, "_background", lambda fn, *args: fn(*args))
    monkeypatch.setattr(
        mailer,
        "send_email",
        lambda to, subject, html, text: sent.append(SentEmail(to, subject, text)),
    )
    return sent


@pytest.fixture
def db():
    Base.metadata.create_all(engine)
    with TestingSessionLocal() as session:
        yield session
    Base.metadata.drop_all(engine)


@pytest.fixture
def client(db: Session, outbox):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def create_user(
    db: Session,
    email: str,
    password: str = PASSWORD,
    role: Role = Role.USER,
    two_factor: bool = True,
) -> User:
    """Create a verified user directly (there is no public sign-up)."""
    user = users_service.create_user(
        db, UserCreate(email=email, password=password), role=role
    )
    user.email_verified_at = datetime.now(UTC)
    user.two_factor_enabled = two_factor
    db.commit()
    db.refresh(user)
    return user


def start_login(client: TestClient, email: str, password: str = PASSWORD):
    return client.post(f"{AUTH}/login", json={"email": email, "password": password})


def sign_in(
    client: TestClient, outbox: list[SentEmail], email: str, password: str = PASSWORD
) -> dict[str, str]:
    """Password + emailed code. Returns Authorization headers."""
    response = start_login(client, email, password)
    assert response.status_code == 200, response.text
    body = response.json()
    if body["status"] == "two_factor_required":
        verify = client.post(
            f"{AUTH}/2fa/verify",
            json={"challenge_id": body["challenge_id"], "code": outbox[-1].code},
        )
        assert verify.status_code == 200, verify.text
        body = verify.json()
    return {"Authorization": f"Bearer {body['access_token']}"}


@pytest.fixture
def user_headers(client: TestClient, db: Session, outbox) -> dict[str, str]:
    create_user(db, "alice@example.com")
    return sign_in(client, outbox, "alice@example.com")


@pytest.fixture
def admin_headers(client: TestClient, db: Session, outbox) -> dict[str, str]:
    create_user(db, "admin@example.com", role=Role.ADMIN)
    return sign_in(client, outbox, "admin@example.com")
