import os
import secrets

# Settings are read at import time, so set them before importing the app.
# Real env vars take priority over .env, so tests never use your secrets.
os.environ.update(
    DATABASE_HOSTNAME="localhost",
    DATABASE_PORT="5432",
    DATABASE_PASSWORD="test",
    DATABASE_NAME="test",
    DATABASE_USERNAME="test",
    SECRET_KEY=secrets.token_hex(32),
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import StaticPool, create_engine  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402

from app.core.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.users.models import Role, User  # noqa: E402

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False)


@pytest.fixture
def db():
    Base.metadata.create_all(engine)
    with TestingSessionLocal() as session:
        yield session
    Base.metadata.drop_all(engine)


@pytest.fixture
def client(db: Session):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def create_user(client: TestClient, email: str, password: str = "password123"):
    response = client.post("/users/", json={"email": email, "password": password})
    assert response.status_code == 201, response.text
    return response.json()


def auth_headers(
    client: TestClient, email: str, password: str = "password123"
) -> dict[str, str]:
    response = client.post("/login", data={"username": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def user_headers(client: TestClient) -> dict[str, str]:
    create_user(client, "alice@example.com")
    return auth_headers(client, "alice@example.com")


@pytest.fixture
def admin_headers(client: TestClient, db: Session) -> dict[str, str]:
    create_user(client, "admin@example.com")
    db.query(User).filter_by(email="admin@example.com").update({"role": Role.ADMIN})
    db.commit()
    return auth_headers(client, "admin@example.com")
