from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.auth import service
from app.auth.models import PasswordResetToken
from tests.conftest import create_user

GENERIC_MESSAGE = "If an account exists for that email, a reset link has been sent"


def request_token(db: Session, email: str = "bob@example.com") -> str:
    token = service.create_password_reset_token(db, email)
    assert token is not None
    return token


def login(client, password: str) -> int:
    return client.post(
        "/login", data={"username": "bob@example.com", "password": password}
    ).status_code


def test_forgot_password_same_response_for_unknown_email(client, db: Session):
    create_user(client, "bob@example.com")

    known = client.post("/forgot-password", json={"email": "bob@example.com"})
    unknown = client.post("/forgot-password", json={"email": "nobody@example.com"})

    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json() == {"message": GENERIC_MESSAGE}
    assert db.query(PasswordResetToken).count() == 1


def test_only_token_hash_is_stored(client, db: Session):
    create_user(client, "bob@example.com")
    token = request_token(db)

    stored = db.query(PasswordResetToken).one()
    assert stored.token_hash != token
    assert len(stored.token_hash) == 64


def test_reset_password(client, db: Session):
    create_user(client, "bob@example.com")
    token = request_token(db)

    response = client.post(
        "/reset-password", json={"token": token, "new_password": "new-password"}
    )
    assert response.status_code == 200
    assert login(client, "password123") == 401
    assert login(client, "new-password") == 200


def test_token_works_only_once(client, db: Session):
    create_user(client, "bob@example.com")
    token = request_token(db)
    body = {"token": token, "new_password": "new-password"}

    assert client.post("/reset-password", json=body).status_code == 200
    assert client.post("/reset-password", json=body).status_code == 400


def test_new_request_invalidates_old_token(client, db: Session):
    create_user(client, "bob@example.com")
    old_token = request_token(db)
    request_token(db)

    response = client.post(
        "/reset-password", json={"token": old_token, "new_password": "new-password"}
    )
    assert response.status_code == 400


def test_expired_token_rejected(client, db: Session):
    create_user(client, "bob@example.com")
    token = request_token(db)
    db.query(PasswordResetToken).update(
        {"expires_at": datetime.now(UTC) - timedelta(minutes=1)}
    )
    db.commit()

    response = client.post(
        "/reset-password", json={"token": token, "new_password": "new-password"}
    )
    assert response.status_code == 400


def test_invalid_token_rejected(client):
    response = client.post(
        "/reset-password", json={"token": "made-up", "new_password": "new-password"}
    )
    assert response.status_code == 400


def test_new_password_must_be_valid(client, db: Session):
    create_user(client, "bob@example.com")
    token = request_token(db)

    response = client.post(
        "/reset-password", json={"token": token, "new_password": "short"}
    )
    assert response.status_code == 422
