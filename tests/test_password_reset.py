from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.auth import service
from app.auth.models import PasswordResetToken
from tests.conftest import AUTH, create_user, sign_in, start_login

GENERIC_MESSAGE = "If an account exists for that email, a reset link has been sent"


def request_token(db: Session, email: str = "bob@example.com") -> str:
    token = service.create_password_reset_token(db, email)
    assert token is not None
    return token


def reset(client, token: str, new_password: str = "new-password"):
    return client.post(
        f"{AUTH}/reset-password", json={"token": token, "new_password": new_password}
    )


def test_forgot_password_same_response_for_unknown_email(client, db: Session, outbox):
    create_user(db, "bob@example.com")

    known = client.post(f"{AUTH}/forgot-password", json={"email": "bob@example.com"})
    unknown = client.post(
        f"{AUTH}/forgot-password", json={"email": "nobody@example.com"}
    )

    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json() == {"message": GENERIC_MESSAGE}
    assert db.query(PasswordResetToken).count() == 1


def test_forgot_password_emails_reset_link(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    client.post(f"{AUTH}/forgot-password", json={"email": "bob@example.com"})

    assert len(outbox) == 1
    assert outbox[0].to == "bob@example.com"
    assert "/reset-password?token=" in outbox[0].text


def test_only_token_hash_is_stored(db: Session):
    create_user(db, "bob@example.com")
    token = request_token(db)

    stored = db.query(PasswordResetToken).one()
    assert stored.token_hash != token
    assert len(stored.token_hash) == 64


def test_reset_password(client, db: Session):
    create_user(db, "bob@example.com")
    token = request_token(db)

    assert reset(client, token).status_code == 200
    assert start_login(client, "bob@example.com").status_code == 401
    assert start_login(client, "bob@example.com", "new-password").status_code == 200


def test_reset_signs_out_every_session(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    headers = sign_in(client, outbox, "bob@example.com")

    assert reset(client, request_token(db)).status_code == 200
    assert client.get(f"{AUTH}/me", headers=headers).status_code == 401


def test_token_works_only_once(client, db: Session):
    create_user(db, "bob@example.com")
    token = request_token(db)

    assert reset(client, token).status_code == 200
    assert reset(client, token).status_code == 400


def test_new_request_invalidates_old_token(client, db: Session):
    create_user(db, "bob@example.com")
    old_token = request_token(db)
    request_token(db)

    assert reset(client, old_token).status_code == 400


def test_expired_token_rejected(client, db: Session):
    create_user(db, "bob@example.com")
    token = request_token(db)
    db.query(PasswordResetToken).update(
        {"expires_at": datetime.now(UTC) - timedelta(minutes=1)}
    )
    db.commit()

    assert reset(client, token).status_code == 400


def test_invalid_token_rejected(client):
    assert reset(client, "made-up").status_code == 400


def test_new_password_must_be_valid(client, db: Session):
    create_user(db, "bob@example.com")
    token = request_token(db)

    assert reset(client, token, "short").status_code == 422
