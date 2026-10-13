import bcrypt
from sqlalchemy.orm import Session

from app.users.models import User
from tests.conftest import auth_headers, create_user


def test_create_user(client):
    user = create_user(client, "bob@example.com")
    assert user["email"] == "bob@example.com"
    assert "password" not in user


def test_create_user_duplicate_email(client):
    create_user(client, "bob@example.com")
    response = client.post(
        "/users/", json={"email": "bob@example.com", "password": "password123"}
    )
    assert response.status_code == 409


def test_create_user_short_password(client):
    response = client.post(
        "/users/", json={"email": "bob@example.com", "password": "short"}
    )
    assert response.status_code == 422


def test_password_stored_as_argon2(client, db: Session):
    create_user(client, "bob@example.com")
    user = db.query(User).filter_by(email="bob@example.com").one()
    assert user.password.startswith("$argon2id$")


def test_login_wrong_password(client):
    create_user(client, "bob@example.com")
    response = client.post(
        "/login", data={"username": "bob@example.com", "password": "wrong-password"}
    )
    assert response.status_code == 401


def test_login_unknown_email(client):
    response = client.post(
        "/login", data={"username": "nobody@example.com", "password": "password123"}
    )
    assert response.status_code == 401


def test_legacy_bcrypt_hash_logs_in_and_is_upgraded(client, db: Session):
    legacy_hash = bcrypt.hashpw(b"password123", bcrypt.gensalt()).decode()
    db.add(User(email="old@example.com", password=legacy_hash))
    db.commit()

    auth_headers(client, "old@example.com")

    user = db.query(User).filter_by(email="old@example.com").one()
    assert user.password.startswith("$argon2id$")


def test_protected_route_requires_token(client):
    assert client.get("/users/me").status_code == 401


def test_invalid_token_rejected(client):
    response = client.get("/users/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert response.status_code == 401
