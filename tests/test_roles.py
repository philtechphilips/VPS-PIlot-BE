from sqlalchemy.orm import Session

from tests.conftest import USERS, create_user, sign_in


def test_get_me(client, user_headers):
    response = client.get(f"{USERS}/me", headers=user_headers)
    assert response.status_code == 200
    assert response.json()["email"] == "alice@example.com"


def test_list_users_is_admin_only(client, user_headers, admin_headers):
    assert client.get(f"{USERS}/", headers=user_headers).status_code == 403

    response = client.get(f"{USERS}/", headers=admin_headers)
    assert response.status_code == 200
    assert {u["email"] for u in response.json()} == {
        "alice@example.com",
        "admin@example.com",
    }


def test_user_can_only_view_themselves(
    client, db: Session, user_headers, admin_headers
):
    other = create_user(db, "bob@example.com")
    me = client.get(f"{USERS}/me", headers=user_headers).json()

    assert client.get(f"{USERS}/{me['id']}", headers=user_headers).status_code == 200
    assert client.get(f"{USERS}/{other.id}", headers=user_headers).status_code == 403
    assert client.get(f"{USERS}/{other.id}", headers=admin_headers).status_code == 200


def test_admin_can_promote_user(client, db: Session, outbox, admin_headers):
    bob = create_user(db, "bob@example.com")

    response = client.patch(
        f"{USERS}/{bob.id}/role", json={"role": "admin"}, headers=admin_headers
    )
    assert response.status_code == 200
    assert response.json()["role"] == "admin"

    # The change applies straight away, without a new token
    bob_headers = sign_in(client, outbox, "bob@example.com")
    assert client.get(f"{USERS}/", headers=bob_headers).status_code == 200


def test_user_cannot_change_roles(client, db: Session, user_headers):
    bob = create_user(db, "bob@example.com")
    response = client.patch(
        f"{USERS}/{bob.id}/role", json={"role": "admin"}, headers=user_headers
    )
    assert response.status_code == 403


def test_admin_cannot_change_own_role(client, admin_headers):
    me = client.get(f"{USERS}/me", headers=admin_headers).json()
    response = client.patch(
        f"{USERS}/{me['id']}/role", json={"role": "user"}, headers=admin_headers
    )
    assert response.status_code == 400


def test_invalid_role_rejected(client, db: Session, admin_headers):
    bob = create_user(db, "bob@example.com")
    response = client.patch(
        f"{USERS}/{bob.id}/role", json={"role": "superuser"}, headers=admin_headers
    )
    assert response.status_code == 422
