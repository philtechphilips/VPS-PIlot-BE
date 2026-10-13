from tests.conftest import auth_headers, create_user


def test_new_users_get_user_role(client):
    assert create_user(client, "bob@example.com")["role"] == "user"


def test_signup_cannot_choose_role(client):
    response = client.post(
        "/users/",
        json={"email": "bob@example.com", "password": "password123", "role": "admin"},
    )
    assert response.json()["role"] == "user"


def test_get_me(client, user_headers):
    response = client.get("/users/me", headers=user_headers)
    assert response.status_code == 200
    assert response.json()["email"] == "alice@example.com"


def test_list_users_is_admin_only(client, user_headers, admin_headers):
    assert client.get("/users/", headers=user_headers).status_code == 403

    response = client.get("/users/", headers=admin_headers)
    assert response.status_code == 200
    assert {u["email"] for u in response.json()} == {
        "alice@example.com",
        "admin@example.com",
    }


def test_user_can_only_view_themselves(client, user_headers, admin_headers):
    other = create_user(client, "bob@example.com")
    me = client.get("/users/me", headers=user_headers).json()

    assert client.get(f"/users/{me['id']}", headers=user_headers).status_code == 200
    assert client.get(f"/users/{other['id']}", headers=user_headers).status_code == 403
    assert client.get(f"/users/{other['id']}", headers=admin_headers).status_code == 200


def test_admin_can_promote_user(client, admin_headers):
    bob = create_user(client, "bob@example.com")

    response = client.patch(
        f"/users/{bob['id']}/role", json={"role": "admin"}, headers=admin_headers
    )
    assert response.status_code == 200
    assert response.json()["role"] == "admin"

    # The change applies straight away, without a new token
    bob_headers = auth_headers(client, "bob@example.com")
    assert client.get("/users/", headers=bob_headers).status_code == 200


def test_user_cannot_change_roles(client, user_headers):
    bob = create_user(client, "bob@example.com")
    response = client.patch(
        f"/users/{bob['id']}/role", json={"role": "admin"}, headers=user_headers
    )
    assert response.status_code == 403


def test_admin_cannot_change_own_role(client, admin_headers):
    me = client.get("/users/me", headers=admin_headers).json()
    response = client.patch(
        f"/users/{me['id']}/role", json={"role": "user"}, headers=admin_headers
    )
    assert response.status_code == 400


def test_invalid_role_rejected(client, admin_headers):
    bob = create_user(client, "bob@example.com")
    response = client.patch(
        f"/users/{bob['id']}/role", json={"role": "superuser"}, headers=admin_headers
    )
    assert response.status_code == 422
