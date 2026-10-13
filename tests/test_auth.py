from datetime import UTC, datetime, timedelta

import bcrypt
from sqlalchemy.orm import Session

from app.auth.models import AuthSession, TwoFactorChallenge
from app.core.config import settings
from app.core.security import create_access_token
from app.users.models import Role, User
from tests.conftest import AUTH, PASSWORD, USERS, create_user, sign_in, start_login

OWNER = {"name": "Ada Lovelace", "email": "ada@example.com", "password": PASSWORD}


def verify(client, challenge_id: str, code: str):
    return client.post(
        f"{AUTH}/2fa/verify", json={"challenge_id": challenge_id, "code": code}
    )


def wrong_code(code: str) -> str:
    return f"{(int(code) + 1) % 1_000_000:06d}"


# ---------------------------------------------------------------------------
# Owner setup
# ---------------------------------------------------------------------------


def test_setup_status_before_and_after(client, outbox):
    assert client.get(f"{AUTH}/setup-status").json() == {"needs_setup": True}
    assert client.post(f"{AUTH}/setup", json=OWNER).status_code == 201
    assert client.get(f"{AUTH}/setup-status").json() == {"needs_setup": False}


def test_setup_creates_admin_and_emails_code(client, db: Session, outbox):
    response = client.post(f"{AUTH}/setup", json=OWNER)
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "two_factor_required"
    assert body["purpose"] == "setup"
    assert body["email_hint"] == "ad•••@example.com"

    owner = db.query(User).one()
    assert owner.role == Role.ADMIN
    assert owner.name == "Ada Lovelace"
    assert owner.email_verified_at is None
    assert len(outbox) == 1 and outbox[0].to == "ada@example.com"


def test_setup_only_once(client, outbox):
    client.post(f"{AUTH}/setup", json=OWNER)
    second = client.post(f"{AUTH}/setup", json={**OWNER, "email": "eve@example.com"})
    assert second.status_code == 409


def test_setup_requires_long_password(client, outbox):
    response = client.post(f"{AUTH}/setup", json={**OWNER, "password": "short-pass"})
    assert response.status_code == 422


def test_setup_code_verifies_email_and_signs_in(client, db: Session, outbox):
    challenge = client.post(f"{AUTH}/setup", json=OWNER).json()
    response = verify(client, challenge["challenge_id"], outbox[-1].code)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "authenticated"
    assert body["user"]["email_verified"] is True
    assert settings.refresh_cookie_name in response.cookies


# ---------------------------------------------------------------------------
# Login and two-factor
# ---------------------------------------------------------------------------


def test_login_requires_emailed_code(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    response = start_login(client, "bob@example.com")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "two_factor_required"
    assert "access_token" not in body
    assert outbox[-1].to == "bob@example.com"

    signed_in = verify(client, body["challenge_id"], outbox[-1].code)
    assert signed_in.status_code == 200
    me = client.get(
        f"{AUTH}/me",
        headers={"Authorization": f"Bearer {signed_in.json()['access_token']}"},
    )
    assert me.json()["email"] == "bob@example.com"


def test_code_is_not_stored_in_plain_text(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    start_login(client, "bob@example.com")
    stored = db.query(TwoFactorChallenge).one()
    assert outbox[-1].code not in stored.code_hash


def test_wrong_password_and_unknown_email_look_the_same(client, db: Session):
    create_user(db, "bob@example.com")
    wrong = start_login(client, "bob@example.com", "wrong-password")
    unknown = start_login(client, "nobody@example.com")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_wrong_code_counts_attempts_then_locks_challenge(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    challenge_id = start_login(client, "bob@example.com").json()["challenge_id"]
    bad = wrong_code(outbox[-1].code)

    first = verify(client, challenge_id, bad)
    assert first.status_code == 400
    assert "4 attempts left" in first.json()["detail"]
    for _ in range(settings.two_factor_max_attempts - 1):
        last = verify(client, challenge_id, bad)
    assert last.status_code == 429
    # Even the right code no longer works on an exhausted challenge.
    assert verify(client, challenge_id, outbox[-1].code).status_code == 429


def test_code_works_once(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    challenge_id = start_login(client, "bob@example.com").json()["challenge_id"]
    code = outbox[-1].code
    assert verify(client, challenge_id, code).status_code == 200
    assert verify(client, challenge_id, code).status_code == 400


def test_expired_code_rejected(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    challenge_id = start_login(client, "bob@example.com").json()["challenge_id"]
    db.query(TwoFactorChallenge).update(
        {"expires_at": datetime.now(UTC) - timedelta(seconds=1)}
    )
    db.commit()
    assert verify(client, challenge_id, outbox[-1].code).status_code == 400


def test_new_login_invalidates_previous_challenge(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    old = start_login(client, "bob@example.com").json()["challenge_id"]
    old_code = outbox[-1].code
    start_login(client, "bob@example.com")
    assert verify(client, old, old_code).status_code == 400


def test_resend_has_cooldown_and_replaces_code(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    challenge_id = start_login(client, "bob@example.com").json()["challenge_id"]
    first_code = outbox[-1].code

    too_soon = client.post(f"{AUTH}/2fa/resend", json={"challenge_id": challenge_id})
    assert too_soon.status_code == 429
    assert "Retry-After" in too_soon.headers

    db.query(TwoFactorChallenge).update(
        {"last_sent_at": datetime.now(UTC) - timedelta(minutes=1)}
    )
    db.commit()
    resent = client.post(f"{AUTH}/2fa/resend", json={"challenge_id": challenge_id})
    assert resent.status_code == 200
    assert len(outbox) == 2

    if outbox[-1].code != first_code:
        assert verify(client, challenge_id, first_code).status_code == 400
    assert verify(client, challenge_id, outbox[-1].code).status_code == 200


def test_account_locks_after_repeated_wrong_passwords(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    for _ in range(settings.login_max_failed_attempts):
        assert start_login(client, "bob@example.com", "wrong").status_code == 401

    locked = start_login(client, "bob@example.com")
    assert locked.status_code == 429
    assert "Too many failed attempts" in locked.json()["detail"]

    db.query(User).update({"locked_until": datetime.now(UTC) - timedelta(seconds=1)})
    db.commit()
    assert start_login(client, "bob@example.com").status_code == 200


def test_user_without_two_factor_gets_session_directly(client, db: Session):
    create_user(db, "bob@example.com", two_factor=False)
    body = start_login(client, "bob@example.com").json()
    assert body["status"] == "authenticated"
    assert body["access_token"]


def test_unverified_owner_must_confirm_email_on_login(client, db: Session, outbox):
    client.post(f"{AUTH}/setup", json=OWNER)
    db.query(User).update({"two_factor_enabled": False})
    db.commit()
    body = start_login(client, OWNER["email"]).json()
    assert body["status"] == "two_factor_required"
    assert body["purpose"] == "setup"


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


def test_refresh_rotates_cookie(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    sign_in(client, outbox, "bob@example.com")
    old_cookie = client.cookies.get(settings.refresh_cookie_name)

    refreshed = client.post(f"{AUTH}/refresh")
    assert refreshed.status_code == 200
    new_cookie = client.cookies.get(settings.refresh_cookie_name)
    assert new_cookie and new_cookie != old_cookie

    # The old refresh token is dead after rotation.
    client.cookies.set(settings.refresh_cookie_name, old_cookie, path=AUTH)
    assert client.post(f"{AUTH}/refresh").status_code == 401


def test_refresh_without_cookie(client):
    assert client.post(f"{AUTH}/refresh").status_code == 401


def test_logout_revokes_access_and_refresh(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    headers = sign_in(client, outbox, "bob@example.com")
    cookie = client.cookies.get(settings.refresh_cookie_name)

    assert client.post(f"{AUTH}/logout").status_code == 204
    assert client.get(f"{AUTH}/me", headers=headers).status_code == 401
    client.cookies.set(settings.refresh_cookie_name, cookie, path=AUTH)
    assert client.post(f"{AUTH}/refresh").status_code == 401


def test_list_and_revoke_sessions(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    first = sign_in(client, outbox, "bob@example.com")
    second = sign_in(client, outbox, "bob@example.com")

    sessions = client.get(f"{AUTH}/sessions", headers=second).json()
    assert len(sessions) == 2
    current = [s for s in sessions if s["current"]]
    other = [s for s in sessions if not s["current"]]
    assert len(current) == len(other) == 1

    assert (
        client.delete(f"{AUTH}/sessions/{other[0]['id']}", headers=second).status_code
        == 204
    )
    assert client.get(f"{AUTH}/me", headers=first).status_code == 401
    assert client.get(f"{AUTH}/me", headers=second).status_code == 200


def test_revoke_other_sessions(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    first = sign_in(client, outbox, "bob@example.com")
    second = sign_in(client, outbox, "bob@example.com")
    response = client.post(f"{AUTH}/sessions/revoke-others", headers=second)
    assert response.json()["message"] == "Signed out of 1 other session"
    assert client.get(f"{AUTH}/me", headers=first).status_code == 401
    assert db.query(AuthSession).filter(AuthSession.revoked_at.is_(None)).count() == 1


def test_cannot_revoke_someone_elses_session(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    create_user(db, "eve@example.com")
    sign_in(client, outbox, "bob@example.com")
    bob_session = db.query(AuthSession).one()
    eve = sign_in(client, outbox, "eve@example.com")
    assert (
        client.delete(f"{AUTH}/sessions/{bob_session.id}", headers=eve).status_code
        == 404
    )


# ---------------------------------------------------------------------------
# Tokens and passwords
# ---------------------------------------------------------------------------


def test_protected_route_requires_token(client):
    assert client.get(f"{AUTH}/me").status_code == 401


def test_invalid_token_rejected(client):
    response = client.get(f"{AUTH}/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert response.status_code == 401


def test_token_without_session_rejected(client, db: Session):
    user = create_user(db, "bob@example.com")
    token = create_access_token(user.id)  # no session id
    response = client.get(f"{AUTH}/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_password_stored_as_argon2(db: Session):
    user = create_user(db, "bob@example.com")
    assert user.password.startswith("$argon2id$")


def test_legacy_bcrypt_hash_logs_in_and_is_upgraded(client, db: Session, outbox):
    legacy_hash = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt()).decode()
    db.add(
        User(
            email="old@example.com",
            password=legacy_hash,
            email_verified_at=datetime.now(UTC),
        )
    )
    db.commit()

    sign_in(client, outbox, "old@example.com")

    user = db.query(User).filter_by(email="old@example.com").one()
    assert user.password.startswith("$argon2id$")


def test_public_signup_is_disabled(client):
    response = client.post(
        f"{USERS}/", json={"email": "x@example.com", "password": PASSWORD}
    )
    assert response.status_code == 405
