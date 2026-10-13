from sqlalchemy.orm import Session

from app.auth.models import RecoveryCode
from app.core.security import current_totp_step, totp_at
from app.users.models import User
from tests.conftest import AUTH, PASSWORD, create_user, sign_in, start_login


def enable_totp(client, headers) -> tuple[str, list[str]]:
    """Run authenticator setup; returns (secret, recovery_codes)."""
    setup = client.post(f"{AUTH}/2fa/totp/setup", headers=headers)
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    code = totp_at(secret, current_totp_step())
    confirm = client.post(
        f"{AUTH}/2fa/totp/confirm", json={"code": code}, headers=headers
    )
    assert confirm.status_code == 200, confirm.text
    return secret, confirm.json()["recovery_codes"]


def next_code(secret: str) -> str:
    # The setup code used the current step; the next step is still inside the
    # allowed drift window and hasn't been used, so it isn't a replay.
    return totp_at(secret, current_totp_step() + 1)


def verify(client, challenge_id: str, code: str):
    return client.post(
        f"{AUTH}/2fa/verify", json={"challenge_id": challenge_id, "code": code}
    )


def test_setup_returns_secret_and_qr(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    headers = sign_in(client, outbox, "bob@example.com")
    body = client.post(f"{AUTH}/2fa/totp/setup", headers=headers).json()
    assert len(body["secret"]) == 32
    assert body["otpauth_uri"].startswith(
        "otpauth://totp/VPSPilot%3Abob%40example.com?"
    )
    assert body["qr_svg"].startswith("<svg")
    # Pending until confirmed: sign-in still uses email codes.
    me = client.get(f"{AUTH}/me", headers=headers).json()
    assert me["two_factor_method"] == "email"


def test_secret_is_encrypted_at_rest(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    headers = sign_in(client, outbox, "bob@example.com")
    secret = client.post(f"{AUTH}/2fa/totp/setup", headers=headers).json()["secret"]
    stored = db.query(User).one().totp_secret
    assert stored and secret not in stored


def test_confirm_rejects_wrong_code(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    headers = sign_in(client, outbox, "bob@example.com")
    secret = client.post(f"{AUTH}/2fa/totp/setup", headers=headers).json()["secret"]
    wrong = f"{(int(totp_at(secret, current_totp_step())) + 1) % 1_000_000:06d}"
    response = client.post(
        f"{AUTH}/2fa/totp/confirm", json={"code": wrong}, headers=headers
    )
    assert response.status_code == 400
    assert db.query(User).one().totp_enabled_at is None


def test_confirm_enables_and_issues_recovery_codes(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    headers = sign_in(client, outbox, "bob@example.com")
    _, codes = enable_totp(client, headers)

    assert len(codes) == 10 and all(len(c) == 9 and c[4] == "-" for c in codes)
    assert db.query(RecoveryCode).count() == 10
    me = client.get(f"{AUTH}/me", headers=headers).json()
    assert me["totp_enabled"] is True and me["two_factor_method"] == "totp"
    status = client.get(f"{AUTH}/2fa/status", headers=headers).json()
    assert status == {
        "method": "totp",
        "totp_enabled": True,
        "recovery_codes_remaining": 10,
    }


def test_setup_again_when_enabled_is_rejected(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    headers = sign_in(client, outbox, "bob@example.com")
    enable_totp(client, headers)
    assert client.post(f"{AUTH}/2fa/totp/setup", headers=headers).status_code == 409


def test_login_with_authenticator_sends_no_email(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    secret, _ = enable_totp(client, sign_in(client, outbox, "bob@example.com"))
    emails_before = len(outbox)

    body = start_login(client, "bob@example.com").json()
    assert body["method"] == "totp"
    assert len(outbox) == emails_before
    assert verify(client, body["challenge_id"], next_code(secret)).status_code == 200


def test_authenticator_code_cannot_be_replayed(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    secret, _ = enable_totp(client, sign_in(client, outbox, "bob@example.com"))
    code = next_code(secret)

    first = start_login(client, "bob@example.com").json()["challenge_id"]
    assert verify(client, first, code).status_code == 200
    second = start_login(client, "bob@example.com").json()["challenge_id"]
    assert verify(client, second, code).status_code == 400


def test_recovery_code_works_once(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    _, codes = enable_totp(client, sign_in(client, outbox, "bob@example.com"))

    first = start_login(client, "bob@example.com").json()["challenge_id"]
    # Case and dash are forgiven when typing a recovery code.
    assert verify(client, first, codes[0].upper().replace("-", "")).status_code == 200
    second = start_login(client, "bob@example.com").json()["challenge_id"]
    assert verify(client, second, codes[0]).status_code == 400
    assert db.query(RecoveryCode).filter(RecoveryCode.used_at.isnot(None)).count() == 1


def test_email_fallback_switches_challenge(client, db: Session, outbox):
    create_user(db, "bob@example.com")
    enable_totp(client, sign_in(client, outbox, "bob@example.com"))
    challenge_id = start_login(client, "bob@example.com").json()["challenge_id"]

    # No cooldown when switching from the app to email.
    switched = client.post(f"{AUTH}/2fa/resend", json={"challenge_id": challenge_id})
    assert switched.status_code == 200
    assert switched.json()["method"] == "email"
    assert verify(client, challenge_id, outbox[-1].code).status_code == 200


def test_totp_endpoints_require_sign_in(client):
    assert client.post(f"{AUTH}/2fa/totp/setup").status_code == 401
    assert (
        client.post(f"{AUTH}/2fa/totp/confirm", json={"code": "123456"}).status_code
        == 401
    )


def test_new_owner_must_finish_onboarding(client, db: Session, outbox):
    challenge = client.post(
        f"{AUTH}/setup",
        json={"name": "Ada", "email": "ada@example.com", "password": PASSWORD},
    ).json()
    auth = verify(client, challenge["challenge_id"], outbox[-1].code).json()
    headers = {"Authorization": f"Bearer {auth['access_token']}"}
    assert auth["user"]["onboarding_completed"] is False

    done = client.post(f"{AUTH}/onboarding/complete", headers=headers)
    assert done.status_code == 200
    assert done.json()["onboarding_completed"] is True
    me = client.get(f"{AUTH}/me", headers=headers).json()
    assert me["onboarding_completed"] is True
