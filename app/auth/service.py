"""Authentication: owner setup, password login with lockout, emailed
two-factor codes, rotating refresh sessions and password resets."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.auth import emails
from app.auth.models import (
    AuthSession,
    PasswordResetToken,
    RecoveryCode,
    TwoFactorChallenge,
)
from app.core import crud
from app.core.config import settings
from app.core.security import (
    decrypt_secret,
    encrypt_secret,
    generate_otp,
    generate_recovery_codes,
    generate_token,
    generate_totp_secret,
    hash_otp,
    hash_password,
    hash_token,
    match_totp,
    new_id,
    normalize_recovery_code,
    otp_matches,
    totp_uri,
    verify_password,
)
from app.users import service as users_service
from app.users.models import Role, User
from app.users.schemas import UserCreate


class AuthError(Exception):
    """A user-facing authentication failure with an HTTP status."""

    def __init__(self, status_code: int, detail: str, retry_after: int | None = None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.retry_after = retry_after


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    # SQLite (tests) returns naive datetimes; Postgres returns aware ones.
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _is_expired(expires_at: datetime) -> bool:
    return _aware(expires_at) <= _now()


def mask_email(email: str) -> str:
    """pelumi@example.com -> pe••••@example.com"""
    local, _, domain = email.partition("@")
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}{'•' * max(3, len(local) - len(visible))}@{domain}"


# ---------------------------------------------------------------------------
# Owner setup
# ---------------------------------------------------------------------------


def needs_setup(db: Session) -> bool:
    return crud.count_items(db, User) == 0


def setup_owner(db: Session, name: str, email: str, password: str) -> User:
    """Create the first (owner) account. Only possible while no users exist."""
    if not needs_setup(db):
        raise AuthError(409, "Setup has already been completed")
    user = users_service.create_user(
        db, UserCreate(email=email, password=password, name=name), role=Role.ADMIN
    )
    return user


# ---------------------------------------------------------------------------
# Password login
# ---------------------------------------------------------------------------


def authenticate(db: Session, email: str, password: str) -> User | None:
    """Check a password without throttling (used internally and by tests)."""
    user = users_service.get_user_by_email(db, email)
    if user is None:
        return None

    is_valid, new_hash = verify_password(password, user.password)
    if not is_valid:
        return None
    if new_hash:
        user = crud.update(db, User, {"id": user.id}, {"password": new_hash})
    return user


def login(db: Session, email: str, password: str) -> User:
    """Check credentials with lockout after repeated failures.

    Raises AuthError(401) for bad credentials (same message for unknown
    emails) and AuthError(429) while the account is locked.
    """
    invalid = AuthError(401, "Incorrect email or password")
    user = users_service.get_user_by_email(db, email)
    if user is None:
        # Spend comparable time to a real check so timing doesn't reveal accounts.
        verify_password(password, _DUMMY_HASH)
        raise invalid

    if user.locked_until and not _is_expired(user.locked_until):
        minutes = max(
            1, int((_aware(user.locked_until) - _now()).total_seconds() // 60) + 1
        )
        unit = "minute" if minutes == 1 else "minutes"
        raise AuthError(
            429,
            f"Too many failed attempts. Try again in {minutes} {unit}.",
            retry_after=minutes * 60,
        )

    is_valid, new_hash = verify_password(password, user.password)
    if not is_valid:
        attempts = user.failed_login_attempts + 1
        if attempts >= settings.login_max_failed_attempts:
            user.failed_login_attempts = 0
            user.locked_until = _now() + timedelta(
                minutes=settings.login_lockout_minutes
            )
        else:
            user.failed_login_attempts = attempts
        db.commit()
        raise invalid

    user.failed_login_attempts = 0
    user.locked_until = None
    if new_hash:
        user.password = new_hash
    db.commit()
    db.refresh(user)
    return user


_DUMMY_HASH = hash_password("timing-equaliser-not-a-real-password")


# ---------------------------------------------------------------------------
# Two-factor challenges (emailed codes)
# ---------------------------------------------------------------------------


@dataclass
class IssuedChallenge:
    challenge: TwoFactorChallenge
    user: User


def start_challenge(
    db: Session, user: User, purpose: str, method: str = "email"
) -> TwoFactorChallenge:
    """Create a challenge. For "email" a code is generated and sent; for
    "totp" the user's authenticator app supplies it. Older pending challenges
    for the same user stop working."""
    crud.hard_delete_many(
        db, TwoFactorChallenge, {"user_id": user.id, "consumed_at": None}
    )
    challenge_id = new_id()
    now = _now()
    code = generate_otp() if method == "email" else None
    challenge = crud.create(
        db,
        TwoFactorChallenge,
        {
            "id": challenge_id,
            "user_id": user.id,
            "purpose": purpose,
            "method": method,
            "code_hash": hash_otp(challenge_id, code) if code else None,
            "expires_at": now
            + timedelta(minutes=settings.two_factor_code_expire_minutes),
            "last_sent_at": now,
        },
    )
    if code:
        emails.send_two_factor_code(user.email, code, purpose)
    return challenge


def _pending_challenge(db: Session, challenge_id: str) -> TwoFactorChallenge:
    challenge = db.get(TwoFactorChallenge, challenge_id)
    if (
        challenge is None
        or challenge.consumed_at is not None
        or _is_expired(challenge.expires_at)
    ):
        raise AuthError(400, "This code has expired. Request a new one.")
    return challenge


def resend_challenge(db: Session, challenge_id: str) -> IssuedChallenge:
    """Email a fresh code. On an authenticator challenge this is the "email me
    a code instead" fallback, and switches the challenge to email."""
    challenge = db.get(TwoFactorChallenge, challenge_id)
    if challenge is None or challenge.consumed_at is not None:
        raise AuthError(400, "This sign-in attempt is no longer valid. Start again.")

    switching = challenge.method == "totp"
    wait = settings.two_factor_resend_cooldown_seconds - int(
        (_now() - _aware(challenge.last_sent_at)).total_seconds()
    )
    if wait > 0 and not switching:
        raise AuthError(
            429,
            f"Please wait {wait}s before requesting another code.",
            retry_after=wait,
        )

    user = users_service.get_user(db, challenge.user_id)
    if user is None:
        raise AuthError(400, "This sign-in attempt is no longer valid. Start again.")

    code = generate_otp()
    now = _now()
    challenge.method = "email"
    challenge.code_hash = hash_otp(challenge.id, code)
    challenge.attempts = 0
    challenge.last_sent_at = now
    challenge.expires_at = now + timedelta(
        minutes=settings.two_factor_code_expire_minutes
    )
    db.commit()
    db.refresh(challenge)
    emails.send_two_factor_code(user.email, code, challenge.purpose)
    return IssuedChallenge(challenge, user)


def _looks_like_recovery_code(code: str) -> bool:
    return not code.isdigit()


def _use_recovery_code(db: Session, user: User, code: str) -> bool:
    hashed = hash_token(normalize_recovery_code(code))
    row = (
        db.query(RecoveryCode)
        .filter(
            RecoveryCode.user_id == user.id,
            RecoveryCode.code_hash == hashed,
            RecoveryCode.used_at.is_(None),
        )
        .first()
    )
    if row is None:
        return False
    row.used_at = _now()
    return True


def _use_totp(user: User, code: str) -> bool:
    if not user.totp_secret or not code.isdigit():
        return False
    step = match_totp(decrypt_secret(user.totp_secret), code)
    if step is None or (
        user.totp_last_step is not None and step <= user.totp_last_step
    ):
        # Wrong, or a code that was already used in this time window.
        return False
    user.totp_last_step = step
    return True


def verify_challenge(db: Session, challenge_id: str, code: str) -> User:
    """Check a code. Returns the user on success; the challenge is single-use.

    Email challenges take the emailed code. Authenticator challenges take the
    app's current code or one of the user's recovery codes.
    """
    challenge = _pending_challenge(db, challenge_id)
    if challenge.attempts >= settings.two_factor_max_attempts:
        raise AuthError(429, "Too many incorrect codes. Request a new one.")

    user = users_service.get_user(db, challenge.user_id)
    if user is None:
        raise AuthError(400, "This code has expired. Request a new one.")

    if challenge.method == "totp":
        if _looks_like_recovery_code(code):
            ok = _use_recovery_code(db, user, code)
        else:
            ok = _use_totp(user, code)
    else:
        ok = (
            code.isdigit()
            and challenge.code_hash is not None
            and otp_matches(challenge.id, code, challenge.code_hash)
        )

    if not ok:
        challenge.attempts += 1
        db.commit()
        left = settings.two_factor_max_attempts - challenge.attempts
        if left <= 0:
            raise AuthError(429, "Too many incorrect codes. Request a new one.")
        raise AuthError(
            400, f"Incorrect code. {left} attempt{'s' if left != 1 else ''} left."
        )

    challenge.consumed_at = _now()
    if user.email_verified_at is None and challenge.method == "email":
        # Reading the emailed code proves the owner controls the address.
        user.email_verified_at = _now()
    db.commit()
    db.refresh(user)
    return user


def login_method(user: User) -> str:
    """Which second factor a password login should ask for."""
    return "totp" if user.totp_enabled else "email"


# ---------------------------------------------------------------------------
# Authenticator app setup and onboarding
# ---------------------------------------------------------------------------


def begin_totp_setup(db: Session, user: User) -> tuple[str, str]:
    """Create a pending authenticator secret. Returns (secret, otpauth_uri).

    The secret only takes effect after confirm_totp, so abandoning setup
    leaves sign-in unchanged.
    """
    if user.totp_enabled:
        raise AuthError(409, "An authenticator app is already set up")
    secret = generate_totp_secret()
    user.totp_secret = encrypt_secret(secret)
    user.totp_last_step = None
    db.commit()
    return secret, totp_uri(secret, user.email)


def confirm_totp(db: Session, user: User, code: str) -> list[str]:
    """Turn on the authenticator after checking a code from it. Returns
    freshly generated recovery codes, which are shown once."""
    if user.totp_enabled:
        raise AuthError(409, "An authenticator app is already set up")
    if not user.totp_secret:
        raise AuthError(400, "Start authenticator setup first")
    if not _use_totp(user, code):
        db.commit()
        raise AuthError(
            400, "That code didn't match. Check the time on your phone and try again."
        )

    user.totp_enabled_at = _now()
    user.two_factor_enabled = True
    codes = generate_recovery_codes()
    crud.hard_delete_many(db, RecoveryCode, {"user_id": user.id})
    for recovery in codes:
        db.add(RecoveryCode(user_id=user.id, code_hash=hash_token(recovery)))
    db.commit()
    db.refresh(user)
    return codes


def remaining_recovery_codes(db: Session, user: User) -> int:
    return (
        db.query(RecoveryCode)
        .filter(RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None))
        .count()
    )


def complete_onboarding(db: Session, user: User) -> User:
    if user.email_verified_at is None:
        raise AuthError(400, "Verify your email before finishing setup")
    if user.onboarding_completed_at is None:
        user.onboarding_completed_at = _now()
        db.commit()
        db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Sessions (rotating refresh tokens)
# ---------------------------------------------------------------------------


def create_session(
    db: Session, user: User, user_agent: str | None, ip_address: str | None
) -> tuple[AuthSession, str]:
    """Return (session, refresh_token). Only the token's hash is stored."""
    token, token_hash = generate_token()
    session = crud.create(
        db,
        AuthSession,
        {
            "id": new_id(),
            "user_id": user.id,
            "refresh_token_hash": token_hash,
            "user_agent": (user_agent or "")[:255] or None,
            "ip_address": ip_address,
            "expires_at": _now() + timedelta(days=settings.refresh_token_expire_days),
        },
    )
    return session, token


def get_active_session(db: Session, session_id: str) -> AuthSession | None:
    session = db.get(AuthSession, session_id)
    if (
        session is None
        or session.revoked_at is not None
        or _is_expired(session.expires_at)
    ):
        return None
    return session


def rotate_session(db: Session, refresh_token: str) -> tuple[AuthSession, str, User]:
    """Exchange a refresh token for a new one. Raises AuthError(401) if invalid."""
    session = crud.fetch_one(
        db, AuthSession, {"refresh_token_hash": hash_token(refresh_token)}
    )
    if (
        session is None
        or session.revoked_at is not None
        or _is_expired(session.expires_at)
    ):
        raise AuthError(401, "Your session has ended. Sign in again.")
    user = users_service.get_user(db, session.user_id)
    if user is None:
        raise AuthError(401, "Your session has ended. Sign in again.")

    token, token_hash = generate_token()
    session.refresh_token_hash = token_hash
    session.last_used_at = _now()
    db.commit()
    db.refresh(session)
    return session, token, user


def revoke_session(db: Session, session: AuthSession) -> None:
    if session.revoked_at is None:
        session.revoked_at = _now()
        db.commit()


def revoke_by_refresh_token(db: Session, refresh_token: str) -> None:
    session = crud.fetch_one(
        db, AuthSession, {"refresh_token_hash": hash_token(refresh_token)}
    )
    if session is not None:
        revoke_session(db, session)


def list_sessions(db: Session, user: User) -> list[AuthSession]:
    sessions = (
        db.query(AuthSession)
        .filter(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))
        .order_by(AuthSession.last_used_at.desc())
        .all()
    )
    return [s for s in sessions if not _is_expired(s.expires_at)]


def revoke_other_sessions(db: Session, user: User, keep_session_id: str) -> int:
    count = (
        db.query(AuthSession)
        .filter(
            AuthSession.user_id == user.id,
            AuthSession.id != keep_session_id,
            AuthSession.revoked_at.is_(None),
        )
        .update({"revoked_at": _now()}, synchronize_session=False)
    )
    db.commit()
    return count


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------


def create_password_reset_token(db: Session, email: str) -> str | None:
    """Return a new reset token for the user, or None if the email is unknown.

    Any earlier unused tokens for the user stop working.
    """
    user = users_service.get_user_by_email(db, email)
    if user is None:
        return None

    token, token_hash = generate_token()
    expires_at = _now() + timedelta(
        minutes=settings.password_reset_token_expire_minutes
    )
    crud.hard_delete_many(db, PasswordResetToken, {"user_id": user.id})
    crud.create(
        db,
        PasswordResetToken,
        {"user_id": user.id, "token_hash": token_hash, "expires_at": expires_at},
    )
    return token


def reset_password(db: Session, token: str, new_password: str) -> bool:
    """Set a new password if the token is valid. Tokens work only once.

    All sessions are revoked, since a reset usually means the old password
    may be known to someone else.
    """
    reset_token = crud.fetch_one(
        db, PasswordResetToken, {"token_hash": hash_token(token)}
    )
    if reset_token is None or _is_expired(reset_token.expires_at):
        return False

    # Delete the tokens first: if the password update then fails, the user just
    # asks for a new link, and a used token can never be replayed.
    user_id = reset_token.user_id
    crud.hard_delete_many(db, PasswordResetToken, {"user_id": user_id})
    crud.update(
        db,
        User,
        {"id": user_id},
        {"password": hash_password(new_password), "failed_login_attempts": 0},
    )
    db.query(AuthSession).filter(
        AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None)
    ).update({"revoked_at": _now()}, synchronize_session=False)
    db.query(User).filter(User.id == user_id).update({"locked_until": None})
    db.commit()
    return True
