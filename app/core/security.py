import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

from app.core.config import settings

# New hashes use Argon2 (the first hasher). Bcrypt is kept only so hashes
# created by the old passlib setup still verify; they get upgraded on login.
password_hash = PasswordHash((Argon2Hasher(), BcryptHasher()))


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(
    plain_password: str, hashed_password: str
) -> tuple[bool, str | None]:
    """Return (is_valid, new_hash). new_hash is set when the stored hash
    uses an outdated algorithm and should be replaced."""
    try:
        return password_hash.verify_and_update(plain_password, hashed_password)
    except ValueError:
        # bcrypt rejects passwords over 72 bytes
        return False, None


def create_access_token(
    subject: str | int,
    session_id: str | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    expire = datetime.now(UTC) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    payload: dict[str, Any] = {"sub": str(subject), "exp": expire, "type": "access"}
    if session_id is not None:
        # Ties the token to a session so revoking the session revokes the token.
        payload["sid"] = session_id
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    """Raises jwt.InvalidTokenError if the token is invalid or expired."""
    return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])


def new_id() -> str:
    """Random, unguessable identifier (32 hex chars)."""
    return uuid.uuid4().hex


def generate_token() -> tuple[str, str]:
    """Return (token, token_hash). Send the token to the user and store only
    the hash, so a leaked database can't be used to impersonate them."""
    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


# Kept for the password reset flow, which predates the generic name.
generate_reset_token = generate_token


def hash_token(token: str) -> str:
    # Tokens are long and random, so a fast hash is enough (unlike passwords).
    return hashlib.sha256(token.encode()).hexdigest()


def generate_otp() -> str:
    """Six-digit one-time code."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(challenge_id: str, code: str) -> str:
    # Keyed and bound to the challenge: a 6-digit code has little entropy, so a
    # plain hash in a leaked database would be trivial to reverse.
    message = f"{challenge_id}:{code}".encode()
    return hmac.new(settings.secret_key.encode(), message, hashlib.sha256).hexdigest()


def otp_matches(challenge_id: str, code: str, code_hash: str) -> bool:
    return hmac.compare_digest(hash_otp(challenge_id, code), code_hash)
