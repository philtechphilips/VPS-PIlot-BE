import base64
import hashlib
import hmac
import secrets
import struct
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlencode

import jwt
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
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


# ---------------------------------------------------------------------------
# Authenticator apps (TOTP, RFC 6238)
# ---------------------------------------------------------------------------

TOTP_PERIOD = 30
TOTP_DIGITS = 6


def generate_totp_secret() -> str:
    """160-bit base32 secret, the size authenticator apps expect."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_at(secret: str, step: int) -> str:
    """The code for a given 30-second time step."""
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 10**TOTP_DIGITS:0{TOTP_DIGITS}d}"


def current_totp_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // TOTP_PERIOD)


def match_totp(secret: str, code: str, now: float | None = None) -> int | None:
    """Return the matching time step, allowing one step of clock drift either
    way, or None. Callers store the step to stop a code being replayed."""
    step = current_totp_step(now)
    for candidate in (step, step - 1, step + 1):
        if hmac.compare_digest(totp_at(secret, candidate), code):
            return candidate
    return None


def totp_uri(secret: str, account: str, issuer: str = "VPSPilot") -> str:
    """Key URI in the most widely accepted form (Google's spec, as pyotp
    writes it): a literal ":" between issuer and account, and the defaults
    (SHA1, 6 digits, 30 s) left out. Some apps, Microsoft Authenticator
    among them, are picky about the extras and an encoded separator."""
    label = f"{quote(issuer)}:{quote(account)}"
    return f"otpauth://totp/{label}?{urlencode({'secret': secret, 'issuer': issuer})}"


def _derive(master: str, purpose: str) -> Fernet:
    # Each purpose gets its own key so one kind of secret can't decrypt
    # another. The master key lives in the environment, not the database:
    # a leaked database alone doesn't reveal stored secrets.
    key = hashlib.sha256(f"vpspilot:{purpose}:{master}".encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def _masters() -> list[str]:
    """Current key first, then keys that can still decrypt (rotation)."""
    keys = [settings.encryption_key] if settings.encryption_key else []
    keys += [
        k.strip() for k in settings.encryption_keys_previous.split(",") if k.strip()
    ]
    # Installs from before ENCRYPTION_KEY encrypted with SECRET_KEY.
    keys.append(settings.secret_key)
    return list(dict.fromkeys(keys))


def _fernet(purpose: str = "totp") -> MultiFernet:
    return MultiFernet([_derive(master, purpose) for master in _masters()])


def encrypt_secret(value: str, purpose: str = "totp") -> str:
    return _fernet(purpose).encrypt(value.encode()).decode()


def decrypt_secret(token: str, purpose: str = "totp") -> str:
    return _fernet(purpose).decrypt(token.encode()).decode()


def reencrypt_secret(token: str, purpose: str = "totp") -> str:
    """Re-encrypt with the current key (no-op cost if it already is)."""
    return _fernet(purpose).rotate(token.encode()).decode()


def decrypt_or_plain(value: str | None, purpose: str) -> str | None:
    """For columns that held plain text before they were encrypted."""
    if not value:
        return value
    try:
        return decrypt_secret(value, purpose)
    except InvalidToken:
        return value


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------

_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o, 1/l/i


def generate_recovery_codes(count: int = 10) -> list[str]:
    """Codes like 'k7m2-q9xa'. Shown once; only hashes are stored."""
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def normalize_recovery_code(code: str) -> str:
    cleaned = "".join(ch for ch in code.lower() if ch.isalnum())
    return f"{cleaned[:4]}-{cleaned[4:]}" if len(cleaned) == 8 else cleaned
