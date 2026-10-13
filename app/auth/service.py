from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.auth.models import PasswordResetToken
from app.core import crud
from app.core.config import settings
from app.core.security import (
    generate_reset_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.users import service as users_service
from app.users.models import User


def authenticate(db: Session, email: str, password: str) -> User | None:
    user = users_service.get_user_by_email(db, email)
    if user is None:
        return None

    is_valid, new_hash = verify_password(password, user.password)
    if not is_valid:
        return None
    if new_hash:
        user = crud.update(db, User, {"id": user.id}, {"password": new_hash})
    return user


def create_password_reset_token(db: Session, email: str) -> str | None:
    """Return a new reset token for the user, or None if the email is unknown.

    Any earlier unused tokens for the user stop working.
    """
    user = users_service.get_user_by_email(db, email)
    if user is None:
        return None

    token, token_hash = generate_reset_token()
    expires_at = datetime.now(UTC) + timedelta(
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
    """Set a new password if the token is valid. Tokens work only once."""
    reset_token = crud.fetch_one(
        db, PasswordResetToken, {"token_hash": hash_token(token)}
    )
    if reset_token is None or _is_expired(reset_token.expires_at):
        return False

    # Delete the tokens first: if the password update then fails, the user just
    # asks for a new link, and a used token can never be replayed.
    user_id = reset_token.user_id
    crud.hard_delete_many(db, PasswordResetToken, {"user_id": user_id})
    crud.update(db, User, {"id": user_id}, {"password": hash_password(new_password)})
    return True


def _is_expired(expires_at: datetime) -> bool:
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at <= datetime.now(UTC)
