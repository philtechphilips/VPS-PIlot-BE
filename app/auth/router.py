from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.auth import service
from app.auth.schemas import (
    ForgotPasswordRequest,
    MessageResponse,
    ResetPasswordRequest,
    Token,
)
from app.core.config import settings
from app.core.database import DbSession
from app.core.security import create_access_token

router = APIRouter(tags=["Authentication"])


@router.post("/login", response_model=Token)
def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: DbSession):
    user = service.authenticate(db, form_data.username, form_data.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Token(access_token=create_access_token(user.id))


@router.post("/forgot-password", response_model=MessageResponse)
def forgot_password(body: ForgotPasswordRequest, db: DbSession):
    token = service.create_password_reset_token(db, body.email)
    if token is not None:
        reset_link = f"{settings.frontend_url}/reset-password?token={token}"  # noqa: F841
        # TODO: send the password reset email to body.email with reset_link here
        # (e.g. background_tasks.add_task(send_reset_email, body.email, reset_link))

    # Same response whether or not the email exists, so this endpoint can't
    # be used to find out who has an account.
    return MessageResponse(
        message="If an account exists for that email, a reset link has been sent"
    )


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(body: ResetPasswordRequest, db: DbSession):
    if not service.reset_password(db, body.token, body.new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )
    return MessageResponse(message="Password has been reset")
