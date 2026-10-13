from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, EmailStr, Field, StringConstraints

from app.users.schemas import Password, UserResponse

Code = Annotated[str, StringConstraints(pattern=r"^\d{6}$")]


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class SetupStatus(BaseModel):
    needs_setup: bool


class SetupRequest(BaseModel):
    name: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)
    ]
    email: EmailStr
    # The owner controls every server, so require a longer password.
    password: Annotated[str, Field(min_length=12, max_length=128)]


class LoginRequest(BaseModel):
    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=128)]


class ChallengeResponse(BaseModel):
    """Returned when an emailed code is needed before a session is issued."""

    status: Literal["two_factor_required"] = "two_factor_required"
    challenge_id: str
    purpose: Literal["login", "setup"]
    email_hint: str
    expires_in: int
    resend_in: int


class AuthResponse(BaseModel):
    status: Literal["authenticated"] = "authenticated"
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class VerifyRequest(BaseModel):
    challenge_id: Annotated[str, Field(min_length=32, max_length=32)]
    code: Code


class ResendRequest(BaseModel):
    challenge_id: Annotated[str, Field(min_length=32, max_length=32)]


class SessionResponse(BaseModel):
    id: str
    user_agent: str | None
    ip_address: str | None
    created_at: datetime
    last_used_at: datetime
    current: bool


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: Password


class MessageResponse(BaseModel):
    message: str
