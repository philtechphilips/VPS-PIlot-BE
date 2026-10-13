from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.users.models import Role

Password = Annotated[str, Field(min_length=8, max_length=128)]


class UserCreate(BaseModel):
    email: EmailStr
    password: Password
    name: str | None = None


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    name: str | None
    role: Role
    two_factor_enabled: bool
    two_factor_method: Literal["email", "totp"] | None
    totp_enabled: bool
    email_verified: bool
    onboarding_completed: bool
    created_at: datetime


class RoleUpdate(BaseModel):
    role: Role
