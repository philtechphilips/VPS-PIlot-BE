from pydantic import BaseModel, EmailStr

from app.users.schemas import Password


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: Password


class MessageResponse(BaseModel):
    message: str
