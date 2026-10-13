from typing import Annotated, NoReturn

import segno
from fastapi import APIRouter, Cookie, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from app.auth import emails, service
from app.auth.dependencies import CurrentSessionId, CurrentUser
from app.auth.models import TwoFactorChallenge
from app.auth.schemas import (
    AuthResponse,
    ChallengeResponse,
    CodeRequest,
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    RecoveryCodesResponse,
    ResendRequest,
    ResetPasswordRequest,
    SessionResponse,
    SetupRequest,
    SetupStatus,
    TotpSetupResponse,
    TwoFactorStatus,
    VerifyRequest,
)
from app.core.config import settings
from app.core.database import DbSession
from app.core.email import EmailDeliveryError
from app.core.security import create_access_token
from app.users.models import User
from app.users.schemas import UserResponse

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

REFRESH_COOKIE_PATH = "/api/v1/auth"
RefreshCookie = Annotated[str | None, Cookie(alias=settings.refresh_cookie_name)]

EMAIL_FAILED = HTTPException(
    status_code=status.HTTP_502_BAD_GATEWAY,
    detail="We couldn't send the verification email. Try again in a moment.",
)


def _raise(error: service.AuthError) -> NoReturn:
    headers = {"Retry-After": str(error.retry_after)} if error.retry_after else None
    raise HTTPException(
        status_code=error.status_code, detail=error.detail, headers=headers
    )


def _client_ip(request: Request) -> str | None:
    # Behind the control plane's reverse proxy the real client is in X-Forwarded-For.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:45]
    return request.client.host if request.client else None


def _challenge_response(challenge: TwoFactorChallenge, user: User) -> ChallengeResponse:
    return ChallengeResponse(
        challenge_id=challenge.id,
        purpose=challenge.purpose,  # type: ignore[arg-type]
        method=challenge.method,  # type: ignore[arg-type]
        email_hint=service.mask_email(user.email),
        expires_in=settings.two_factor_code_expire_minutes * 60,
        resend_in=settings.two_factor_resend_cooldown_seconds,
    )


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=token,
        max_age=settings.refresh_token_expire_days * 24 * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path=REFRESH_COOKIE_PATH,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path=REFRESH_COOKIE_PATH,
    )


def _auth_response(user: User, session_id: str) -> AuthResponse:
    return AuthResponse(
        access_token=create_access_token(user.id, session_id),
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserResponse.model_validate(user),
    )


# ---------------------------------------------------------------------------
# Owner setup
# ---------------------------------------------------------------------------


@router.get("/setup-status", response_model=SetupStatus)
def setup_status(db: DbSession):
    """Whether the control plane still needs its owner account."""
    return SetupStatus(needs_setup=service.needs_setup(db))


@router.post(
    "/setup", response_model=ChallengeResponse, status_code=status.HTTP_201_CREATED
)
def setup(body: SetupRequest, db: DbSession):
    """Create the owner account and email a code to verify the address."""
    try:
        user = service.setup_owner(db, body.name, body.email, body.password)
        challenge = service.start_challenge(db, user, "setup")
    except service.AuthError as error:
        _raise(error)
    except EmailDeliveryError:
        raise EMAIL_FAILED from None
    return _challenge_response(challenge, user)


# ---------------------------------------------------------------------------
# Login with emailed two-factor code
# ---------------------------------------------------------------------------


@router.post(
    "/login",
    response_model=ChallengeResponse | AuthResponse,
    responses={200: {"description": "A code was emailed, or the user is signed in"}},
)
def login(body: LoginRequest, request: Request, response: Response, db: DbSession):
    """Check the password. Usually returns a challenge and emails a code;
    accounts without two-factor get a session straight away."""
    try:
        user = service.login(db, body.email, body.password)
    except service.AuthError as error:
        _raise(error)

    if user.two_factor_enabled or user.email_verified_at is None:
        if user.email_verified_at is None:
            # Owner never finished verifying the address: do that first.
            purpose, method = "setup", "email"
        else:
            purpose, method = "login", service.login_method(user)
        try:
            challenge = service.start_challenge(db, user, purpose, method)
        except EmailDeliveryError:
            raise EMAIL_FAILED from None
        return _challenge_response(challenge, user)

    session, refresh_token = service.create_session(
        db, user, request.headers.get("user-agent"), _client_ip(request)
    )
    _set_refresh_cookie(response, refresh_token)
    return _auth_response(user, session.id)


@router.post("/2fa/verify", response_model=AuthResponse)
def verify_two_factor(
    body: VerifyRequest, request: Request, response: Response, db: DbSession
):
    """Exchange an emailed code for a session."""
    try:
        user = service.verify_challenge(db, body.challenge_id, body.code)
    except service.AuthError as error:
        _raise(error)

    session, refresh_token = service.create_session(
        db, user, request.headers.get("user-agent"), _client_ip(request)
    )
    _set_refresh_cookie(response, refresh_token)
    return _auth_response(user, session.id)


@router.post("/2fa/resend", response_model=ChallengeResponse)
def resend_two_factor(body: ResendRequest, db: DbSession):
    try:
        issued = service.resend_challenge(db, body.challenge_id)
    except service.AuthError as error:
        _raise(error)
    except EmailDeliveryError:
        raise EMAIL_FAILED from None
    return _challenge_response(issued.challenge, issued.user)


# ---------------------------------------------------------------------------
# Authenticator app, recovery codes and onboarding
# ---------------------------------------------------------------------------


@router.get("/2fa/status", response_model=TwoFactorStatus)
def two_factor_status(current_user: CurrentUser, db: DbSession):
    return TwoFactorStatus(
        method=current_user.two_factor_method,  # type: ignore[arg-type]
        totp_enabled=current_user.totp_enabled,
        recovery_codes_remaining=service.remaining_recovery_codes(db, current_user),
    )


@router.post("/2fa/totp/setup", response_model=TotpSetupResponse)
def totp_setup(current_user: CurrentUser, db: DbSession):
    """Start authenticator setup: returns the secret and a QR code to scan."""
    try:
        secret, uri = service.begin_totp_setup(db, current_user)
    except service.AuthError as error:
        _raise(error)
    # Dark modules on white (many scanners can't read inverted codes), the
    # standard 4-module quiet zone, and a viewBox instead of a fixed size so
    # the browser scales the code rather than cropping it.
    qr_svg = segno.make(uri, error="m").svg_inline(
        border=4, omitsize=True, dark="#000000", light="#ffffff"
    )
    return TotpSetupResponse(secret=secret, otpauth_uri=uri, qr_svg=qr_svg)


@router.post("/2fa/totp/confirm", response_model=RecoveryCodesResponse)
def totp_confirm(body: CodeRequest, current_user: CurrentUser, db: DbSession):
    """Turn on the authenticator with a code from it. Returns recovery codes,
    which are only ever shown here."""
    try:
        codes = service.confirm_totp(db, current_user, body.code)
    except service.AuthError as error:
        _raise(error)
    return RecoveryCodesResponse(recovery_codes=codes)


@router.post("/onboarding/complete", response_model=UserResponse)
def onboarding_complete(current_user: CurrentUser, db: DbSession):
    try:
        return service.complete_onboarding(db, current_user)
    except service.AuthError as error:
        _raise(error)


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------


@router.post("/refresh", response_model=AuthResponse)
def refresh(response: Response, db: DbSession, refresh_token: RefreshCookie = None):
    """Rotate the refresh cookie and return a fresh access token."""
    if not refresh_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")
    try:
        session, new_token, user = service.rotate_session(db, refresh_token)
    except service.AuthError as error:
        failed = JSONResponse(
            status_code=error.status_code, content={"detail": error.detail}
        )
        _clear_refresh_cookie(failed)
        return failed
    _set_refresh_cookie(response, new_token)
    return _auth_response(user, session.id)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response, db: DbSession, refresh_token: RefreshCookie = None):
    if refresh_token:
        service.revoke_by_refresh_token(db, refresh_token)
    _clear_refresh_cookie(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=UserResponse)
def me(current_user: CurrentUser):
    return current_user


@router.get("/sessions", response_model=list[SessionResponse])
def sessions(current_user: CurrentUser, session_id: CurrentSessionId, db: DbSession):
    return [
        SessionResponse(
            id=s.id,
            user_agent=s.user_agent,
            ip_address=s.ip_address,
            created_at=s.created_at,
            last_used_at=s.last_used_at,
            current=s.id == session_id,
        )
        for s in service.list_sessions(db, current_user)
    ]


@router.delete("/sessions/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session(target_id: str, current_user: CurrentUser, db: DbSession):
    session = service.get_active_session(db, target_id)
    if session is None or session.user_id != current_user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    service.revoke_session(db, session)


@router.post("/sessions/revoke-others", response_model=MessageResponse)
def revoke_other_sessions(
    current_user: CurrentUser, session_id: CurrentSessionId, db: DbSession
):
    count = service.revoke_other_sessions(db, current_user, session_id)
    return MessageResponse(
        message=f"Signed out of {count} other session{'s' if count != 1 else ''}"
    )


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------


@router.post("/forgot-password", response_model=MessageResponse)
def forgot_password(body: ForgotPasswordRequest, db: DbSession):
    token = service.create_password_reset_token(db, body.email)
    if token is not None:
        reset_link = f"{settings.frontend_url}/reset-password?token={token}"
        try:
            emails.send_password_reset(body.email, reset_link)
        except EmailDeliveryError:
            # Don't reveal whether the account exists; the failure is logged.
            pass

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
