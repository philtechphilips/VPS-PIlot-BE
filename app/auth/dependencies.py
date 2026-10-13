from collections.abc import Callable
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth import service as auth_service
from app.core.database import DbSession
from app.core.security import decode_access_token
from app.users import service as users_service
from app.users.models import Role, User

# Bearer tokens come from /api/v1/auth/2fa/verify or /refresh. Swagger's
# "Authorize" button accepts a pasted token (login needs an emailed code).
bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: DbSession,
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise credentials_exception
    try:
        payload = decode_access_token(credentials.credentials)
        user_id = int(payload["sub"])
        session_id = payload["sid"]
        if payload.get("type") != "access":
            raise KeyError("type")
    except (jwt.InvalidTokenError, KeyError, ValueError, TypeError):
        raise credentials_exception from None

    # Revoked or expired sessions invalidate their access tokens immediately.
    if auth_service.get_active_session(db, session_id) is None:
        raise credentials_exception

    user = users_service.get_user(db, user_id)
    if user is None:
        raise credentials_exception
    request.state.session_id = session_id
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_session_id(request: Request, _: CurrentUser) -> str:
    return request.state.session_id


CurrentSessionId = Annotated[str, Depends(get_session_id)]


def require_roles(*roles: Role) -> Callable[[User], User]:
    """Dependency that allows only users with one of the given roles.

    Use it in a route signature or a router's dependencies:

        @router.get("/reports", dependencies=[Depends(require_roles(Role.ADMIN))])
    """

    def check_role(current_user: CurrentUser) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to perform this action",
            )
        return current_user

    return check_role


AdminUser = Annotated[User, Depends(require_roles(Role.ADMIN))]
