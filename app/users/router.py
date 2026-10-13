from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from app.auth.dependencies import AdminUser, CurrentUser
from app.core.database import DbSession
from app.users import service
from app.users.models import Role
from app.users.schemas import RoleUpdate, UserCreate, UserResponse

router = APIRouter(prefix="/users", tags=["Users"])


@router.post("/", status_code=status.HTTP_201_CREATED, response_model=UserResponse)
def create_user(user_in: UserCreate, db: DbSession):
    if service.get_user_by_email(db, user_in.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email {user_in.email} already exists",
        )
    # Sign-ups are always regular users; admins are made by another admin
    # or with `uv run poe createadmin`.
    return service.create_user(db, user_in)


@router.get("/me", response_model=UserResponse)
def get_me(current_user: CurrentUser):
    return current_user


@router.get("/", response_model=list[UserResponse])
def list_users(
    db: DbSession,
    _: AdminUser,
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
    skip: Annotated[int, Query(ge=0)] = 0,
):
    return service.list_users(db, limit, skip)


@router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: int, db: DbSession, current_user: CurrentUser):
    if current_user.id != user_id and current_user.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to perform this action",
        )
    user = service.get_user(db, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {user_id} not found",
        )
    return user


@router.patch("/{user_id}/role", response_model=UserResponse)
def update_role(user_id: int, body: RoleUpdate, db: DbSession, admin: AdminUser):
    if user_id == admin.id:
        # Stops the last admin from locking everyone out by demoting themselves.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You can't change your own role",
        )
    user = service.get_user(db, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {user_id} not found",
        )
    return service.set_role(db, user, body.role)
