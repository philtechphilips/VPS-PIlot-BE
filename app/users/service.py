from sqlalchemy.orm import Session

from app.core import crud
from app.core.security import hash_password
from app.users.models import Role, User
from app.users.schemas import UserCreate


def get_user(db: Session, user_id: int) -> User | None:
    return crud.fetch_one(db, User, {"id": user_id})


def get_user_by_email(db: Session, email: str) -> User | None:
    return crud.fetch_one(db, User, {"email": email})


def list_users(db: Session, limit: int = 10, skip: int = 0) -> list[User]:
    return crud.fetch(db, User, limit=limit, skip=skip)


def create_user(db: Session, user_in: UserCreate, role: Role = Role.USER) -> User:
    data = {
        "email": user_in.email,
        "password": hash_password(user_in.password),
        "role": role,
    }
    return crud.create(db, User, data)


def set_role(db: Session, user: User, role: Role) -> User:
    return crud.update(db, User, {"id": user.id}, {"role": role})
