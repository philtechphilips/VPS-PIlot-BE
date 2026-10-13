"""Reusable database helpers for SQLAlchemy models.

Every function takes the db session and a model class, e.g.:

    admins = fetch(db, User, {"role": Role.ADMIN}, limit=20)
    user = fetch_one(db, User, {"email": email})

`filters` is a dict of column == value pairs. `populate` is a list of
relationship names to load with the result (like mongoose .populate()).

Soft delete: if a model has an `is_deleted` column, fetch/fetch_one/aggregate
skip deleted rows and delete_item/delete_multiple_items set it to True.
"""

from collections.abc import Sequence
from typing import Any, Literal, TypeVar

from sqlalchemy import Row, func
from sqlalchemy.orm import Query, Session, defer, selectinload

ModelT = TypeVar("ModelT")


def _not_deleted(model: type[Any]) -> list[Any]:
    if hasattr(model, "is_deleted"):
        return [model.is_deleted.isnot(True)]
    return []


def _require_soft_delete(model: type[Any]) -> None:
    if not hasattr(model, "is_deleted"):
        raise ValueError(
            f"{model.__name__} has no is_deleted column; use hard_delete instead"
        )


def _base_query(
    db: Session,
    model: type[ModelT],
    filters: dict[str, Any] | None,
    populate: Sequence[str],
    exclude_deleted: bool,
) -> Query[ModelT]:
    query = db.query(model).filter_by(**(filters or {}))
    if exclude_deleted:
        query = query.filter(*_not_deleted(model))
    for relationship in populate:
        query = query.options(selectinload(getattr(model, relationship)))
    return query


def simple_list(
    db: Session,
    model: type[ModelT],
    filters: dict[str, Any] | None = None,
    populate: Sequence[str] = (),
) -> list[ModelT]:
    query = _base_query(db, model, filters, populate, exclude_deleted=False)
    return query.all()


def create(db: Session, model: type[ModelT], data: dict[str, Any]) -> ModelT:
    new_item = model(**data)
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    return new_item


def is_unique(db: Session, model: type[Any], unique_field: dict[str, Any]) -> bool:
    return db.query(model).filter_by(**unique_field).first() is None


def count_items(
    db: Session, model: type[Any], filters: dict[str, Any] | None = None
) -> int:
    return (
        db.query(func.count())
        .select_from(model)
        .filter_by(**(filters or {}))
        .filter(*_not_deleted(model))
        .scalar()
    )


def fetch(
    db: Session,
    model: type[ModelT],
    filters: dict[str, Any] | None = None,
    populate: Sequence[str] = (),
    sort_by: str = "created_at",
    sort_type: Literal["asc", "desc"] = "desc",
    limit: int | None = None,
    skip: int = 0,
) -> list[ModelT]:
    query = _base_query(db, model, filters, populate, exclude_deleted=True)
    if hasattr(model, "password"):
        query = query.options(defer(model.password))
    column = getattr(model, sort_by)
    order = column.desc() if sort_type == "desc" else column.asc()
    return query.order_by(order).offset(skip).limit(limit).all()


def fetch_one(
    db: Session,
    model: type[ModelT],
    filters: dict[str, Any] | None = None,
    populate: Sequence[str] = (),
) -> ModelT | None:
    query = _base_query(db, model, filters, populate, exclude_deleted=True)
    return query.first()


def update(
    db: Session,
    model: type[ModelT],
    filters: dict[str, Any],
    data: dict[str, Any],
    populate: Sequence[str] = (),
) -> ModelT:
    """Update the first matching row, or create it if none matches (upsert).

    Keys whose value is None are skipped (like mongoose omitUndefined).
    """
    data = {key: value for key, value in data.items() if value is not None}
    item = db.query(model).filter_by(**filters).first()
    if item is None:
        item = model(**{**filters, **data})
        db.add(item)
    else:
        for key, value in data.items():
            setattr(item, key, value)
    db.commit()
    db.refresh(item)
    if populate:
        query = _base_query(db, model, {"id": item.id}, populate, exclude_deleted=False)
        return query.one()
    return item


def delete_item(
    db: Session, model: type[ModelT], filters: dict[str, Any]
) -> ModelT | None:
    """Soft delete the first matching row. Returns it, or None if no match."""
    _require_soft_delete(model)
    item = db.query(model).filter_by(**filters).first()
    if item is None:
        return None
    item.is_deleted = True
    db.commit()
    db.refresh(item)
    return item


def delete_multiple_items(
    db: Session, model: type[Any], filters: dict[str, Any]
) -> int:
    """Soft delete every matching row. Returns how many were updated."""
    _require_soft_delete(model)
    count = (
        db.query(model)
        .filter_by(**filters)
        .update({"is_deleted": True}, synchronize_session=False)
    )
    db.commit()
    return count


def aggregate(
    db: Session,
    model: type[Any],
    filters: dict[str, Any] | None = None,
    columns: Sequence[Any] = (),
    group_by: Sequence[Any] = (),
) -> list[Row[Any]]:
    """Run a grouped query, e.g. users per role:

    aggregate(
        db,
        User,
        columns=[User.role, func.count(User.id)],
        group_by=[User.role],
    )
    """
    query = (
        db.query(*columns)
        .select_from(model)
        .filter_by(**(filters or {}))
        .filter(*_not_deleted(model))
    )
    if group_by:
        query = query.group_by(*group_by)
    return query.all()


def hard_delete(db: Session, model: type[Any], filters: dict[str, Any]) -> int:
    """Permanently delete the first matching row. Returns 1 if deleted."""
    item = db.query(model).filter_by(**filters).first()
    if item is None:
        return 0
    db.delete(item)
    db.commit()
    return 1


def hard_delete_many(db: Session, model: type[Any], filters: dict[str, Any]) -> int:
    """Permanently delete every matching row. Returns how many were deleted."""
    count = db.query(model).filter_by(**filters).delete(synchronize_session=False)
    db.commit()
    return count
