"""Status pages: managed by admins, readable by anyone."""

from datetime import datetime
from typing import Annotated, NoReturn

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field, StringConstraints

from app.audit import service as audit
from app.auth.dependencies import AdminUser
from app.core.database import DbSession
from app.domains import status_pages
from app.domains.models import StatusPage

router = APIRouter(prefix="/api/v1", tags=["Status pages"])

Slug = Annotated[
    str, StringConstraints(pattern=r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")
]


class ComponentIn(BaseModel):
    domain_id: Annotated[str, StringConstraints(max_length=32)]
    label: Annotated[str, StringConstraints(strip_whitespace=True, max_length=60)] = ""


class PageIn(BaseModel):
    slug: Slug | None = None
    title: (
        Annotated[str, StringConstraints(strip_whitespace=True, max_length=80)] | None
    ) = None
    description: Annotated[str, StringConstraints(max_length=300)] | None = None
    components: Annotated[list[ComponentIn], Field(max_length=30)] | None = None


class PageOut(BaseModel):
    id: str
    slug: str
    title: str
    description: str | None
    components: list[dict]
    created_at: datetime


def _raise(error: status_pages.StatusPageError) -> NoReturn:
    raise HTTPException(status_code=error.status_code, detail=error.detail)


def _audit(db, user, request, action: str, page: StatusPage) -> None:
    actor, label = audit.user_actor(user)
    audit.record(
        db,
        action=action,
        result="success",
        actor=actor,
        actor_label=label,
        target_type="status_page",
        target_id=page.id,
        target_label=page.slug,
        request=request,
    )


@router.get("/status-pages", response_model=list[PageOut])
def list_pages(db: DbSession, _: AdminUser):
    return [
        PageOut.model_validate(p, from_attributes=True)
        for p in db.query(StatusPage).order_by(StatusPage.created_at)
    ]


@router.post("/status-pages", response_model=PageOut, status_code=201)
def create_page(body: PageIn, request: Request, db: DbSession, user: AdminUser):
    if not body.slug:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Pick an address")
    _, label = audit.user_actor(user)
    try:
        page = status_pages.save(db, None, body.model_dump(exclude_unset=True), label)
    except status_pages.StatusPageError as error:
        _raise(error)
    _audit(db, user, request, "status_page.create", page)
    return PageOut.model_validate(page, from_attributes=True)


@router.patch("/status-pages/{page_id}", response_model=PageOut)
def update_page(
    page_id: str, body: PageIn, request: Request, db: DbSession, user: AdminUser
):
    page = db.get(StatusPage, page_id)
    if page is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Status page not found")
    _, label = audit.user_actor(user)
    try:
        page = status_pages.save(db, page, body.model_dump(exclude_unset=True), label)
    except status_pages.StatusPageError as error:
        _raise(error)
    _audit(db, user, request, "status_page.update", page)
    return PageOut.model_validate(page, from_attributes=True)


@router.delete("/status-pages/{page_id}", status_code=204)
def delete_page(page_id: str, request: Request, db: DbSession, user: AdminUser):
    page = db.get(StatusPage, page_id)
    if page is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Status page not found")
    _audit(db, user, request, "status_page.delete", page)
    status_pages._cache.pop(page.slug, None)
    db.delete(page)
    db.commit()


@router.get("/status/{slug}")
def public_page(slug: Slug, db: DbSession):
    """The public view. No sign-in: share the link with anyone."""
    body = status_pages.public(db, slug)
    if body is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such status page")
    return body
