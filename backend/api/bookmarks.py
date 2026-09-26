"""Bookmarks API — save/alert/investigation favorites."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError

from backend.database.connection import get_db
from backend.database.models import Bookmark
from backend.security import require_auth, resolve_user

router = APIRouter(prefix="/api/bookmarks", tags=["bookmarks"], dependencies=[Depends(require_auth)])


def _caller(request: Request, db):
    user = resolve_user(request, db)
    if user is None:
        raise HTTPException(401, "An interactive user session is required")
    return user


class BookmarkCreate(BaseModel):
    entity_type: str
    entity_id: int
    note: str | None = None
    tags: list[str] = []


@router.post("")
async def create_bookmark(body: BookmarkCreate, request: Request, db=Depends(get_db)):
    user = _caller(request, db)
    existing = db.query(Bookmark).filter_by(
        user_id=user.id, entity_type=body.entity_type, entity_id=body.entity_id
    ).first()
    if existing:
        existing.note = body.note or existing.note
        existing.tags = body.tags or existing.tags
        db.commit()
        db.refresh(existing)
        return existing
    bm = Bookmark(user_id=user.id, entity_type=body.entity_type, entity_id=body.entity_id,
                  note=body.note, tags=body.tags)
    db.add(bm)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.query(Bookmark).filter_by(
            user_id=user.id, entity_type=body.entity_type, entity_id=body.entity_id
        ).first()
        if existing:
            return existing
        raise HTTPException(409, "Bookmark already exists")
    db.refresh(bm)
    return bm


@router.get("")
async def list_bookmarks(
    request: Request,
    entity_type: str | None = None,
    db=Depends(get_db),
):
    user = _caller(request, db)
    q = db.query(Bookmark).filter(Bookmark.user_id == user.id)
    if entity_type:
        q = q.filter_by(entity_type=entity_type)
    return q.order_by(Bookmark.created_at.desc()).all()


@router.delete("/{bookmark_id}")
async def delete_bookmark(bookmark_id: int, request: Request, db=Depends(get_db)):
    user = _caller(request, db)
    bm = db.query(Bookmark).filter_by(id=bookmark_id, user_id=user.id).first()
    if not bm:
        raise HTTPException(404, "Bookmark not found")
    db.delete(bm)
    db.commit()
    return {"ok": True}
