"""Bookmarks API — save/alert/investigation favorites."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.exc import IntegrityError
from backend.database.connection import get_db
from backend.database.models import Bookmark
from backend.security import require_auth

router = APIRouter(prefix="/api/bookmarks", tags=["bookmarks"], dependencies=[Depends(require_auth)])


class BookmarkCreate(BaseModel):
    entity_type: str
    entity_id: int
    note: Optional[str] = None
    tags: list[str] = []


@router.post("")
async def create_bookmark(body: BookmarkCreate, db=Depends(get_db)):
    existing = db.query(Bookmark).filter_by(
        user_id=1, entity_type=body.entity_type, entity_id=body.entity_id
    ).first()
    if existing:
        existing.note = body.note or existing.note
        existing.tags = body.tags or existing.tags
        db.commit()
        db.refresh(existing)
        return existing
    bm = Bookmark(user_id=1, entity_type=body.entity_type, entity_id=body.entity_id,
                  note=body.note, tags=body.tags)
    db.add(bm)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.query(Bookmark).filter_by(
            user_id=1, entity_type=body.entity_type, entity_id=body.entity_id
        ).first()
        if existing:
            return existing
        raise HTTPException(409, "Bookmark already exists")
    db.refresh(bm)
    return bm


@router.get("")
async def list_bookmarks(entity_type: Optional[str] = None, db=Depends(get_db)):
    q = db.query(Bookmark)
    if entity_type:
        q = q.filter_by(entity_type=entity_type)
    return q.order_by(Bookmark.created_at.desc()).all()


@router.delete("/{bookmark_id}")
async def delete_bookmark(bookmark_id: int, db=Depends(get_db)):
    bm = db.query(Bookmark).filter_by(id=bookmark_id).first()
    if not bm:
        raise HTTPException(404, "Bookmark not found")
    db.delete(bm)
    db.commit()
    return {"ok": True}
