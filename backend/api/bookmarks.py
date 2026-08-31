"""Bookmarks API — save/alert/investigation favorites."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from database import get_db
from database.models import Bookmark
from auth import get_current_user

router = APIRouter(prefix="/api/bookmarks", tags=["bookmarks"])


class BookmarkCreate(BaseModel):
    entity_type: str
    entity_id: int
    note: Optional[str] = None
    tags: list[str] = []


class BookmarkResponse(BaseModel):
    id: int
    user_id: int
    entity_type: str
    entity_id: int
    note: Optional[str]
    tags: list[str]
    created_at: str


@router.post("", response_model=BookmarkResponse)
async def create_bookmark(body: BookmarkCreate, user=Depends(get_current_user), db=Depends(get_db)):
    existing = db.query(Bookmark).filter_by(
        user_id=user.id, entity_type=body.entity_type, entity_id=body.entity_id
    ).first()
    if existing:
        raise HTTPException(400, "Already bookmarked")
    bm = Bookmark(user_id=user.id, entity_type=body.entity_type, entity_id=body.entity_id,
                  note=body.note, tags=body.tags)
    db.add(bm)
    db.commit()
    db.refresh(bm)
    return bm


@router.get("", response_model=list[BookmarkResponse])
async def list_bookmarks(entity_type: Optional[str] = None, user=Depends(get_current_user), db=Depends(get_db)):
    q = db.query(Bookmark).filter_by(user_id=user.id)
    if entity_type:
        q = q.filter_by(entity_type=entity_type)
    return q.order_by(Bookmark.created_at.desc()).all()


@router.delete("/{bookmark_id}")
async def delete_bookmark(bookmark_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    bm = db.query(Bookmark).filter_by(id=bookmark_id, user_id=user.id).first()
    if not bm:
        raise HTTPException(404, "Bookmark not found")
    db.delete(bm)
    db.commit()
    return {"ok": True}
