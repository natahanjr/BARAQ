"""AI Assistant API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.ai.assistant import SecurityAssistant
from backend.audit import client_ip, log_action
from backend.database.connection import get_db
from backend.security import actor_name, require_auth

router = APIRouter(
    prefix="/api/assistant",
    tags=["assistant"],
    dependencies=[Depends(require_auth)],
)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


class ExplainRequest(BaseModel):
    alert_id: int | None = Field(default=None, ge=1)
    query: str = Field(default="", max_length=2000)


class EntityExplainRequest(BaseModel):
    kind: str = Field(min_length=1, max_length=32)
    name: str = Field(min_length=1, max_length=512)


@router.post("/chat")
def chat(body: ChatRequest, db: Session = Depends(get_db)):
    assistant = SecurityAssistant(db)
    response = assistant.chat(body.message)
    return {"reply": response, "history": assistant.history()}


@router.get("/history")
def history(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    assistant = SecurityAssistant(db)
    return {"items": assistant.history(limit)}


@router.delete("/history")
def clear_history(request: Request, db: Session = Depends(get_db)):
    assistant = SecurityAssistant(db)
    count = assistant.clear_history()
    log_action(
        db,
        actor_name(request),
        "assistant.clear_history",
        "assistant_messages",
        str(count),
        f"deleted {count} conversation message(s)",
        client_ip(request),
    )
    return {"cleared": count, "message": "Conversation history cleared."}


@router.post("/explain")
def explain(body: ExplainRequest, db: Session = Depends(get_db)):
    assistant = SecurityAssistant(db)
    query = (
        body.query or f"explain alert {body.alert_id}"
        if body.alert_id
        else "explain the latest alert"
    )
    response = assistant.chat(query, persist=False)
    return {"reply": response}


@router.post("/summarize")
def summarize(db: Session = Depends(get_db)):
    assistant = SecurityAssistant(db)
    response = assistant.chat("summarize the current incidents", persist=False)
    return {"reply": response}


@router.post("/explain-entity")
def explain_entity(body: EntityExplainRequest, db: Session = Depends(get_db)):
    assistant = SecurityAssistant(db)
    response = assistant.explain_entity(body.kind, body.name)
    return {"reply": response}
