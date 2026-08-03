"""AI Assistant API endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.ai.assistant import SecurityAssistant
from backend.database.connection import get_db

router = APIRouter(prefix="/api/assistant", tags=["assistant"])


class ChatRequest(BaseModel):
    message: str


class ExplainRequest(BaseModel):
    alert_id: int | None = None
    query: str = ""


@router.post("/chat")
def chat(body: ChatRequest, db: Session = Depends(get_db)):
    assistant = SecurityAssistant(db)
    response = assistant.chat(body.message)
    return {"reply": response, "history": assistant.history()}


@router.get("/history")
def history(limit: int = 50, db: Session = Depends(get_db)):
    assistant = SecurityAssistant(db)
    return {"items": assistant.history(limit)}


@router.post("/explain")
def explain(body: ExplainRequest, db: Session = Depends(get_db)):
    assistant = SecurityAssistant(db)
    query = body.query or f"explain alert {body.alert_id}" if body.alert_id else "explain the latest alert"
    response = assistant.chat(query, persist=False)
    return {"reply": response}


@router.post("/summarize")
def summarize(db: Session = Depends(get_db)):
    assistant = SecurityAssistant(db)
    response = assistant.chat("summarize the current incidents", persist=False)
    return {"reply": response}
