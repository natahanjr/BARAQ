"""WebSocket real-time endpoints (dashboard push channel).

``GET /api/realtime/ws?token=<session-token>`` authenticates with the same
session token used by the REST API (``Authorization: Bearer`` flow). The
endpoint is excluded from the API-key middleware so browsers can connect
directly.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.auth import session_fresh_for_user, verify_token
from backend.database.connection import SessionLocal
from backend.database.models import User
from backend.realtime import hub

logger = logging.getLogger("baraq.api.realtime")
router = APIRouter(prefix="/api/realtime", tags=["realtime"])


@router.websocket("/ws")
async def realtime_ws(websocket: WebSocket):
    token = websocket.query_params.get("token", "")
    payload = verify_token(token, expected_type="access") if token else None
    if not payload:
        cookie = websocket.cookies.get("baraq_session", "")
        payload = verify_token(cookie, expected_type="access") if cookie else None
    if not payload:
        await websocket.close(code=4401)
        return

    db = SessionLocal()
    try:
        user = db.get(User, payload.get("uid"))
        if not user or not user.is_active or not session_fresh_for_user(payload, user):
            await websocket.close(code=4401)
            return
        org = None if user.role == "admin" else str(user.org or "")
    finally:
        db.close()

    await websocket.accept()
    sub_id, queue = await hub.connect(org=org, role=user.role)
    await websocket.send_json(
        {
            "type": "hello",
            "payload": {"user": payload.get("sub"), "role": user.role},
        }
    )
    try:
        while True:
            message = await queue.get()
            await websocket.send_text(message)
    except WebSocketDisconnect:
        pass
    finally:
        await hub.disconnect(sub_id)
