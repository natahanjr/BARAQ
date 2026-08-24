"""WebSocket real-time endpoints (dashboard push channel).

``GET /api/realtime/ws?token=<session-token>`` authenticates with the same
session token used by the REST API (``Authorization: Bearer`` flow). The
endpoint is excluded from the API-key middleware so browsers can connect
directly.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.auth import verify_token
from backend.realtime import hub

logger = logging.getLogger("baraq.api.realtime")
router = APIRouter(prefix="/api/realtime", tags=["realtime"])


@router.websocket("/ws")
async def realtime_ws(websocket: WebSocket):
    token = websocket.query_params.get("token", "")
    payload = verify_token(token) if token else None
    if not payload:
        # Session-token fallback: the SPA keeps the token in memory only
        # (XSS hardening), so after a page reload the query param is gone
        # while the httpOnly baraq_session cookie is still sent automatically
        # by the browser on this same-origin upgrade. Accept either.
        cookie = websocket.cookies.get("baraq_session", "")
        payload = verify_token(cookie) if cookie else None
    if not payload:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    queue = await hub.connect()
    await websocket.send_json(
        {"type": "hello", "payload": {"user": payload.get("sub"), "role": payload.get("role")}}
    )
    try:
        while True:
            message = await queue.get()
            await websocket.send_text(message)
    except WebSocketDisconnect:
        pass
    finally:
        await hub.disconnect(queue)
