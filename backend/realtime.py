"""Real-time push hub (WebSocket) for the SOC dashboard.

The hub decouples event producers (scheduler, alerting, agents) from
connected dashboard clients. Producers call ``publish()`` from any thread;
messages are marshalled onto the asyncio event loop and fanned out to every
connected WebSocket.

Connection flow:
  1. The client opens ``/api/realtime/ws?token=<session token>``.
  2. ``connect()`` validates the token via ``backend.auth.verify_token`` and
     registers the socket.
  3. Messages are JSON: ``{"type": ..., "payload": ...}`` — e.g.
     ``{"type": "alert", "payload": {...alert dict...}}``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

logger = logging.getLogger("baraq.realtime")


class BroadcastHub:
    """Thread-safe fan-out of JSON events to WebSocket subscribers."""

    def __init__(self) -> None:
        self._clients: set[asyncio.Queue] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = asyncio.Lock() if asyncio.get_event_loop_policy() is not None else None
        self._started = False

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        """Attach to the server event loop (called from app lifespan)."""
        self._loop = loop
        self._started = True

    async def connect(self) -> asyncio.Queue:
        """Register a new client queue and return it."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        async with self._lock:
            self._clients.add(queue)
        logger.info("Realtime client connected (%d total)", len(self._clients))
        return queue

    async def disconnect(self, queue: asyncio.Queue) -> None:
        if self._lock is None:
            return
        async with self._lock:
            self._clients.discard(queue)
        logger.info("Realtime client disconnected (%d total)", len(self._clients))

    # ------------------------------------------------------------------
    # producer side (callable from any thread)
    # ------------------------------------------------------------------
    def publish(self, message: dict[str, Any]) -> None:
        """Push a JSON-serialisable message to all clients (thread-safe)."""
        if not self._started or self._loop is None or not self._clients:
            return
        payload = json.dumps(message, default=str, ensure_ascii=False)
        try:
            asyncio.run_coroutine_threadsafe(
                self._broadcast(payload), self._loop
            )
        except (RuntimeError, Exception):  # noqa: BLE001 - loop shutting down
            pass

    async def _broadcast(self, payload: str) -> None:
        if self._lock is None:
            return
        async with self._lock:
            clients = list(self._clients)
        stale: list[asyncio.Queue] = []
        for queue in clients:
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                stale.append(queue)
        for queue in stale:
            await self.disconnect(queue)


#: Module-level singleton used across the app.
hub = BroadcastHub()


def publish_alert(alert: dict[str, Any]) -> None:
    hub.publish({"type": "alert", "payload": alert, "ts": time.time()})


def publish_status(status: dict[str, Any]) -> None:
    hub.publish({"type": "status", "payload": status, "ts": time.time()})


def publish_incident(incident: dict[str, Any]) -> None:
    hub.publish({"type": "incident", "payload": incident, "ts": time.time()})
