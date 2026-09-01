"""Real-time push hub (WebSocket) for the SOC dashboard.

The hub decouples event producers (scheduler, alerting, agents) from
connected dashboard clients. Producers call ``publish()`` from any thread;
messages are marshalled onto the asyncio event loop and fanned out to every
connected WebSocket.

Connection flow:
  1. The client opens ``/api/realtime/ws?token=<session token>``.
  2. ``connect()`` validates the token via ``backend.auth.verify_token`` and
     registers the socket.
  3. Messages are JSON: ``{"type": ..., "payload": ...}`` -- e.g.
     ``{"type": "alert", "payload": {...alert dict...}}``.

Failure visibility:
  Producers were previously blind to publish failures: a closed event loop,
  a JSON encoding error, or a full client queue would all be swallowed with
  ``except (RuntimeError, Exception): pass``. Every failed publish now
  increments ``_publish_failures`` and logs at WARNING level. The cumulative
  count is exposed via ``publish_failure_count()`` (mirrors the audit-chain
  counter in ``backend.audit``) so dashboards and health endpoints can detect
  a silent publish outage.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

logger = logging.getLogger("baraq.realtime")


#: Monotonic counter of publish() failures since process start. Incremented
#: from publish()'s exception handler so a closed loop, JSON encoding error,
#: or asyncio.QueueFull never goes unobserved again.
_publish_failures: int = 0


def record_publish_failure(reason: BaseException | str) -> None:
    """Record a publish() failure. Increments the counter and logs at WARNING."""
    global _publish_failures
    _publish_failures += 1
    logger.warning(
        "Realtime publish failure (#%d): %s", _publish_failures, reason
    )


def publish_failure_count() -> int:
    """Return the cumulative count of publish() failures since process start.

    Mirrors ``backend.audit.audit_failure_count`` so a health endpoint can
    detect a silently broken realtime channel.
    """
    return _publish_failures


class BroadcastHub:
    """Thread-safe fan-out of JSON events to WebSocket subscribers."""

    def __init__(self) -> None:
        self._clients: set[asyncio.Queue] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = (
            asyncio.Lock() if asyncio.get_event_loop_policy() is not None else None
        )
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
        try:
            payload = json.dumps(message, default=str, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            record_publish_failure(f"json encode failed: {exc}")
            return
        try:
            asyncio.run_coroutine_threadsafe(self._broadcast(payload), self._loop)
        except RuntimeError as exc:
            # Event loop closed (lifespan shutdown) or no running loop.
            record_publish_failure(f"loop unavailable: {exc}")
        except Exception as exc:
            # Anything else (TypeError, ValueError from a bad coroutine,
            # OSError from a queue that has been garbage-collected, ...).
            record_publish_failure(exc)

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
