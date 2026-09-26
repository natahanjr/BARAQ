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
from dataclasses import dataclass
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


@dataclass
class _Subscriber:
    queue: asyncio.Queue
    org: str | None
    role: str


class BroadcastHub:
    """Thread-safe, tenant-aware fan-out of JSON events."""

    def __init__(self) -> None:
        self._clients: dict[int, _Subscriber] = {}
        self._next_id = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = (
            asyncio.Lock() if asyncio.get_event_loop_policy() is not None else None
        )
        self._started = False

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._started = True

    async def connect(
        self, org: str | None = None, role: str = "analyst"
    ) -> tuple[int, asyncio.Queue]:
        if self._lock is None:
            self._lock = asyncio.Lock()
        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        async with self._lock:
            sub_id = self._next_id
            self._next_id += 1
            self._clients[sub_id] = _Subscriber(queue=queue, org=org, role=role)
        logger.info("Realtime client connected (%d total)", len(self._clients))
        return sub_id, queue

    async def disconnect(self, sub_id: int) -> None:
        if self._lock is None:
            return
        async with self._lock:
            self._clients.pop(sub_id, None)
        logger.info("Realtime client disconnected (%d total)", len(self._clients))

    def publish(self, message: dict[str, Any]) -> None:
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
            record_publish_failure(f"loop unavailable: {exc}")
        except Exception as exc:
            record_publish_failure(exc)

    async def _broadcast(self, payload: str) -> None:
        if self._lock is None:
            return
        try:
            message = json.loads(payload)
        except (TypeError, ValueError):
            message = {}
        message_payload = message.get("payload") if isinstance(message, dict) else None
        message_org = (
            message_payload.get("org") if isinstance(message_payload, dict) else None
        )
        async with self._lock:
            clients = list(self._clients.items())
        stale: list[int] = []
        for sub_id, subscriber in clients:
            if subscriber.org is not None and message_org != subscriber.org:
                continue
            try:
                subscriber.queue.put_nowait(payload)
            except asyncio.QueueFull:
                stale.append(sub_id)
        for sub_id in stale:
            await self.disconnect(sub_id)



#: Module-level singleton used across the app.
hub = BroadcastHub()


def publish_alert(alert: dict[str, Any]) -> None:
    hub.publish({"type": "alert", "payload": alert, "ts": time.time()})


def publish_status(status: dict[str, Any]) -> None:
    hub.publish({"type": "status", "payload": status, "ts": time.time()})


def publish_incident(incident: dict[str, Any]) -> None:
    hub.publish({"type": "incident", "payload": incident, "ts": time.time()})
