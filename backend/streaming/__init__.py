"""Streaming pipeline - forward normalized events / alerts to external buses.

A config-gated outbound path that publishes the SOC's event and alert stream
to one or more of: **Kafka**, **Redis Streams**, **Elasticsearch** (or
OpenSearch). Enabling a sink is a configuration-only action:

* ``BARAQ_STREAM_ENABLED=1`` switches the pipeline on.
* Each sink has its own env key (``BARAQ_KAFKA_BOOTSTRAP``,
  ``BARAQ_REDIS_URL``, ``BARAQ_ELASTICSEARCH_URL``). Empty sinks stay
  dormant.
* Driver packages (``kafka-python``, ``redis``, ``elasticsearch``) are
  imported lazily; a missing package degrades that sink to "unavailable"
  (logged once) without breaking the rest of the platform.

Design considerations:

* Records are serialized to JSON once, enqueued on an in-process buffer and
  flushed by a daemon worker every ``STREAM_FLUSH_SECONDS`` or when
  ``STREAM_BATCH_SIZE`` records pile up. Publish is therefore never on the
  request/collection hot path.
* Each sink retries transient failures up to ``STREAM_MAX_RETRIES`` before a
  record is dropped (a SIEM forwarder must never grow unbounded).
* Alert records are forwarded with the same schema as events + alert fields
  so a downstream SIEM can pivot between them on ``baraq.type``.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
from datetime import datetime, timezone

from backend.config import (
    ELASTICSEARCH_INDEX,
    ELASTICSEARCH_PASSWORD,
    ELASTICSEARCH_URL,
    ELASTICSEARCH_USERNAME,
    KAFKA_BOOTSTRAP_SERVERS,
    KAFKA_TOPIC,
    REDIS_STREAM,
    REDIS_URL,
    STREAM_BATCH_SIZE,
    STREAM_ENABLED,
    STREAM_FLUSH_SECONDS,
    STREAM_MAX_RETRIES,
)

logger = logging.getLogger("baraq.streaming")

_record_queue: queue.Queue[dict] = queue.Queue(maxsize=2000)
_stop = threading.Event()
_worker: threading.Thread | None = None

#: Lazy-initialised sinks: {"kafka": {"send": callable, "kind": str}, ...}
_sinks: dict[str, dict] = {}
_sinks_lock = threading.Lock()
_driver_warned: set[str] = set()

_sent_counts: dict[str, int] = {}
_started = False
_last_init_attempt = float("-inf")
_INIT_RETRY_SECONDS = 30.0
_MAX_SINK_FAILURES = 3
#: Hard per-sink wall-clock budget for init/send so a wedged server can never
#: stall the flush worker (see ``_run_bounded``).
_SINK_OP_TIMEOUT = 6.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _stamp(record: dict) -> dict:
    stamped = dict(record)
    stamped.setdefault("@timestamp", _now_iso())
    stamped.setdefault("baraq.type", "event")
    return stamped


def record_event(event: dict) -> None:
    """Enqueue a normalized event for forwarding (non-blocking)."""
    if not STREAM_ENABLED:
        return
    try:
        _record_queue.put_nowait(_stamp({"baraq.type": "event", **event}))
    except queue.Full:  # pragma: no cover - bounded buffer safety valve
        logger.warning("Stream buffer full; dropping event record")


def record_alert(alert: dict) -> None:
    """Enqueue an alert record for forwarding (non-blocking)."""
    if not STREAM_ENABLED:
        return
    try:
        _record_queue.put_nowait(_stamp({"baraq.type": "alert", **alert}))
    except queue.Full:  # pragma: no cover
        logger.warning("Stream buffer full; dropping alert record")


def start() -> None:
    """Start the background flush worker once."""
    global _started, _worker
    if not STREAM_ENABLED or _started:
        return
    _started = True
    _stop.clear()
    _worker = threading.Thread(target=_flush_loop, daemon=True, name="baraq-stream")
    _worker.start()
    logger.info("Streaming pipeline enabled: %s", _describe_config())


def _describe_config() -> str:
    parts = []
    if KAFKA_BOOTSTRAP_SERVERS:
        parts.append(f"kafka={KAFKA_BOOTSTRAP_SERVERS} ({KAFKA_TOPIC})")
    if REDIS_URL:
        parts.append(f"redis={REDIS_URL} ({REDIS_STREAM})")
    if ELASTICSEARCH_URL:
        parts.append(f"elasticsearch={ELASTICSEARCH_URL} ({ELASTICSEARCH_INDEX})")
    return "sinks: " + (", ".join(parts) if parts else "none")


def _flush_loop() -> None:
    while not _stop.is_set():
        batch: list[dict] = []
        try:
            item = _record_queue.get(timeout=STREAM_FLUSH_SECONDS)
        except queue.Empty:
            continue
        batch.append(item)
        while not _record_queue.empty() and len(batch) < STREAM_BATCH_SIZE:
            try:
                batch.append(_record_queue.get_nowait())
            except queue.Empty:
                break
        _dispatch(batch)

def _run_bounded(fn, timeout: float):
    """Run ``fn()`` on a daemon worker with a hard wall-clock budget.

    Returns the callable's result, ``None`` if the callable itself returned
    ``None``, or raises :class:`SinkTimeoutError` once ``timeout`` seconds
    elapse (the worker is left to finish/linger; deliberately never joined so
    a wedged driver can't freeze the flush loop).
    """
    result: dict = {"value": _MISSING, "error": None}

    def _target():
        try:
            result["value"] = fn()
        except Exception as exc:  # noqa: BLE001
            result["error"] = exc

    thread = threading.Thread(target=_target, daemon=True, name="baraq-sink")
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise SinkTimeoutError(f"sink op exceeded {timeout:.1f}s budget")
    if result["error"] is not None:
        raise result["error"]
    if result["value"] is _MISSING:
        raise SinkTimeoutError("sink op produced no result")
    return result["value"]


_MISSING = object()


class SinkTimeoutError(Exception):
    """Raised when a sink operation exceeds its wall-clock budget."""


def _dispatch(batch: list[dict]) -> None:
    try:
        _run_bounded(_ensure_sinks, _SINK_OP_TIMEOUT)
    except SinkTimeoutError:
        pass  # sink init still retried on the next flush (throttled)
    if not _sinks:
        return  # no sink configured/available - records already dequeued
    for name, sink in list(_sinks.items()):
        try:
            _run_bounded(lambda: sink["send"](batch), _SINK_OP_TIMEOUT)
            sink["fails"] = 0
            sink["oops"] = None
            _sent_counts[name] = _sent_counts.get(name, 0) + len(batch)
        except Exception as exc:  # noqa: BLE001
            sink["fails"] = sink.get("fails", 0) + 1
            sink["oops"] = str(exc)[:200]
            if sink["fails"] >= _MAX_SINK_FAILURES:
                logger.warning(
                    "Sink %s failed %d times in a row (%s); suspending until next init retry",
                    name, sink["fails"], exc,
                )
                _sinks.pop(name, None)
            else:
                logger.warning(
                    "Sink %s failed (attempt %d): %s",
                    name, sink["fails"], exc,
                )


def _sink_driver(package: str) -> object | None:
    try:
        return __import__(package, fromlist=["*"])
    except ImportError:
        if package not in _driver_warned:
            _driver_warned.add(package)
            logger.warning(
                "Stream sink unavailable: install package '%s' to enable it",
                package,
            )
        return None


def _ensure_sinks() -> None:
    """Initialise configured sinks (throttled, lock released before I/O).

    The 30s throttle claim happens under the lock so only one init runs at a
    time, but the actual driver construction (which can block on unreachable
    servers) happens **outside** the lock so a wedged init can never stall
    other flushes waiting for ``_sinks_lock``.
    """
    global _last_init_attempt
    now = time.monotonic()
    if now - _last_init_attempt < _INIT_RETRY_SECONDS:
        return
    with _sinks_lock:
        if _sinks:
            return
        _last_init_attempt = now
    _init_kafka()
    _init_redis()
    _init_elasticsearch()
    logger.info("Stream sinks ready: %s", list(_sinks.keys()))


def _init_kafka() -> None:
    if not KAFKA_BOOTSTRAP_SERVERS or _sink_driver("kafka") is None:
        return
    try:
        from kafka import KafkaProducer

        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            acks="all",
            retries=STREAM_MAX_RETRIES,
            max_in_flight_requests_per_connection=1,
            request_timeout_ms=5000,
            connections_max_idle_ms=60000,
        )
        _sinks["kafka"] = {
            "kind": "kafka",
            "send": lambda batch, p=producer: [
                p.send(KAFKA_TOPIC, json.dumps(r).encode("utf-8")) for r in batch
            ] or None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Kafka producer init failed: %s", exc)


def _init_redis() -> None:
    if not REDIS_URL or _sink_driver("redis") is None:
        return
    try:
        import redis

        client = redis.Redis.from_url(
            REDIS_URL,
            decode_responses=False,
            socket_connect_timeout=3,
            socket_timeout=5,
        )

        def _send_redis(batch):
            pipe = client.pipeline(transaction=False)
            for r in batch:
                fields = {
                    k: (v if isinstance(v, (str, bytes, int, float)) else json.dumps(v))
                    for k, v in r.items()
                }
                pipe.xadd(REDIS_STREAM, fields)
            return pipe.execute()

        _sinks["redis"] = {"kind": "redis", "send": _send_redis}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Redis client init failed: %s", exc)


def _init_elasticsearch() -> None:
    if not ELASTICSEARCH_URL or _sink_driver("elasticsearch") is None:
        return
    try:
        from elasticsearch import Elasticsearch

        kwargs = {}
        if ELASTICSEARCH_USERNAME:
            kwargs["basic_auth"] = (
                ELASTICSEARCH_USERNAME,
                ELASTICSEARCH_PASSWORD,
            )
        es = Elasticsearch(
            ELASTICSEARCH_URL,
            request_timeout=5,
            max_retries=STREAM_MAX_RETRIES,
            retry_on_timeout=False,
            **kwargs,
        )

        def _send_es(batch):
            body = []
            for r in batch:
                day = r.get("@timestamp", _now_iso())[:10].replace("-", ".")
                body.append({"index": {"_index": f"{ELASTICSEARCH_INDEX}-{day}"}})
                body.append(r)
            return es.bulk(body=body)

        _sinks["elasticsearch"] = {"kind": "elasticsearch", "send": _send_es}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Elasticsearch client init failed: %s", exc)


def status() -> dict:
    """Configuration + per-sink availability for the System page."""
    return {
        "enabled": STREAM_ENABLED,
        "pending": _record_queue.qsize(),
        "configured": {
            "kafka": bool(KAFKA_BOOTSTRAP_SERVERS),
            "redis": bool(REDIS_URL),
            "elasticsearch": bool(ELASTICSEARCH_URL),
        },
        "active": {name: True for name in _sinks},
        "sent": dict(_sent_counts),
    }
