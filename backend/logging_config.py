"""Centralized logging: JSON formatter, optional syslog/SIEM forwarder, and
a tamper-evident hash-chained audit stream.

- ``JSONFormatter`` renders each record as a single JSON line
  (``ts / level / logger / msg``) so a SIEM can ingest the stream directly.
- ``setup_logging()`` wires the root logger once: console (text or JSON),
  optional rotating file, and an optional remote syslog forwarder.
- The audit hash chain (see ``backend/audit.py``) is re-emitted on every
  ``log_action`` through the "sentinel.audit" logger; SIEM-side consumers can
  re-verify chain integrity against the database copy.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import socket
import time
from pathlib import Path

from backend.config import (
    LOG_DIR,
    LOG_FORMAT,
    SYSLOG_AUDIT,
    SYSLOG_HOST,
    SYSLOG_PORT,
    SYSLOG_PROTO,
)

logger = logging.getLogger("sentinel.logging")


class JSONFormatter(logging.Formatter):
    """One JSON object per log line, in stable key order."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        extra = getattr(record, "sentinel", None)
        if isinstance(extra, dict):
            payload.update(extra)
        return json.dumps(payload, ensure_ascii=False, default=str)


class _Rfc5424SyslogHandler(logging.handlers.SysLogHandler):
    """Syslog forwarder (RFC3164 over UDP by default, RFC5424 over TCP).

    Falls back silently when the collector is unreachable — logging must
    never break the application.
    """

    def __init__(self, host: str, port: int, proto: str):
        if proto == "tcp":
            self._sock = socket.create_connection((host, port), timeout=3)
            self.socket = self._sock
            logging.Handler.__init__(self)
            self._address = (host, port)
            self.socktype = socket.SOCK_STREAM
        else:
            logging.handlers.SysLogHandler.__init__(
                self, address=(host, port), facility="user"
            )

    def close(self) -> None:  # noqa: D102
        try:
            if getattr(self, "_sock", None) is not None:
                self._sock.close()
                self._sock = None
                self.socket = None
        except OSError:
            pass
        logging.Handler.close(self)

    def emit(self, record: logging.LogRecord):  # noqa: D102
        try:
            if getattr(self, "socktype", None) == socket.SOCK_STREAM:
                msg = self.format(record)
                self._sock.sendall(msg.encode("utf-8") + b"\n")
            else:
                super().emit(record)
        except OSError:
            # Collector down: drop the message, keep the app alive.
            pass


def _configured() -> bool:
    return logger._configured  # type: ignore[attr-defined]


def setup_logging() -> None:
    """Idempotent root-logger configuration (call once at startup)."""
    if getattr(logger, "_configured", False):
        return
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()

    formatter: logging.Formatter
    if LOG_FORMAT == "json":
        formatter = JSONFormatter()
        for h in root.handlers:
            root.removeHandler(h)
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        root.addHandler(console)
        fileh = logging.handlers.RotatingFileHandler(
            LOG_DIR / "sentinel.log", maxBytes=10 * 1024 * 1024, backupCount=5
        )
        fileh.setFormatter(formatter)
        root.addHandler(fileh)
        # Keep the uvicorn access logs (colored CLI) separate.
        logging.getLogger("uvicorn.error").propagate = True
        logging.getLogger("uvicorn.access").propagate = True
    else:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
        )
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        root.addHandler(console)
        fileh = logging.handlers.RotatingFileHandler(
            LOG_DIR / "sentinel.log", maxBytes=10 * 1024 * 1024, backupCount=5
        )
        fileh.setFormatter(formatter)
        root.addHandler(fileh)

    if SYSLOG_HOST:
        try:
            syslog = _Rfc5424SyslogHandler(SYSLOG_HOST, SYSLOG_PORT, SYSLOG_PROTO)
            # SIEM stream is always structured JSON so audit payloads are
            # complete (the console may stay human-readable).
            syslog.setFormatter(JSONFormatter())
            root.addHandler(syslog)
            logger.info("Syslog forwarding enabled -> %s:%s (%s)",
                        SYSLOG_HOST, SYSLOG_PORT, SYSLOG_PROTO)
        except OSError as exc:
            logger.warning("Syslog forwarder disabled: %s", exc)

    # Quiet the noisy third-party loggers.
    for noisy in ("urllib3", "httpx", "matplotlib", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logger._configured = True  # type: ignore[attr-defined]


def audit_syslog(payload: dict) -> None:
    """Emit one audit entry to the syslog/SIEM stream (no-op when disabled)."""
    if not SYSLOG_HOST or not SYSLOG_AUDIT:
        return
    audit_logger = logging.getLogger("sentinel.audit")
    audit_logger.info("audit", extra={"sentinel": payload})
