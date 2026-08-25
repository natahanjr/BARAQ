"""Collector health registry, channel permission probing and retry helpers.

Gives the pipeline three things the roadmap asks for:

* **Permission detection** - probe each watched channel at startup and tell
  the operator exactly what to fix when ``SeSecurityPrivilege`` is missing
  (win32 error 1314 - the "Event Log Readers" group / elevation issue).
* **Health registry** - per-channel success/failure counters, consecutive
  failures and last-error text, surfaced on ``/api/system/collectors/health``
  and Prometheus.
* **Retry with exponential backoff** for transient channel errors (the
  privilege error is persistent and is *not* retried).
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger("baraq.collectors.health")

#: ERROR_PRIVILEGE_NOT_HELD - OpenEventLog fails with this when the caller
#: is not allowed to read the channel (Security needs SeSecurityPrivilege).
PRIVILEGE_NOT_HELD = 1314

#: Transient win32 errors worth retrying with backoff (channel busy,
#: log-file in use, buffer issues, ...). Privilege errors are excluded.
_TRANSIENT_ERRORS = {
    1501,  # ERROR_EVENTLOG_FILE_CORRUPT
    1502,  # ERROR_EVENTLOG_CANT_START
    1503,  # ERROR_LOG_FILE_FULL
    1504,  # ERROR_EVENTLOG_FILE_CHANGED
    5,     # ERROR_ACCESS_DENIED (may clear after group membership applies)
}

FIX_HINT = (
    "Run 'powershell -NoProfile -ExecutionPolicy Bypass -File "
    "scripts\\elevate_permissions.ps1 grant' (or add the service user to "
    "the 'Event Log Readers' group / run elevated) and restart."
)


class CollectorHealth:
    """In-memory per-channel health + collection statistics."""

    def __init__(self):
        self._lock = threading.Lock()
        self._channels: dict[str, dict] = {}
        self.started_at = datetime.now(timezone.utc).isoformat()

    def reset(self) -> None:
        """Clear all per-channel state (tests, post-incident triage)."""
        with self._lock:
            self._channels.clear()
            self.started_at = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _blank(channel: str) -> dict:
        return {
            "channel": channel,
            "ok": False,
            "records_total": 0,
            "cycles_total": 0,
            "failures_total": 0,
            "consecutive_failures": 0,
            "last_error": "",
            "last_success_at": None,
            "last_failure_at": None,
            "permission_issue": False,
        }

    def record_success(self, channel: str, records: int = 0) -> None:
        if not _enabled():
            return
        with self._lock:
            state = self._channels.setdefault(channel, self._blank(channel))
            state["ok"] = True
            state["records_total"] += records
            state["cycles_total"] += 1
            state["consecutive_failures"] = 0
            state["last_success_at"] = datetime.now(timezone.utc).isoformat()

    def record_failure(self, channel: str, error: str, permission_issue: bool = False) -> None:
        if not _enabled():
            return
        with self._lock:
            state = self._channels.setdefault(channel, self._blank(channel))
            state["ok"] = False
            state["failures_total"] += 1
            state["consecutive_failures"] += 1
            state["last_error"] = error[:400]
            state["last_failure_at"] = datetime.now(timezone.utc).isoformat()
            state["permission_issue"] = permission_issue or state["permission_issue"]

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [
                dict(state, **{
                    "last_success_at": state["last_success_at"],
                    "last_failure_at": state["last_failure_at"],
                })
                for state in sorted(self._channels.values(), key=lambda s: s["channel"])
            ]

    def unhealthy(self) -> list[dict]:
        return [s for s in self.snapshot() if not s["ok"]]


#: Process-wide singleton shared by every collector and the API.
registry = CollectorHealth()


def _enabled() -> bool:
    try:
        from backend.config import COLLECTOR_HEALTH

        return COLLECTOR_HEALTH
    except Exception:  # noqa: BLE001 - config import must never break health
        return True


def check_channel_access(channel: str) -> tuple[bool, int | None, str]:
    """Probe one event-log channel with a real OpenEventLog call.

    Returns ``(readable, win32_error, detail)``. Fails closed (readable=False)
    when pywin32 is unavailable so non-Windows hosts report it honestly.
    """
    try:
        import win32evtlog
    except ImportError:  # pragma: no cover - non-Windows
        return False, None, "pywin32 not available"
    try:
        handle = win32evtlog.OpenEventLog(None, channel)
    except Exception as exc:  # noqa: BLE001
        winerror = getattr(exc, "winerror", None) or getattr(exc, "args", (None,))[0]
        if isinstance(winerror, tuple):  # pywin32 wraps (code, func, msg)
            winerror = winerror[0]
        try:
            return False, int(winerror) if winerror is not None else None, str(exc)
        except (TypeError, ValueError):
            return False, None, str(exc)
    try:
        win32evtlog.CloseEventLog(handle)
    except Exception:  # noqa: BLE001
        pass
    return True, 0, "ok"


def check_collector_permissions(channels: list[str]) -> list[dict]:
    """Probe every watched channel at startup; returns a status report.

    Logs a clear, actionable message when any channel is not readable so
    operators can fix it before the first collection cycle fails silently.
    """
    report: list[dict] = []
    for channel in channels:
        readable, winerror, detail = check_channel_access(channel)
        status = {
            "channel": channel,
            "readable": readable,
            "winerror": winerror,
            "detail": detail,
        }
        if readable:
            logger.info("Collector permissions: %s readable", channel)
        elif winerror == PRIVILEGE_NOT_HELD:
            logger.error(
                "Collector permissions: %s NOT readable - missing privilege "
                "(win32 error 1314). %s",
                channel, FIX_HINT,
            )
        else:
            logger.warning(
                "Collector permissions: %s NOT readable (%s). %s",
                channel, detail or winerror, FIX_HINT,
            )
        report.append(status)
    return report


def retry_with_backoff(fn, attempts: int = 3, base_delay: float = 1.0, transient_only: bool = True):
    """Call ``fn()`` retrying transient failures with exponential backoff.

    Privilege errors (1314) are persistent and raise immediately. Returns the
    last exception when all attempts are exhausted.
    """
    delay = base_delay
    last_exc: Exception | None = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            winerror = getattr(exc, "winerror", None)
            if isinstance(winerror, tuple):
                winerror = winerror[0]
            if transient_only and winerror == PRIVILEGE_NOT_HELD:
                raise
            if attempt < attempts - 1:
                logger.debug(
                    "Transient collector error (attempt %d/%d): %s - retrying in %.1fs",
                    attempt + 1, attempts, exc, delay,
                )
                time.sleep(delay)
                delay *= 2
    raise last_exc  # type: ignore[misc]
