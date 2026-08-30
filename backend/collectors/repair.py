"""Auto-repair engine for corrupted event data.

When the corruption rate crosses the CRITICAL threshold (or an operator
triggers repair manually), the platform runs a best-effort repair sequence:

1. clear the Security + System event logs (``wevtutil cl``),
2. restart the Windows EventLog service,
3. wait briefly for stabilization,
4. retrain the ML models on the cleaned history,
5. notify the administrator (audit chain + alerting channels).

Every step is isolated: a failure (missing privileges, non-Windows host,
service control denied) is recorded in the step result and never aborts the
remaining steps.  The sequence itself is purely data-driven, so tests can
run it on any platform with the OS-specific steps stubbed.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime

from backend.config import DATA_QUALITY_REPAIR_COOLDOWN_MINUTES

logger = logging.getLogger("baraq.data_quality")

#: Channels cleared during the repair sequence (Windows names).
REPAIR_CHANNELS = ("Security", "System")

_last_repair_lock = threading.Lock()
_last_repair_ts: float = 0.0


def is_windows() -> bool:
    return sys.platform.startswith("win")


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    """Run a command, never raising; returns (returncode, output)."""
    kwargs: dict = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
    }
    if is_windows():
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(cmd, **kwargs)
        return proc.returncode, (proc.stdout or "")[:300] + (proc.stderr or "")[:300]
    except FileNotFoundError:
        return -1, "command not found"
    except subprocess.TimeoutExpired:
        return -1, f"timed out after {timeout}s"
    except Exception as exc:
        return -1, str(exc)[:300]


def clear_log(channel: str) -> dict:
    """Clear one Windows event log channel (``wevtutil cl``)."""
    if not is_windows():
        return {
            "step": f"clear {channel}",
            "status": "skipped",
            "detail": "not a Windows host",
        }
    code, output = _run(["wevtutil", "cl", channel])
    if code == 0:
        logger.info("Event log %s cleared", channel)
        return {"step": f"clear {channel}", "status": "ok", "detail": "log cleared"}
    return {
        "step": f"clear {channel}",
        "status": "failed",
        "detail": output or f"wevtutil exit {code}",
    }


def restart_eventlog_service() -> dict:
    """Restart the Windows EventLog service (needs admin/service perms)."""
    if not is_windows():
        return {
            "step": "restart EventLog service",
            "status": "skipped",
            "detail": "not a Windows host",
        }
    _, stop_out = _run(["sc", "stop", "EventLog"], timeout=90)
    code, start_out = _run(["sc", "start", "EventLog"], timeout=90)
    if code == 0:
        logger.info("EventLog service restarted")
        return {
            "step": "restart EventLog service",
            "status": "ok",
            "detail": "service restarted",
        }
    detail = (stop_out + " " + start_out).strip()[:300]
    return {
        "step": "restart EventLog service",
        "status": "failed",
        "detail": detail or f"sc exit {code}",
    }


def _retrain_model() -> dict:
    """Kick a background ML retrain; returns the launch result."""
    try:
        from backend.ml.tasks import train_in_background

        started = train_in_background(force=True)
        return {
            "step": "retrain ML",
            "status": "ok" if started else "skipped",
            "detail": "training started" if started else "training already running",
        }
    except Exception as exc:
        return {"step": "retrain ML", "status": "failed", "detail": str(exc)[:300]}


def _notify_admin(reason: str, status: str, steps: list[dict]) -> None:
    """Surface the repair through the standard alerting channels."""
    try:
        from backend.notify import notify_alert

        notify_alert(
            {
                "title": "BARAQ data-quality auto-repair",
                "severity": "critical" if status == "critical" else "high",
                "name": "BARAQ data-quality auto-repair",
                "description": f"Repair sequence triggered ({reason}).",
                "evidence": f"Steps: {steps}",
                "host": os.environ.get("COMPUTERNAME", ""),
            }
        )
    except Exception:
        logger.debug("Repair notification failed", exc_info=True)


def repair_due() -> bool:
    """True when a repair may run (cooldown elapsed)."""
    global _last_repair_ts
    with _last_repair_lock:
        return (
            time.time() - _last_repair_ts
        ) >= DATA_QUALITY_REPAIR_COOLDOWN_MINUTES * 60


def _mark_repaired() -> None:
    global _last_repair_ts
    with _last_repair_lock:
        _last_repair_ts = time.time()


def run_repair(
    db,
    reason: str,
    clear_logs: bool = True,
    restart_service: bool = True,
    retrain: bool = True,
) -> dict:
    """Run the full repair sequence; returns per-step results.

    Safe on any platform: the OS-specific steps report "skipped" outside
    Windows and "failed" on privilege errors without aborting the sequence.
    """
    if not repair_due():
        return {
            "triggered": False,
            "reason": reason,
            "detail": "repair cooldown active (last repair within cooldown window)",
        }

    steps: list[dict] = []
    if clear_logs:
        for channel in REPAIR_CHANNELS:
            steps.append(clear_log(channel))
    if restart_service:
        steps.append(restart_eventlog_service())

    if any(s["status"] == "ok" for s in steps):
        # Let the OS settle after log/service churn before touching data.
        time.sleep(5)

    if retrain:
        steps.append(_retrain_model())

    failures = [s for s in steps if s["status"] == "failed"]
    success = len(failures) == 0
    _mark_repaired()

    try:
        from backend.audit import log_action

        log_action(
            db,
            "system",
            "data_quality.repair",
            "system",
            "data-quality",
            f"{reason} | steps: {len(steps)}, failures: {len(failures)}",
            "127.0.0.1",
        )
    except Exception:
        logger.debug("Repair audit entry failed", exc_info=True)

    _notify_admin(reason, "critical" if failures else "ok", steps)

    return {
        "triggered": True,
        "reason": reason,
        "success": success,
        "steps": steps,
        "started_at": datetime.now(UTC).isoformat(),
    }
