"""Entry point for the packaged SentinelSOC server executable.

Usage:
    SentinelSOC.exe            listen on 127.0.0.1:8000
    SentinelSOC.exe --lan      listen on 0.0.0.0:8000 (LAN access)
    SENTINEL_HOST / SENTINEL_PORT env vars override host and port.

The executable is built windowed (PyInstaller console=False), so double
clicking it starts the SOC in the background with no console window.
"""
from __future__ import annotations

import argparse
import ctypes
import logging
import os
import sys
import traceback
from datetime import datetime

import uvicorn

# Import the ASGI application module so PyInstaller analyses and bundles the
# whole backend package (the uvicorn.run() app path is only a string).
import backend.main  # noqa: F401  isort:skip
from backend.config import LOG_DIR


def _redirect_nulls() -> None:
    """Windowed builds have no stdout/stderr; give uvicorn something to write to."""
    if sys.stdout is None or sys.stderr is None:
        null = open(os.devnull, "w")
        sys.stdout = null
        sys.stderr = null


def _is_elevated() -> bool:
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return True


def _self_elevate() -> bool:
    """Re-launch with admin rights (UAC prompt) when needed.

    Reading the Security event log channel (error 1314) requires elevation.
    When the exe is already elevated - e.g. started by the Task Scheduler
    logon task with highest privileges - no UAC prompt appears and the
    existing instance just proceeds.
    """
    if _is_elevated():
        return False
    args = " ".join(f'"{a}"' for a in sys.argv[1:])
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, args, None, 1
    )
    return int(rc) <= 32


def _add_file_logging() -> None:
    """Persist app + uvicorn logs to dist\\logs\\sentinel.log."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(LOG_DIR / "sentinel.log", encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s")
    )
    logging.getLogger().addHandler(handler)


def _log_failure(exc: BaseException) -> None:
    """Persist a startup/runtime crash so hidden failures are never silent."""
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_DIR / "daemon.err.log", "a", encoding="utf-8") as fh:
            stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            fh.write(f"\n[{stamp}] SentinelSOC exited ({exc!r})\n")
            fh.write(traceback.format_exc())
    except OSError:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelSOC server")
    parser.add_argument(
        "--lan",
        action="store_true",
        help="listen on all interfaces (0.0.0.0) instead of localhost",
    )
    parser.add_argument("--port", type=int, default=None, help="port (default 8001)")
    args = parser.parse_args()

    _redirect_nulls()

    if _self_elevate():
        _log_failure(RuntimeError("User declined the admin elevation prompt"))
        return

    _add_file_logging()

    host = os.environ.get("SENTINEL_HOST", "0.0.0.0" if args.lan else "127.0.0.1")
    port = args.port or int(os.environ.get("SENTINEL_PORT", "8001"))
    try:
        uvicorn.run("backend.main:app", host=host, port=port, log_level="info")
    except BaseException as exc:  # noqa: BLE001 - surface daemon crashes in log
        _log_failure(exc)
        raise


if __name__ == "__main__":
    main()
