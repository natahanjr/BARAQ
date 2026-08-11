"""Process collector using psutil: running processes + new process detection."""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone

from backend.collectors.base import BaseCollector

logger = logging.getLogger("baraq.collectors.process")

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:  # pragma: no cover
    psutil = None
    HAS_PSUTIL = False


class ProcessCollector(BaseCollector):
    """Enumerates running processes and flags newly-observed ones."""

    name = "process"

    def __init__(self):
        super().__init__()
        self._known_pids: set[int] = set()
        self._first_run = True

    def enabled(self) -> bool:
        return HAS_PSUTIL

    # ------------------------------------------------------------------
    @staticmethod
    def _proc_info(proc) -> dict | None:
        try:
            info = proc.info
            if info.get("pid") is None:
                return None
            return {
                "source": "process",
                "pid": info.get("pid"),
                "ppid": info.get("ppid") or 0,
                "name": info.get("name") or "",
                "path": info.get("exe") or "",
                "command_line": info.get("cmdline") or [],
                "user": info.get("username") or "",
                "create_time": info.get("create_time") or 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def collect(self) -> list[dict]:
        if not self.enabled():
            return []
        records: list[dict] = []
        current_pids: set[int] = set()

        for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
            info = self._proc_info(proc)
            if not info:
                continue
            pid = info["pid"]
            current_pids.add(pid)
            info["is_new"] = self._first_run or pid not in self._known_pids
            info["raw"] = {
                "cmdline": " ".join(info.pop("command_line"))[:4096] if info.get("command_line") else "",
            }
            records.append(info)

        self._known_pids = current_pids
        self._first_run = False
        self.logger.debug("Collected %d processes", len(records))
        return records
