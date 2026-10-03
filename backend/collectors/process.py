"""Process collector using psutil: running processes + new process detection."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime

from backend.collectors.base import BaseCollector

logger = logging.getLogger("baraq.collectors.process")

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:  # pragma: no cover
    psutil = None
    HAS_PSUTIL = False

#: Cycles between forced full re-emission of the whole process inventory.
#: Zero disables the periodic refresh (dedup is then purely change-driven).
FULL_REFRESH_CYCLES = max(0, int(os.environ.get("BARAQ_PROCESS_FULL_REFRESH", "30")))


class ProcessCollector(BaseCollector):
    """Enumerates running processes and flags newly-observed ones.

    The process table is the largest single source of records on a busy host
    (every running process on each cycle). Re-emitting an unchanged process
    every cycle produced hundreds of identical rows per cycle, which dominated
    collection cost and bloated ``ProcessRecord`` with duplicates that carry no
    new information.

    A record is therefore emitted when the process is new, when any
    state-bearing field changed (re-parenting, rename, new command line, new
    user, or a reused pid with a different create time), or on the periodic
    full-refresh cycle so the inventory is still re-asserted as a baseline.
    """

    name = "process"

    def __init__(self):
        super().__init__()
        self._known_pids: set[int] = set()
        self._fingerprints: dict[int, tuple] = {}
        self._first_run = True
        self._cycles = 0

    def enabled(self) -> bool:
        return HAS_PSUTIL

    @staticmethod
    def _fingerprint(info: dict) -> tuple:
        """Identity of a process's observable state.

        ``create_time`` is part of the key so a recycled pid is treated as a
        new process rather than silently suppressed as "unchanged".
        """
        return (
            info.get("ppid") or 0,
            info.get("name") or "",
            info.get("path") or "",
            tuple(info.get("command_line") or ()),
            info.get("user") or "",
            info.get("create_time") or 0,
        )

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
                "timestamp": datetime.now(UTC).isoformat(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def collect(self) -> list[dict]:
        if not self.enabled():
            return []
        records: list[dict] = []
        current_pids: set[int] = set()
        current_fingerprints: dict[int, tuple] = {}
        self._cycles += 1
        full_refresh = self._first_run or (FULL_REFRESH_CYCLES > 0 and self._cycles % FULL_REFRESH_CYCLES == 0)
        suppressed = 0

        for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
            info = self._proc_info(proc)
            if not info:
                continue
            pid = info["pid"]
            current_pids.add(pid)
            fingerprint = self._fingerprint(info)
            current_fingerprints[pid] = fingerprint
            is_new = self._first_run or pid not in self._known_pids
            if not (full_refresh or is_new or fingerprint != self._fingerprints.get(pid)):
                suppressed += 1
                continue
            info["is_new"] = is_new
            info["raw"] = {
                "cmdline": (" ".join(info.pop("command_line"))[:4096] if info.get("command_line") else ""),
            }
            records.append(info)

        self._known_pids = current_pids
        self._fingerprints = current_fingerprints
        self._first_run = False
        self.logger.debug(
            "Collected %d processes (%d unchanged suppressed, full_refresh=%s)",
            len(records),
            suppressed,
            full_refresh,
        )
        return records
