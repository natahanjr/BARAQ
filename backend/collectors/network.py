"""Network connection collector using psutil net_connections()."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from backend.collectors.base import BaseCollector

logger = logging.getLogger("baraq.collectors.network")

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:  # pragma: no cover
    psutil = None
    HAS_PSUTIL = False

LISTEN_STATES = {"LISTEN"}


class NetworkCollector(BaseCollector):
    """Observes active TCP/UDP connections and listening sockets.

    Also approximates flow metadata (bytes sent/received via per-process
    I/O counters and connection duration) so the ML network model can learn
    richer features than the remote-IP bucket alone.
    """

    name = "network"

    def enabled(self) -> bool:
        return HAS_PSUTIL

    def _pid_name(self, pid: int) -> str:
        try:
            proc = psutil.Process(pid)
            return proc.name() or ""
        except Exception:
            return ""

    def _pid_io(self, pid: int) -> tuple[int, int]:
        try:
            io = psutil.Process(pid).io_counters()
            return int(io.bytes_sent or 0), int(io.bytes_recv or 0)
        except Exception:
            return 0, 0

    def _pid_create_time(self, pid: int) -> float | None:
        try:
            return psutil.Process(pid).create_time()
        except Exception:
            return None

    def collect(self) -> list[dict]:
        if not self.enabled():
            return []
        records: list[dict] = []
        now = datetime.now(timezone.utc)
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.logger.warning("Access denied reading network connections")
            return []

        for conn in conns:
            pid = conn.pid or 0
            duration = 0.0
            if conn.status in LISTEN_STATES:
                duration = 0.0
            else:
                created = self._pid_create_time(pid) if pid else None
                if created:
                    duration = max(0.0, now.timestamp() - created)
            bytes_sent, bytes_recv = self._pid_io(pid) if pid else (0, 0)
            records.append(
                {
                    "source": "network",
                    "pid": pid,
                    "process": self._pid_name(pid) if pid else "",
                    "local_ip": (conn.laddr.ip if conn.laddr else ""),
                    "local_port": (conn.laddr.port if conn.laddr else 0),
                    "remote_ip": (conn.raddr.ip if conn.raddr else ""),
                    "remote_port": (conn.raddr.port if conn.raddr else 0),
                    "state": conn.status or "",
                    "is_listening": conn.status in LISTEN_STATES,
                    "bytes_sent": bytes_sent,
                    "bytes_recv": bytes_recv,
                    "duration_seconds": round(duration, 2),
                    "timestamp": now.isoformat(),
                }
            )
        self.logger.debug("Collected %d network connections", len(records))
        return records
