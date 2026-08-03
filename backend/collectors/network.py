"""Network connection collector using psutil net_connections()."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from backend.collectors.base import BaseCollector

logger = logging.getLogger("sentinel.collectors.network")

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:  # pragma: no cover
    psutil = None
    HAS_PSUTIL = False

LISTEN_STATES = {"LISTEN"}


class NetworkCollector(BaseCollector):
    """Observes active TCP/UDP connections and listening sockets."""

    name = "network"

    def enabled(self) -> bool:
        return HAS_PSUTIL

    def _pid_name(self, pid: int) -> str:
        try:
            proc = psutil.Process(pid)
            return proc.name() or ""
        except Exception:
            return ""

    def collect(self) -> list[dict]:
        if not self.enabled():
            return []
        records: list[dict] = []
        now = datetime.now(timezone.utc).isoformat()
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.logger.warning("Access denied reading network connections")
            return []

        for conn in conns:
            records.append(
                {
                    "source": "network",
                    "pid": conn.pid or 0,
                    "process": self._pid_name(conn.pid) if conn.pid else "",
                    "local_ip": (conn.laddr.ip if conn.laddr else ""),
                    "local_port": (conn.laddr.port if conn.laddr else 0),
                    "remote_ip": (conn.raddr.ip if conn.raddr else ""),
                    "remote_port": (conn.raddr.port if conn.raddr else 0),
                    "state": conn.status or "",
                    "is_listening": conn.status in LISTEN_STATES,
                    "timestamp": now,
                }
            )
        self.logger.debug("Collected %d network connections", len(records))
        return records
