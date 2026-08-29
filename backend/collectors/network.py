"""Network connection collector using psutil net_connections()."""
from __future__ import annotations

import ipaddress
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

# Heuristic org tagging by well-known IP prefixes (no network egress).
_ORG_PREFIXES = [
    ("13.107", "Microsoft"), ("52.96", "Microsoft"), ("52.123", "Microsoft 365"),
    ("52.110", "Microsoft 365"), ("135.116", "Microsoft"), ("204.79.197", "Microsoft"),
    ("142.250", "Google"), ("142.251", "Google"), ("172.217", "Google"), ("216.58", "Google"),
    ("173.194", "Google"), ("74.125", "Google"),
    ("149.154", "Telegram"), ("91.108", "Telegram"),
    ("162.159", "Cloudflare"), ("104.16", "Cloudflare"), ("172.64", "Cloudflare"),
    ("20.190", "Azure"), ("20.86", "Azure"), ("40.1", "Azure"), ("98.66", "Azure"),
    ("140.82", "GitHub"), ("199.232", "GitHub"),
    ("13.107.4", "Microsoft"),
]


def _classify(ip: str) -> str:
    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return "internal"
    if addr.is_multicast:
        return "multicast"
    return "external"


def _org_for(ip: str) -> str:
    if _classify(ip) != "external":
        return ""
    for prefix, org in _ORG_PREFIXES:
        if ip.startswith(prefix):
            return org
    return "Unknown"


class NetworkCollector(BaseCollector):
    """Observes active TCP/UDP connections and listening sockets.

    Flow metadata notes (Windows limitation):
    - psutil only exposes **per-process** cumulative I/O counters, not per-socket
      bytes. To make per-connection byte figures meaningful we distribute the
      process's total I/O equally across that process's observed connections
      (so the per-connection numbers sum to the true process total). The UI
      labels these as "process-shared" estimates.
    - True connection duration is tracked via an in-memory first-seen map
      (keyed by the 5-tuple) since Windows does not expose socket open time.
    """

    name = "network"

    def __init__(self):
        super().__init__()
        # (pid, lip, lport, rip, rport) -> first_seen timestamp
        self._first_seen: dict[tuple, float] = {}

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

    def _prune_first_seen(self, live_keys: set[tuple]) -> None:
        """Drop stale 5-tuple keys so the map does not grow forever."""
        for k in list(self._first_seen.keys()):
            if k not in live_keys:
                self._first_seen.pop(k, None)

    def collect(self) -> list[dict]:
        if not self.enabled():
            return []
        records: list[dict] = []
        now = datetime.now(timezone.utc)
        now_ts = now.timestamp()
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.logger.warning("Access denied reading network connections")
            return []

        # Pass 1: collect raw rows + count connections per pid for I/O distribution
        raw = []
        per_pid = {}
        live_keys = set()
        for conn in conns:
            pid = conn.pid or 0
            lip = conn.laddr.ip if conn.laddr else ""
            lport = conn.laddr.port if conn.laddr else 0
            rip = conn.raddr.ip if conn.raddr else ""
            rport = conn.raddr.port if conn.raddr else 0
            key = (pid, lip, lport, rip, rport)
            live_keys.add(key)
            per_pid[pid] = per_pid.get(pid, 0) + 1
            raw.append({
                "pid": pid,
                "process": self._pid_name(pid) if pid else "",
                "local_ip": lip,
                "local_port": lport,
                "remote_ip": rip,
                "remote_port": rport,
                "state": conn.status or "",
                "is_listening": conn.status in LISTEN_STATES,
                "key": key,
            })

        # Pass 2: distribute process I/O equally across its connections
        pid_io = {}
        for pid, count in per_pid.items():
            if pid:
                tot_sent, tot_recv = self._pid_io(pid)
                pid_io[pid] = (tot_sent // max(count, 1), tot_recv // max(count, 1))

        self._prune_first_seen(live_keys)

        for r in raw:
            key = r.pop("key")
            if key not in self._first_seen:
                self._first_seen[key] = now_ts
            duration = round(max(0.0, now_ts - self._first_seen[key]), 2)
            sent, recv = pid_io.get(r["pid"], (0, 0))
            records.append({
                "source": "network",
                "pid": r["pid"],
                "process": r["process"],
                "local_ip": r["local_ip"],
                "local_port": r["local_port"],
                "remote_ip": r["remote_ip"],
                "remote_port": r["remote_port"],
                "state": r["state"],
                "is_listening": r["is_listening"],
                "bytes_sent": sent,
                "bytes_recv": recv,
                "duration_seconds": duration,
                "org": _org_for(r["remote_ip"]),
                "timestamp": now.isoformat(),
            })
        self.logger.debug("Collected %d network connections", len(records))
        return records
