"""Rule - External C2 beacon / sustained exfiltration flows (MITRE T1071.001).

Flags sustained high-volume connections from a single process to a
single *external* remote IP - the network signature of a command-and-control
beacon or bulk data transfer that normal client traffic does not exhibit.

Emitted (process, remote) pairs are remembered with a cooldown so the same
sliding-window rows are not re-reported every scheduler cycle while still
re-checking candidates whose byte counters keep growing.
"""

from __future__ import annotations

import ipaddress
import json
import os
import time
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from backend.database.models import NetworkConnection, SystemState
from backend.detection.rules.base import BaseRule, DetectionResult

BEACON_BYTES_THRESHOLD = 5_000_000  # 5 MB in either direction to one remote IP
BEACON_MIN_CONNECTIONS = 3
BEACON_MIN_DURATION_SECONDS = 120.0

#: system_state key: JSON map of "process|remote" -> last emit epoch.
_COOLDOWN_KEY = "c2_beacon_emit_cooldown"

#: TEST-NET ranges are fixture/lab stand-ins. Production treats them as
#: non-external so documentation IPs never alert; tests set this to "1".
_TESTNET_EXTERNAL = os.environ.get("BARAQ_TESTNET_EXTERNAL", "0").lower() in (
    "1",
    "true",
    "yes",
)


def _is_external(ip: str) -> bool:
    """True when the address is routable (not private/loopback/link-local).

    TEST-NET documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) count as external only when ``BARAQ_TESTNET_EXTERNAL``
    is enabled (fixture / lab traffic).
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if addr.exploded.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
        return _TESTNET_EXTERNAL
    if addr.is_loopback or addr.is_link_local or addr.is_private:
        return False
    return not (addr.is_multicast or addr.is_reserved)


def _load_cooldowns(session) -> dict[str, float]:
    row = session.get(SystemState, _COOLDOWN_KEY)
    if row is None or not row.value:
        return {}
    try:
        data = json.loads(row.value)
        return {str(k): float(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}


def _save_cooldowns(session, data: dict[str, float]) -> None:
    payload = json.dumps(data)
    row = session.get(SystemState, _COOLDOWN_KEY)
    if row is None:
        session.add(SystemState(key=_COOLDOWN_KEY, value=payload))
    else:
        row.value = payload


class C2BeaconRule(BaseRule):
    rule_id = "c2_beacon"
    name = "External C2 Beacon / Bulk Transfer"
    description = (
        "A process maintained sustained high-volume connections to a single "
        "external address - consistent with command-and-control beaconing "
        "or large-scale exfiltration."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1071.001"
    recommendation = (
        "Block the remote host at the firewall, inspect the initiating "
        "process memory and parent chain, and hunt for additional beacon "
        "intervals or data stores on the host."
    )

    def __init__(
        self,
        session,
        bytes_threshold: int = BEACON_BYTES_THRESHOLD,
        min_connections: int = BEACON_MIN_CONNECTIONS,
        min_duration_seconds: float = BEACON_MIN_DURATION_SECONDS,
    ):
        super().__init__(session)
        self.bytes_threshold = bytes_threshold
        self.min_connections = min_connections
        self.min_duration_seconds = min_duration_seconds

    def evaluate(self, window_minutes: int, since_id: int | None = None) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(NetworkConnection).where(
                NetworkConnection.observed_at >= since,
                *self._org_conds(NetworkConnection),
            )
        ).all()

        buckets: dict[tuple[str, str], dict] = defaultdict(
            lambda: {"count": 0, "sent": 0, "recv": 0, "max_duration": 0.0}
        )
        for conn in rows:
            remote = (conn.remote_ip or "").strip()
            if not _is_external(remote):
                continue
            process = (conn.process or "?").strip() or "?"
            bucket = buckets[(process, remote)]
            bucket["count"] += 1
            bucket["sent"] += conn.bytes_sent or 0
            bucket["recv"] += conn.bytes_recv or 0
            bucket["max_duration"] = max(
                bucket["max_duration"], conn.duration_seconds or 0.0
            )

        now = time.time()
        cooldown_sec = max(window_minutes, 1) * 60.0
        cooldowns = _load_cooldowns(self.session)
        # Drop entries that can no longer suppress a re-fire in this window.
        cooldowns = {
            k: v for k, v in cooldowns.items() if now - v < cooldown_sec * 2
        }
        dirty = False

        for (process, remote), stats in buckets.items():
            total = stats["sent"] + stats["recv"]
            if total < self.bytes_threshold:
                continue
            if stats["count"] < self.min_connections:
                continue
            if stats["max_duration"] < self.min_duration_seconds:
                continue

            pair_key = f"{process}|{remote}"
            last = cooldowns.get(pair_key)
            if last is not None and now - last < cooldown_sec:
                # Already reported this pair within the cooldown - do not
                # re-emit the same sliding-window rows every cycle.
                continue

            confidence = min(
                0.95,
                self.confidence + 0.05 * (stats["count"] >= self.min_connections * 2),
            )
            findings.append(
                self._result(
                    evidence=(
                        f"Process '{process}' exchanged {total:,} bytes with "
                        f"external host {remote} across {stats['count']} "
                        f"connections (longest {stats['max_duration']:.0f}s) - "
                        f"possible C2 beacon or bulk exfiltration."
                    ),
                    event_ids=[],
                    confidence=confidence,
                )
            )
            cooldowns[pair_key] = now
            dirty = True

        if dirty:
            _save_cooldowns(self.session, cooldowns)
        return findings
