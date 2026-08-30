"""Base adapter interface and shared utilities for external SOC datasets."""

from __future__ import annotations

import hashlib
import ipaddress
import math
from abc import ABC, abstractmethod
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict


class NormalizedEventDict(TypedDict, total=False):
    """Shape matching BARAQ's ``NormalizedEvent`` raw_json.facts structure.

    Every adapter must populate at minimum: event_id, channel, timestamp,
    host, user, message.  The ``raw`` dict carries facts that
    ``event_feature_vector()`` reads.
    """

    event_id: int
    channel: str
    timestamp: str
    host: str
    user: str
    message: str
    source_ip: str
    attack_chain: str | None
    stage: str | None
    source: str
    label: int
    raw: dict[str, Any]


class AdapterResult(TypedDict):
    """Outcome of an adapter run."""

    total: int
    loaded: int
    skipped: int
    errors: list[str]
    events: list[NormalizedEventDict]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
COMMON_LOGON_TYPES = frozenset({2, 3, 7, 10, 11})
NIGHT_HOURS = frozenset({0, 1, 2, 3, 4, 5, 22, 23})

# Sysmon event IDs that indicate attacks in BARAQ's heuristic
_ATTACK_EVENT_IDS = frozenset({4720, 4732, 7045, 4698, 1102})
_BENIGN_EVENT_IDS = frozenset({4634, 4647, 4771})


def parse_ts(raw: Any) -> datetime | None:
    """Best-effort parse of timestamp from various string formats."""
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    text = str(raw).strip()
    if not text:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f+00:00",
        "%Y-%m-%dT%H:%M:%S+00:00",
    ):
        try:
            dt = datetime.strptime(text, fmt)  # naive parse; tz added below
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def fingerprint(event: NormalizedEventDict) -> str:
    """Deterministic dedup key for an event."""
    key = f"{event.get('timestamp')}-{event.get('event_id')}-{event.get('host')}-{event.get('message', '')[:128]}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP is RFC1918 / loopback / link-local."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def ip_to_int(ip_str: str) -> float:
    """Convert dotted-quad IP to numeric (same logic as _ip_feature in anomaly.py)."""
    try:
        parts = [int(p) for p in ip_str.split(".") if p.isdigit()]
        if len(parts) == 4:
            return float(
                (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
            )
    except (TypeError, ValueError):
        pass
    return 0.0


def shannon_entropy(text: str) -> float:
    """Normalized Shannon entropy of a string (0..1)."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for c in counts.values():
        p = c / length
        if p > 0:
            entropy -= p * math.log2(p)
    return min(1.0, entropy / 7.0)


def heuristic_label(event: NormalizedEventDict) -> int:
    """Apply BARAQ's heuristic labeling to an event.

    Returns 1 (attack) or 0 (benign).  Analyses use this for unsupervised
    training; analyst labels override when present.
    """
    eid = event.get("event_id", 0)
    if eid in _ATTACK_EVENT_IDS:
        return 1
    if eid in _BENIGN_EVENT_IDS:
        return 0

    # PowerShell: check for suspicious patterns
    if eid in (4104, 4103):
        cmdline = (event.get("raw") or {}).get("command_line", "")
        if any(
            tok in cmdline.lower()
            for tok in (
                "hidden",
                "bypass",
                "nop",
                "iex",
                "downloadstring",
                "invoke-expression",
            )
        ):
            return 1
        return 0

    # Failed logon: check sub_status
    if eid == 4625:
        raw = event.get("raw") or {}
        sub = raw.get("sub_status", 0)
        try:
            sub_int = int(sub)
        except (ValueError, TypeError):
            sub_int = 0
        if sub_int in (3221226036, 3221225586):
            return 1

    # Network events: check for known-bad ports or external IPs
    if event.get("source") == "network":
        remote_ip = (event.get("raw") or {}).get("remote_ip", "")
        if remote_ip and not is_private_ip(remote_ip):
            return 0.6  # moderate risk

    return 0


class BaseAdapter(ABC):
    """Base class for all dataset adapters.

    Subclasses implement ``iter_events()`` which yields raw records from
    the source dataset, and ``parse_event()`` which converts a single
    record into BARAQ's normalized format.
    """

    name: str = "base"
    description: str = ""

    @abstractmethod
    def iter_events(self, path: Path) -> Generator[dict, None, None]:
        """Yield raw event dicts from the dataset at *path*."""
        ...

    @abstractmethod
    def parse_event(self, raw: dict) -> NormalizedEventDict | None:
        """Convert a single raw event into BARAQ's normalized format.

        Return None to skip unparseable records.
        """
        ...

    def load(self, path: Path, *, max_events: int = 0) -> AdapterResult:
        """Load and convert all events from a dataset path.

        Args:
            path: Directory or file containing the dataset.
            max_events: Stop after this many events (0 = unlimited).

        Returns:
            AdapterResult with loaded events, counts, and any errors.
        """
        events: list[NormalizedEventDict] = []
        seen: set[str] = set()
        errors: list[str] = []
        total = 0
        skipped = 0

        for raw in self.iter_events(path):
            total += 1
            if max_events and len(events) >= max_events:
                break
            if not isinstance(raw, dict):
                skipped += 1
                continue
            try:
                parsed = self.parse_event(raw)
                if parsed is None:
                    skipped += 1
                    continue
                fp = fingerprint(parsed)
                if fp in seen:
                    skipped += 1
                    continue
                seen.add(fp)
                # Apply heuristic label if not already labeled
                if "label" not in parsed:
                    parsed["label"] = heuristic_label(parsed)
                events.append(parsed)
            except Exception as exc:
                errors.append(f"event {total}: {exc}")
                skipped += 1
                if len(errors) > 100:
                    break

        return AdapterResult(
            total=total,
            loaded=len(events),
            skipped=skipped,
            errors=errors,
            events=events,
        )
