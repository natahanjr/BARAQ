"""Rule - External C2 beaconing and bulk exfiltration (MITRE T1071.001).

Two genuinely different behaviours live in this rule, and conflating them is
what makes it cry wolf:

* **C2 beaconing** - many *small* connections to one external address. The
  volume is low; the *repetition* is the signal. This is the high-severity
  path.
* **Bulk transfer** - a few *large* connections (a 4 GB browser download, a
  cloud-sync client, Windows Update). High volume, no repetition. This is
  informational only, and is suppressed for well-known bulk-transfer programs
  because a desktop that browses the web is not an incident.

The earlier version fired on ">= 5 MB total, >= 3 connections, one long
connection", which every Firefox/Edge/Telegram/Discord session satisfies - on
a real laptop that produced 8 high-severity alerts in a single pass, all of
them ordinary software talking to Google, Cloudflare and Microsoft.
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

# --- beaconing (repetition is the signal) ----------------------------------
BEACON_BYTES_THRESHOLD = 1_000_000  # 1 MB total, spread over many transfers
BEACON_MIN_CONNECTIONS = 8  # repetition, not one-off traffic
#: A beacon carries a small payload per connection. Above this average the
#: traffic is a transfer, not a beacon.
BEACON_MAX_AVG_BYTES = 256 * 1024
BEACON_MIN_DURATION_SECONDS = 120.0

# --- bulk transfer (volume is the signal) ---------------------------------
#: Deliberately high for ordinary programs: at 5 MB this fired on browsing.
BULK_BYTES_THRESHOLD = 250_000_000  # 250 MB in the window
#: ...but 24 MB leaving a PowerShell to an external host is not "browsing".
#: For interpreters and LOLBins any significant external transfer is worth a
#: look, so they get their own, much lower bar.
BULK_SUSPICIOUS_BYTES_THRESHOLD = 5_000_000
BULK_MIN_CONNECTIONS = 3
BULK_MIN_DURATION_SECONDS = 300.0

#: Programs that have no business moving bulk data off the host. Volume from
#: one of these is meaningful at a level that would be noise from a browser.
SUSPICIOUS_TRANSFER_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "wmic.exe",
    "installutil.exe",
    "msbuild.exe",
}

#: Programs that legitimately move large volumes. A beacon from one of these
#: is still reported (the beacon path is shape-based, not name-based) - only
#: the volume-driven bulk path is suppressed.
BENIGN_BULK_PROCESSES = {
    "firefox.exe",
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "thunderbird.exe",
    "outlook.exe",
    "onedrive.exe",
    "dropbox.exe",
    "googledrivefs.exe",
    "rclone.exe",
    "telegram.exe",
    "discord.exe",
    "slack.exe",
    "zoom.exe",
    "teams.exe",
    "svchost.exe",  # Windows Update / BITS
    "wuauclt.exe",
    "tiworker.exe",
    "searchindexer.exe",
    "mbamain.exe",
    "mrt.exe",
    # Chromium/WebView and desktop dev tooling move the same volumes through
    # the same hosts as anything else; measured on real traffic.
    "msedgewebview2.exe",
    "msedge.exe",
    "webview2.exe",
    "code.exe",
    "code-sidecar.exe",
    "electron.exe",
    "opencode.exe",
    "grammarly.desktop.exe",
    "crossdeviceservice.exe",
    "node.exe",
}

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
    name = "External C2 Beaconing / Bulk Transfer"
    description = (
        "A process either beaconed - many small connections to one external "
        "address - or moved an unusually large volume to one external "
        "address. Repetition separates command-and-control from ordinary "
        "bulk transfer."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1071.001"
    recommendation = (
        "For beaconing: block the remote host, inspect the process memory and "
        "parent chain, and hunt for the implant. For bulk transfer: confirm "
        "the transfer was expected before acting."
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
            lambda: {
                "count": 0,
                "sent": 0,
                "recv": 0,
                "max_duration": 0.0,
                "peak": 0,
            }
        )
        for conn in rows:
            remote = (conn.remote_ip or "").strip()
            if not _is_external(remote):
                continue
            process = (conn.process or "?").strip() or "?"
            volume = (conn.bytes_sent or 0) + (conn.bytes_recv or 0)
            bucket = buckets[(process, remote)]
            bucket["count"] += 1
            bucket["sent"] += conn.bytes_sent or 0
            bucket["recv"] += conn.bytes_recv or 0
            bucket["max_duration"] = max(
                bucket["max_duration"], conn.duration_seconds or 0.0
            )
            bucket["peak"] = max(bucket["peak"], volume)

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
            count = stats["count"]
            avg_bytes = total / count if count else 0.0
            proc_key = process.lower()
            suspicious_proc = proc_key in SUSPICIOUS_TRANSFER_PROCESSES

            # --- classify by shape before deciding anything ---
            # Beaconing: repetition of SMALL transfers.
            is_beacon = (
                count >= self.min_connections
                and total >= self.bytes_threshold
                and avg_bytes <= BEACON_MAX_AVG_BYTES
                and stats["max_duration"] >= self.min_duration_seconds
            )
            # Bulk transfer: few LARGE transfers. The bar depends on WHO is
            # moving the data - 5 MB from powershell.exe is exfiltration,
            # 5 MB from firefox.exe is a video.
            bulk_threshold = (
                BULK_SUSPICIOUS_BYTES_THRESHOLD
                if suspicious_proc
                else BULK_BYTES_THRESHOLD
            )
            is_bulk = (
                count >= BULK_MIN_CONNECTIONS
                and total >= bulk_threshold
                and avg_bytes > BEACON_MAX_AVG_BYTES
                and stats["max_duration"] >= BULK_MIN_DURATION_SECONDS
            )
            if not (is_beacon or is_bulk):
                continue
            if is_bulk and not suspicious_proc and proc_key in BENIGN_BULK_PROCESSES:
                # A browser downloading a video is not an incident.
                continue

            pair_key = f"{process}|{remote}"
            last = cooldowns.get(pair_key)
            if last is not None and now - last < cooldown_sec:
                # Already reported this pair within the cooldown - do not
                # re-emit the same sliding-window rows every cycle.
                continue

            if is_beacon:
                confidence = min(0.95, 0.75 + 0.02 * (count >= self.min_connections * 2))
                evidence = (
                    f"Process '{process}' made {count} connections to external "
                    f"host {remote} carrying {total:,} bytes total "
                    f"(~{avg_bytes:,.0f} B per connection, longest "
                    f"{stats['max_duration']:.0f}s) - the small, repeated "
                    f"transfers are consistent with C2 beaconing."
                )
                severity = "high"
            elif suspicious_proc:
                # An interpreter or LOLBin shipping bulk data off-host.
                confidence = 0.6
                evidence = (
                    f"Process '{process}' moved {total:,} bytes to external host "
                    f"{remote} across {count} connections (largest single "
                    f"connection {stats['peak']:,} B, longest "
                    f"{stats['max_duration']:.0f}s). {process} has no normal "
                    f"reason to bulk-transfer data off this host - treat as "
                    f"possible exfiltration or a download-and-execute stage."
                )
                severity = "medium"
            else:
                # Informational: volume alone, with no repetition, is a much
                # weaker signal and must not page anyone.
                confidence = 0.4
                evidence = (
                    f"Process '{process}' moved {total:,} bytes to external "
                    f"host {remote} across {count} connections (largest single "
                    f"connection {stats['peak']:,} B, longest "
                    f"{stats['max_duration']:.0f}s) - large transfer, not "
                    f"repetitive. Confirm this was expected."
                )
                severity = "low"

            findings.append(
                self._result(
                    evidence=evidence,
                    event_ids=[],
                    confidence=confidence,
                    severity=severity,
                )
            )
            cooldowns[pair_key] = now
            dirty = True

        if dirty:
            _save_cooldowns(self.session, cooldowns)
        return findings
