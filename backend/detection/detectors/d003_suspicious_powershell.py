"""Detector D003 - Suspicious PowerShell (Phase 2).

Detects PowerShell based on *contextual characteristics*, never on
"powershell.exe = malicious":

  * encoded command (e.g. -EncodedCommand, FromBase64String)
  * suspicious download (IEX, Invoke-WebRequest, DownloadString, ...)
  * execution from an unusual location (Temp / AppData / hidden window)

At least one characteristic is required; two or more raise severity.
"""
from __future__ import annotations

import re

from backend.detection.context import DetectionContext
from backend.detection.contract import DETECTION
from backend.detection.evidence import ev
from backend.detection.fp_filters import is_trusted_agent_activity
from backend.detection.registry import Detector
from backend.telemetry.contract import EVENT

_POWERSHELL_NAMES = {
    "powershell", "powershell.exe", "powershell_ise", "powershell_ise.exe",
    "pwsh", "pwsh.exe",
}

_ENCODED_RE = re.compile(r"-enc(oded)?(command)?\b", re.IGNORECASE)
_ENCODED_B64_RE = re.compile(r"frombase64string", re.IGNORECASE)
_DOWNLOAD_RE = re.compile(
    r"invoke-webrequest|\biwr\b|invoke-expression|\biex\b|downloadstring|"
    r"downloadfile|net\.webclient|\bcurl\b|\bwget\b|start-bitstransfer",
    re.IGNORECASE,
)
_UNUSUAL_LOCATION_RE = re.compile(
    r"\\temp\\|appdata\\local\\temp|users\\public|programdata|"
    r"/tmp/|/var/tmp/|/dev/shm",
    re.IGNORECASE,
)
# Only a genuinely hidden window counts; -nop is ubiquitous benign automation.
_HIDDEN_WINDOW_RE = re.compile(r"-windowstyle\s+hidden|-w\s+hidden\b", re.IGNORECASE)


class SuspiciousPowerShellDetector(Detector):
    id = "D003"
    version = "1.0.0"
    name = "Suspicious PowerShell"
    description = (
        "PowerShell with contextual suspicious characteristics: encoded "
        "commands, script download, or execution from an unusual location. "
        "Plain PowerShell is not suspicious by itself."
    )
    enabled = True
    supported_event_types = ("process",)

    def evaluate(self, event: EVENT, context: DetectionContext | None = None) -> DETECTION | None:
        proc = event.process or {}
        name = str(proc.get("name") or event.facts.get("process_name") or "").lower()
        if name not in _POWERSHELL_NAMES:
            return None

        command_line = str(
            proc.get("command_line")
            or proc.get("cmdline")
            or event.facts.get("command_line")
            or event.facts.get("commandLine")
            or event.facts.get("cmdline")
            or ""
        )
        path = str(proc.get("path") or event.facts.get("path") or "")

        # FP filter: trusted local automation tooling (e.g. coding agents
        # running helpers from their own Temp directory) never alerts here.
        if is_trusted_agent_activity(command_line, path):
            return None

        characteristics: list[tuple[str, str, str]] = []
        if _ENCODED_RE.search(command_line) or _ENCODED_B64_RE.search(command_line):
            characteristics.append(("encoded_command", "true", "Encoded/obfuscated command detected in command line"))
        if _DOWNLOAD_RE.search(command_line):
            characteristics.append(("script_download", "true", "PowerShell download/execute pattern in command line"))
        if _UNUSUAL_LOCATION_RE.search(path) or _HIDDEN_WINDOW_RE.search(command_line):
            characteristics.append(("unusual_location", path or command_line[:80], "Execution from unusual location / hidden window"))

        if not characteristics:
            return None

        n = len(characteristics)
        severity = "high" if n >= 2 else "medium"
        confidence = min(0.90, 0.55 + 0.15 * n)

        evidence = [
            ev("process", name, "PowerShell process"),
            ev("host", event.host, "Target endpoint"),
            ev("user", event.user, "Account that started the process"),
        ]
        evidence += [
            ev(field, value, reason) for field, value, reason in characteristics
        ]

        return DETECTION(
            detector_id=self.id,
            detector_version=self.version,
            event_id=event.fingerprint(),
            event_ids=(event.fingerprint(),),
            timestamp=event.timestamp,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            event_type=event.event_type,
            host_name=event.host,
            username=event.user,
            title="Suspicious PowerShell",
            description=(
                f"PowerShell ({name}) on {event.host} by {event.user} with "
                f"{n} suspicious characteristic(s): "
                + "; ".join(reason for _, _, reason in characteristics)
            ),
            severity=severity,
            confidence=confidence,
            mitre_tactic="Execution",
            mitre_technique="T1059.001",
            evidence=tuple(evidence),
            observables=(
                {"type": "process", "value": name},
                {"type": "hostname", "value": event.host},
                {"type": "user-account", "value": event.user},
            ),
            status="new",
        )