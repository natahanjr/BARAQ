"""Rule set - Collection techniques (TA0009).

Covers clipboard capture (T1115), screen capture (T1113), archive
collection (T1560.001) and data from local systems (T1005).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from backend.detection.rules.base import BaseRule, DetectionResult

_CLIPBOARD = re.compile(
    r"\b(?:Get-Clipboard|Set-Clipboard|Get-ClipboardText)\b|"
    r"\bclip\.exe\b|\bclipboard\b[^\n]*\b(?:view|dump|capture)\b",
    re.IGNORECASE,
)
_SCREEN_CAPTURE = re.compile(
    r"\b(?:CopyFromScreen|PrintWindow|BitBlt|GetDC)\b|"
    r"\bscreenshot\b|\b(?:nircmd|scrot|import)\b[^\n]*\bsave\b|"
    r"\b(?:-Width\b[^\n]*\b-Height\b)",
    re.IGNORECASE,
)
_ARCHIVE = re.compile(
    r"\b(?:7z|rar|zip|tar|cabarc)\.exe\b[^\n]*\b(?:a|m|c|d)\b[^\n]*"
    r"(?:\\Users\\|\\.ssh\b|\\.aws\b|\\.git\b|Documents|Desktop|AppData)",
    re.IGNORECASE,
)
_LOCAL_DATA = re.compile(
    r"\b(?:copy|robocopy|xcopy)\b[^\n]*\\Users\\.*(?:Documents|Desktop|Downloads)|"
    r"\b(?:Get-Content|Type)\b[^\n]*\\.(?:kdbx|key|pem|pfx|config|env)\b|"
    r"\bcat\b[^\n]*\b(?:id_rsa|id_ed25519)\b",
    re.IGNORECASE,
)


class ClipboardCaptureRule(BaseRule):
    rule_id = "clipboard_capture"
    name = "Clipboard Capture"
    description = (
        "Clipboard contents were read or written - harvesting passwords, "
        "tokens and sensitive text copied by users."
    )
    severity = "medium"
    confidence = 0.7
    mitre_id = "T1115"
    recommendation = (
        "Clear clipboard history, review what the capturing process "
        "accessed, and rotate credentials that may have been copied."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _CLIPBOARD.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Clipboard access by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class ScreenCaptureRule(BaseRule):
    rule_id = "screen_capture"
    name = "Screen Capture"
    description = (
        "GDI screen-capture APIs or screenshot tools were invoked - "
        "capturing sensitive on-screen information."
    )
    severity = "medium"
    confidence = 0.65
    mitre_id = "T1113"
    recommendation = (
        "Review the captured images if found, restrict screen-capture "
        "tooling, and monitor for exfiltration of the image files."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _SCREEN_CAPTURE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Screen capture by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class ArchiveCollectionRule(BaseRule):
    rule_id = "archive_collection"
    name = "Archive of Sensitive Data"
    description = (
        "An archive was created over user data (documents, credentials, "
        "keys) - staging data for collection and exfiltration."
    )
    severity = "medium"
    confidence = 0.7
    mitre_id = "T1560.001"
    recommendation = (
        "Inspect the archive contents, check for matching exfiltration "
        "traffic, and review the archiving process and its source paths."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _ARCHIVE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Archive created over sensitive data by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class LocalDataCollectionRule(BaseRule):
    rule_id = "local_data_collection"
    name = "Sensitive Local File Collection"
    description = (
        "Files holding credentials or sensitive documents were copied or "
        "read - collection of data from the local system."
    )
    severity = "medium"
    confidence = 0.65
    mitre_id = "T1005"
    recommendation = (
        "Identify which files were collected, rotate exposed credentials, "
        "and watch for exfiltration of the copied data."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _LOCAL_DATA.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Sensitive file collection by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings
