"""Detector D005 - Ransomware behavior (Phase 2).

Requires behavioral evidence, never a single file event:

  * 20+ file modification events on one host within 5 minutes
  * shadow copy deletion in the same window raises confidence
  * 50+ modifications raise confidence further

Produces a DETECTION only - never a CRITICAL INCIDENT by itself.
"""
from __future__ import annotations

from collections import Counter

from backend.detection.context import DetectionContext
from backend.detection.contract import DETECTION
from backend.detection.evidence import ev
from backend.detection.registry import Detector
from backend.telemetry.contract import EVENT

FILE_THRESHOLD = 20
HIGH_RATE_COUNT = 50
WINDOW_MINUTES = 5
SHADOW_MARKERS = ("vssadmin", "delete shadows", "shadowcopy", "shadow_delete", "wmic shadowcopy delete")


def _is_file_modification(event: EVENT) -> bool:
    action = event.action.lower()
    if event.event_type in ("file",):
        return any(k in action for k in ("modify", "write", "create", "change", "rename"))
    return any(k in action for k in ("file_modify", "file_write", "file_create", "file_rename"))


def _is_shadow_delete(event: EVENT) -> bool:
    action = event.action.lower()
    if "shadow" in action and ("delete" in action or "remove" in action):
        return True
    proc = event.process or {}
    command_line = str(proc.get("command_line") or event.facts.get("command_line") or "").lower()
    return "vssadmin" in command_line and "delete" in command_line


class RansomwareBehaviorDetector(Detector):
    id = "D005"
    version = "1.0.0"
    name = "Ransomware Behavior"
    description = (
        f"Behavioral mass file modification: {FILE_THRESHOLD}+ file "
        f"modifications on one host within {WINDOW_MINUTES} minutes. "
        "Shadow copy deletion or a very high modification rate escalates "
        "severity to high."
    )
    enabled = True
    supported_event_types = ()  # file events may arrive under any event_type

    def evaluate(self, event: EVENT, context: DetectionContext | None = None) -> DETECTION | None:
        if not _is_file_modification(event):
            return None

        if context is None:
            return None

        window = context.events_in_window(
            event.timestamp, WINDOW_MINUTES, host=event.host, limit=10_000
        )
        file_events = [e for e in window if _is_file_modification(e)]
        stored_current = any(e.fingerprint == event.fingerprint() for e in file_events)
        count = len(file_events) + (0 if stored_current else 1)

        if count < FILE_THRESHOLD or count % FILE_THRESHOLD != 0:
            return None

        shadow = any(_is_shadow_delete(e) for e in window) or _is_shadow_delete(event)

        confidence = 0.60
        if count >= HIGH_RATE_COUNT:
            confidence += 0.15
        if shadow:
            confidence += 0.15

        severity = "medium"
        if count >= HIGH_RATE_COUNT or shadow:
            severity = "high"

        processes = Counter(
            str((e.process or {}).get("name") or "-") for e in file_events
        )
        top_process = processes.most_common(1)[0][0] if processes else "-"

        event_ids = tuple(e.fingerprint for e in file_events) + (event.fingerprint(),)

        evidence = [
            ev("file_modifications", count, f"within {WINDOW_MINUTES} minutes (threshold {FILE_THRESHOLD})"),
            ev("window_minutes", WINDOW_MINUTES, "defined evaluation window"),
            ev("host", event.host, "Target endpoint"),
            ev("process", top_process, "Most frequent process performing modifications"),
        ]
        if shadow:
            evidence.append(ev("shadow_copy_deletion", True, "Shadow copy deletion observed - recovery undermined"))

        return DETECTION(
            detector_id=self.id,
            detector_version=self.version,
            event_id=event.fingerprint(),
            event_ids=event_ids,
            timestamp=event.timestamp,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            event_type=event.event_type,
            host_name=event.host,
            title="Ransomware Behavior - Mass File Modification",
            description=(
                f"{count} file modifications on {event.host} within "
                f"{WINDOW_MINUTES} minutes"
                + ("; shadow copy deletion observed" if shadow else "")
            ),
            severity=severity,
            confidence=confidence,
            mitre_tactic="Impact",
            mitre_technique="T1486",
            evidence=tuple(evidence),
            observables=(
                {"type": "hostname", "value": event.host},
                {"type": "process", "value": top_process},
            ),
            status="new",
        )