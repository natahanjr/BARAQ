"""Detector D001 - External RDP Logon (Phase 2).

Detects remote interactive logons (logon type 10) originating from an
external / public source IP. Deterministic, evidence-explainable, and with
zero side effects beyond producing a DETECTION.
"""

from __future__ import annotations

from backend.detection.context import DetectionContext
from backend.detection.contract import DETECTION, make_detection_id
from backend.detection.evidence import ev, first_ip, is_external
from backend.detection.registry import Detector
from backend.telemetry.contract import EVENT

REMOTE_INTERACTIVE_LOGON_TYPE = 10


class ExternalRDPDetector(Detector):
    id = "D001"
    version = "1.0.0"
    name = "External RDP Logon"
    description = (
        "Remote interactive (RDP) logon from an external/public source IP. "
        "Remote logon type 10 combined with an externally classified source."
    )
    enabled = True
    supported_event_types = ("authentication",)

    def evaluate(
        self, event: EVENT, context: DetectionContext | None = None
    ) -> DETECTION | None:
        if event.action != "logon":
            return None
        logon_type = event.facts.get("logon_type")
        try:
            logon_type = int(logon_type)
        except (TypeError, ValueError):
            return None
        if logon_type != REMOTE_INTERACTIVE_LOGON_TYPE:
            return None

        source_ip = first_ip(
            (event.network or {}).get("src_ip"),
            event.facts.get("source_ip"),
            event.facts.get("ip"),
        )
        if not source_ip or not is_external(source_ip):
            return None

        evidence = [
            ev("logon_type", logon_type, "Remote Interactive Logon (RDP)"),
            ev("source_ip", source_ip, "Source classified as external/public"),
            ev("host", event.host, "Target endpoint"),
            ev("user", event.user, "Account used for remote logon"),
        ]

        confidence = 0.70
        confidence += 0.15  # remote interactive logon
        confidence += 0.10  # external source
        if event.host and event.host != "-":
            confidence += 0.02
        if event.user and event.user != "-":
            confidence += 0.02

        return DETECTION(
            detector_id=self.id,
            detector_version=self.version,
            detection_id=make_detection_id(self.id, event.host, event.user, source_ip),
            event_id=event.fingerprint(),
            event_ids=(event.fingerprint(),),
            timestamp=event.timestamp,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            event_type=event.event_type,
            host_name=event.host,
            username=event.user,
            source_ip=source_ip,
            title="External Remote RDP Logon",
            description=(
                f"Remote interactive logon (type {logon_type}) to {event.host} "
                f"as {event.user} from external source {source_ip}."
            ),
            severity="high",
            confidence=confidence,
            mitre_tactic="Initial Access",
            mitre_technique="T1133",
            evidence=tuple(evidence),
            observables=(
                {"type": "ipv4-addr", "value": source_ip},
                {"type": "user-account", "value": event.user},
                {"type": "hostname", "value": event.host},
            ),
            status="new",
        )
