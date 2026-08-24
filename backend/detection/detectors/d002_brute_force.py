"""Detector D002 - Brute Force (Phase 2).

Detects repeated authentication failures in a defined event window.
Never triggers on a single failed login. A successful login inside the
window escalates severity and raises confidence.

Deterministic rules:
  * failure threshold : 10 failed logons within 15 minutes
  * escalation       : 30+ failures, or 20+ failures + a successful logon
  * fires on the failure event that crosses a threshold multiple
"""
from __future__ import annotations

from sqlalchemy import select

from backend.detection.context import DetectionContext
from backend.detection.contract import DETECTION, make_detection_id
from backend.detection.evidence import ev, first_ip
from backend.detection.registry import Detector
from backend.telemetry.contract import EVENT

FAILURE_THRESHOLD = 10
WINDOW_MINUTES = 15
HIGH_COUNT = 30
ESCALATE_COUNT_WITH_SUCCESS = 20


class BruteForceDetector(Detector):
    id = "D002"
    version = "1.0.0"
    name = "Brute Force"
    description = (
        "Repeated authentication failures against the same account within "
        f"{WINDOW_MINUTES} minutes ({FAILURE_THRESHOLD}+). A successful "
        "login in the window escalates severity and confidence."
    )
    enabled = True
    supported_event_types = ("authentication",)

    def evaluate(self, event: EVENT, context: DetectionContext | None = None) -> DETECTION | None:
        if event.action != "logon_failed":
            return None

        failures, success_events = self._window_counts(event, context)
        count = failures + (0 if self._stored(event, context) else 1)

        # Threshold crossing: deterministic - fires at each multiple.
        if count < FAILURE_THRESHOLD or count % FAILURE_THRESHOLD != 0:
            return None

        success = len(success_events) > 0
        if count >= HIGH_COUNT or (success and count >= ESCALATE_COUNT_WITH_SUCCESS):
            severity = "high"
        else:
            severity = "medium"

        src_ips = sorted(
            {
                ip
                for e in success_events
                for ip in [first_ip(
                    (e.network or {}).get("src_ip"),
                    (e.facts or {}).get("source_ip"),
                )]
                if ip
            }
        )
        if (ip := first_ip((event.network or {}).get("src_ip"), event.facts.get("source_ip"))):
            src_ips.append(ip)
        src_ips = sorted(set(src_ips))

        confidence = min(0.90, 0.60 + 0.02 * (count // FAILURE_THRESHOLD))
        if success:
            confidence += 0.08

        evidence = [
            ev("failed_logons", count, f"within {WINDOW_MINUTES} minutes (threshold {FAILURE_THRESHOLD})"),
            ev("window_minutes", WINDOW_MINUTES, "defined evaluation window"),
            ev("host", event.host, "Target endpoint"),
            ev("user", event.user, "Target account"),
        ]
        if src_ips:
            evidence.append(ev("source_ips", ",".join(src_ips[:5]), "Source addresses observed"))
        if success:
            evidence.append(ev("successful_logon", len(success_events), "Successful login within window - escalation"))

        event_ids = tuple(e.fingerprint for e in success_events) + (
            event.fingerprint(),
        )

        return DETECTION(
            detector_id=self.id,
            detector_version=self.version,
            detection_id=make_detection_id(self.id, event.host, event.user),
            event_id=event.fingerprint(),
            event_ids=event_ids,
            timestamp=event.timestamp,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            event_type=event.event_type,
            host_name=event.host,
            username=event.user,
            source_ip=src_ips[0] if src_ips else "",
            title="Brute Force - Repeated Authentication Failures",
            description=(
                f"{count} failed logons for {event.user}@{event.host} within "
                f"{WINDOW_MINUTES} minutes"
                + ("; successful logon observed in the same window" if success else "")
            ),
            severity=severity,
            confidence=confidence,
            mitre_tactic="Credential Access",
            mitre_technique="T1110",
            evidence=tuple(evidence),
            observables=(
                {"type": "user-account", "value": event.user},
                {"type": "hostname", "value": event.host},
            )
            + tuple({"type": "ipv4-addr", "value": ip} for ip in src_ips),
            status="new",
        )

    @staticmethod
    def _window_counts(event: EVENT, context: DetectionContext | None):
        if context is None:
            return 0, []
        failures = context.events_in_window(
            event.timestamp, WINDOW_MINUTES,
            host=event.host, user=event.user, action="logon_failed",
        )
        successes = context.events_in_window(
            event.timestamp, WINDOW_MINUTES,
            host=event.host, user=event.user, action="logon",
        )
        return len(failures), successes

    @staticmethod
    def _stored(event: EVENT, context: DetectionContext | None) -> bool:
        if context is None or context._db is None:  # noqa: SLF001 - internal probe
            return False
        from backend.telemetry.models import TelemetryEvent

        hit = context._db.scalars(  # noqa: SLF001
            select(TelemetryEvent.fingerprint).where(
                TelemetryEvent.fingerprint == event.fingerprint()
            )
        ).first()
        return hit is not None