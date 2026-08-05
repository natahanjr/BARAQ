"""Rule - Removable Media / USB Device Insertion (MITRE T1091, Lateral Movement).

Flags insertion of new USB storage devices, which may be used to move
malware onto the host or exfiltrate data (autorun / replication through
removable media).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.database.models import UsbDevice
from backend.detection.rules.base import BaseRule, DetectionResult


class UsbDeviceRule(BaseRule):
    rule_id = "usb_device"
    name = "Removable Storage Device Inserted"
    description = (
        "A new USB / removable storage device was recognised on the endpoint. "
        "Such devices are a common vector for malware transfer (T1091) and "
        "data exfiltration, and should be reviewed in context."
    )
    severity = "medium"
    confidence = 0.70
    mitre_id = "T1091"
    recommendation = (
        "Identify the person who attached the device, restrict USB write "
        "access and Autorun, and scan the media before further mounting."
    )

    def __init__(self, session, window_minutes: int = 30):
        super().__init__(session)
        self.window_minutes = window_minutes

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        since = datetime.now(timezone.utc) - timedelta(minutes=self.window_minutes or window_minutes)
        findings: list[DetectionResult] = []

        devices = self.session.scalars(
            select(UsbDevice).where(UsbDevice.inserted_at >= since)
        ).all()

        for dev in devices:
            evidence = (
                f"Removable device inserted at {dev.inserted_at.isoformat()}: "
                f"'{dev.device_name}' (id={dev.device_id or 'unknown'}, "
                f"vendor={dev.vendor or 'unknown'}, serial={dev.serial or 'unknown'})."
            )
            findings.append(
                self._result(
                    evidence=evidence,
                    event_ids=[],
                    severity="medium",
                    confidence=0.7,
                )
            )
        return findings
