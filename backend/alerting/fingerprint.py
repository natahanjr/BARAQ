"""Deterministic alert fingerprint (spec 3.7).

``hash(detector_id + host_id + user_id + source_ip + mitre_technique)`` -
stable, reproducible, independent of alert id and timestamps. Never a
random UUID: UUIDs are fine as alert IDs, never as dedup keys.
"""

from __future__ import annotations

import hashlib
import json

from backend.detection.contract import DETECTION


def fingerprint(detection: DETECTION) -> str:
    """Deterministic dedup key for an alert built from this detection."""
    payload = {
        "detector_id": detection.detector_id,
        "host_id": detection.host_id or detection.host_name,
        "user_id": detection.user_id or detection.username,
        "source_ip": detection.source_ip,
        "mitre_technique": detection.mitre_technique,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
