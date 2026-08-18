"""BARAQ Phase 3 - Alert Management (EVENT -> DETECTION -> ALERT).

Converts validated Phase 2 DETECTIONs into analyst-facing ALERTs with
deterministic deduplication, explicit lifecycle, analyst feedback, audit
trail and controlled suppression. ALERT is NOT an INCIDENT; this package
never creates incidents, never mutates risk and never executes SOAR.
See docs/phase3/ALERT_CONTRACT.md.
"""
from backend.alerting.contract import ALERT, ALERT_SEVERITIES, ALERT_STATUSES
from backend.alerting.engine import process_detection

__all__ = ["ALERT", "ALERT_SEVERITIES", "ALERT_STATUSES", "process_detection"]