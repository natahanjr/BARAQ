"""Phase 5 labeled evaluation corpus (spec 5.62).

Small, deterministic, hand-labeled dataset measuring correlation quality
WITHOUT inventing an accuracy percentage. Each scenario fabricates alerts,
aggregates them into behavior groups, then labels which group chains MUST
correlate (``correlated: True``) and which MUST NOT.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.alerting.models import AlertRecord
from backend.aggregation.engine import process_alerts
from backend.aggregation.models import BehaviorGroupRecord

T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=timezone.utc)


def _fabricate(db: Session, spec: dict, base: datetime, index: int) -> AlertRecord:
    ts = base + timedelta(minutes=spec.get("minutes", 0.0))
    detector_id = spec.get("detector_id", "D001")
    return AlertRecord(
        alert_id="",
        alert_fingerprint="f" * 64,
        detector_id=detector_id,
        detector_version="1.0.0",
        title=spec.get("title", f"{detector_id} detection"),
        description="",
        severity=spec.get("severity", "high"),
        confidence=spec.get("confidence", 0.91),
        status="OPEN",
        first_seen=ts,
        last_seen=ts,
        occurrence_count=spec.get("occurrence_count", 1),
        host_id="",
        host_name=spec.get("host", "corr-host"),
        user_id="",
        username=spec.get("user", "corr-user"),
        source_ip=spec.get("source_ip", "185.100.1.5"),
        destination_ip=spec.get("destination_ip", ""),
        mitre_tactic=spec.get("mitre_tactic", "Initial Access"),
        mitre_technique=spec.get("mitre", "T1133"),
        evidence=[],
        observables=spec.get("observables", []),
        detection_ids=[f"det-corr-{index:02d}"],
        created_at=T0,
        updated_at=T0,
    )


def build_groups(db: Session, scenario: dict) -> list[dict]:
    """Fabricate the scenario's alerts + groups; return group summaries and
    bind the scenario's ``g<i>`` labels to real behavior_group ids."""
    base = T0 + timedelta(minutes=scenario.get("base_minutes", 0))
    alerts: list[AlertRecord] = []
    for index, spec in enumerate(scenario["alerts"]):
        row = _fabricate(db, spec, base, index)
        db.add(row)
        db.flush()
        row.alert_id = f"ALR-{row.id:06d}"
        alerts.append(row)
    db.commit()
    process_alerts(db, alerts)

    from backend.correlation.engine import group_summary

    groups = list(
        db.scalars(
            select(BehaviorGroupRecord).order_by(BehaviorGroupRecord.id)
        ).all()
    )
    scenario["group_ids"] = {
        f"g{i}": group.behavior_group_id for i, group in enumerate(groups)
    }
    return [group_summary(db, group) for group in groups]


SCENARIOS: list[dict] = [
    {
        "name": "c1-rdp-to-lateral",
        "base_minutes": 0,
        "alerts": [
            dict(detector_id="D002", host="10.0.0.4", user="u-r1", source_ip="198.51.100.9",
                 mitre="T1110", minutes=0, severity="high", destination_ip="10.0.0.5"),
            dict(detector_id="D002", host="10.0.0.5", user="u-r1", source_ip="198.51.100.9",
                 mitre="T1110", minutes=4, severity="high", destination_ip="10.0.0.6"),
            dict(detector_id="D002", host="10.0.0.6", user="u-r1", source_ip="198.51.100.9",
                 mitre="T1110", minutes=8, severity="high", destination_ip="10.0.0.7"),
            dict(detector_id="D003", host="10.0.0.7", user="u-r1", source_ip="198.51.100.9",
                 mitre="T1021.001", minutes=14, severity="high"),
        ],
        "labels": [
            {"groups": ["g0", "g1", "g2", "g3"], "correlated": True},
        ],
    },
    {
        "name": "c2-unrelated-hosts",
        "base_minutes": 240,
        "alerts": [
            dict(detector_id="D001", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1133", minutes=0),
            dict(detector_id="D003", host="host-b", user="bob", source_ip="203.0.113.9",
                 mitre="T1059.001", minutes=1),
        ],
        "labels": [
            {"groups": ["g0", "g1"], "correlated": False},
        ],
    },
    {
        "name": "c3-temporal-only",
        "base_minutes": 480,
        "alerts": [
            dict(detector_id="D001", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1133", minutes=0),
            dict(detector_id="D002", host="host-a", user="bob", source_ip="203.0.113.9",
                 mitre="T1110", minutes=1),
        ],
        "labels": [
            {"groups": ["g0", "g1"], "correlated": False},
        ],
    },
]
