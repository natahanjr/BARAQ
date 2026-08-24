"""Phase 4 labeled evaluation corpus (spec 4.41).

Small, deterministic, hand-labeled dataset used to measure grouping
quality WITHOUT inventing an accuracy percentage. Reports raw counts:

    labeled_groups / correct_groupings / incorrect_groupings /
    over_grouping / under_grouping

Each scenario lists alert specs; ``expected`` lists the alert indices
(0-based) that must end up in ONE group together. Alerts are fabricated
as distinct ``v2_alerts`` rows (Phase 3's dedup would collapse same-identity
detections before aggregation can see them - the corpus measures the
aggregation layer itself).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from backend.alerting.models import AlertRecord

T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=timezone.utc)


def _alerts(db: Session, scenario: dict) -> list[AlertRecord]:
    """Fabricate the scenario's alerts, shifted onto the scenario's own
    base time so episodes from different scenarios never overlap."""
    base = T0 + timedelta(minutes=scenario.get("base_minutes", 0))
    rows = []
    for spec in scenario["alerts"]:
        ts = base + timedelta(minutes=spec.get("minutes", 0.0))
        detector_id = spec.get("detector_id", "D001")
        row = AlertRecord(
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
            host_name=spec.get("host", "ml-host"),
            user_id="",
            username=spec.get("user", "ml-online-user"),
            source_ip=spec.get("source_ip", "185.100.1.5"),
            destination_ip="",
            mitre_tactic=spec.get("mitre_tactic", "Initial Access"),
            mitre_technique=spec.get("mitre", "T1133"),
            evidence=[],
            observables=[],
            detection_ids=[f"det-e-{len(rows) + 1}"],
            created_at=T0,
            updated_at=T0,
        )
        db.add(row)
        db.flush()
        row.alert_id = f"ALR-{row.id:06d}"
        rows.append(row)
    db.commit()
    return rows


SCENARIOS: list[dict] = [
    {
        "name": "e1-auth-episode",
        "base_minutes": 0,
        "alerts": [
            dict(detector_id="D001", minutes=2),
            dict(detector_id="D002", mitre="T1110", minutes=4),
            dict(detector_id="D001", minutes=6),
        ],
        "expected": [{0, 1, 2}],
    },
    {
        "name": "e2-same-host-different-users",
        "base_minutes": 120,
        "alerts": [
            dict(host="ml-host", user="alice", source_ip="203.0.113.5", minutes=0),
            dict(host="ml-host", user="bob", source_ip="203.0.113.9", minutes=1),
        ],
        "expected": [{0}, {1}],
    },
    {
        "name": "e3-same-user-different-hosts",
        "base_minutes": 240,
        "alerts": [
            dict(host="ml-host", user="alice", source_ip="203.0.113.5", minutes=0),
            dict(host="finance-host", user="alice", source_ip="203.0.113.7", minutes=1),
        ],
        "expected": [{0}, {1}],
    },
    {
        "name": "e4-same-source-different-hosts",
        "base_minutes": 360,
        "alerts": [
            dict(host="host-a", user="user-a", source_ip="185.100.1.5", minutes=0),
            dict(host="host-b", user="user-b", source_ip="185.100.1.5", minutes=1),
        ],
        "expected": [{0}, {1}],
    },
    {
        "name": "e5-flood-compression",
        "base_minutes": 480,
        "alerts": [
            dict(detector_id="D001", minutes=i / 2)
            for i in range(30)
        ],
        "expected": [set(range(30))],
    },
    {
        "name": "e6-unrelated-episodes",
        "base_minutes": 600,
        "alerts": [
            dict(detector_id="D001", host="ml-host", user="alice",
                 source_ip="203.0.113.5", mitre="T1133", minutes=0),
            dict(detector_id="D003", host="finance-host", user="bob",
                 source_ip="203.0.113.7", mitre="T1059.001", minutes=1),
            dict(detector_id="D005", host="backup-host", user="system",
                 source_ip="203.0.113.9", mitre="T1486", minutes=2),
        ],
        "expected": [{0}, {1}, {2}],
    },
]