"""Phase 4 aggregation test helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text

from backend.aggregation.models import (
    BehaviorGroupAuditEvent,
    BehaviorGroupEvidence,
    BehaviorGroupMember,
    BehaviorGroupRecord,
)
from backend.alerting.engine import process_detection
from backend.alerting.models import AlertRecord
from tests.alerting.helpers import detection

GROUP_T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=UTC)


def dt(minutes_ago: float = 0.0) -> datetime:
    return GROUP_T0 - timedelta(minutes=minutes_ago)


def make_alerts(
    db, specs: list[dict], now: datetime | None = None
) -> list[AlertRecord]:
    """Seed v2 alerts through the Phase 3 pipeline, then return them."""
    if now is None:
        now = GROUP_T0
    created = []
    for spec in specs:
        alert = process_detection(db, detection(**spec), now=now)
        if alert is not None:
            created.append(alert)
    return list(
        db.scalars(
            select(AlertRecord)
            .where(AlertRecord.alert_id.in_([a.alert_id for a in created]))
            .order_by(AlertRecord.id)
        ).all()
    )


def fabricate_alerts(db, specs: list[dict]) -> list[AlertRecord]:
    """Create DISTINCT v2 alert rows directly (bypassing Phase 3 dedup).

    Aggregation-level tests need N distinct alerts for the same identity;
    Phase 3's dedup would merge same-detector detections into one alert.
    Fabricated rows are real ``v2_alerts`` rows, so referential integrity
    holds.
    """
    rows = []
    for spec in specs:
        ts = GROUP_T0 - timedelta(minutes=spec.get("minutes_ago", 0.0))
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
            host_name=spec.get("host", "workstation-42"),
            user_id="",
            username=spec.get("user", "alice"),
            source_ip=spec.get("source_ip", "203.0.113.5"),
            destination_ip=spec.get("destination_ip", ""),
            mitre_tactic=spec.get("mitre_tactic", "Initial Access"),
            mitre_technique=spec.get("mitre", "T1133"),
            evidence=spec.get("evidence", None),
            observables=spec.get("observables", None),
            detection_ids=[spec.get("detection_id", f"det-{len(rows) + 1}")],
            created_at=GROUP_T0,
            updated_at=GROUP_T0,
        )
        db.add(row)
        db.flush()
        row.alert_id = f"ALR-{row.id:06d}"
        rows.append(row)
    db.commit()
    return rows


def stored_groups(db) -> list[BehaviorGroupRecord]:
    return list(
        db.scalars(select(BehaviorGroupRecord).order_by(BehaviorGroupRecord.id)).all()
    )


def stored_members(db) -> list[BehaviorGroupMember]:
    return list(
        db.scalars(select(BehaviorGroupMember).order_by(BehaviorGroupMember.id)).all()
    )


def stored_group_evidence(db) -> list[BehaviorGroupEvidence]:
    return list(
        db.scalars(
            select(BehaviorGroupEvidence).order_by(BehaviorGroupEvidence.id)
        ).all()
    )


def stored_group_audit(db) -> list[BehaviorGroupAuditEvent]:
    return list(
        db.scalars(
            select(BehaviorGroupAuditEvent).order_by(BehaviorGroupAuditEvent.id)
        ).all()
    )


def v1_counts(db) -> dict[str, int]:
    return {
        t: db.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar()
        for t in ("alerts", "incidents", "entity_risk")
    }
