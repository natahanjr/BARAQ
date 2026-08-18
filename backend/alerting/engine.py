"""Alert engine (spec 3.2, 3.5-3.10, 3.28-3.31).

The Detection -> Alert pipeline:

    DETECTION
      -> eligibility (detector-aware policy)
      -> suppression check (auditable, expiring rules)
      -> fingerprint
      -> existing active alert in window? merge : create
      -> occurrence row + audit event

Hard boundaries (3.28-3.31): never creates incidents, never mutates risk,
never executes SOAR, no ML. The ONLY tables this engine writes are the
five v2 alert tables.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

import backend.config as config
from backend.alerting import audit, deduplication, fingerprint as fingerprint_mod
from backend.alerting.eligibility import evaluate_detection
from backend.alerting.models import AlertOccurrence, AlertRecord
from backend.alerting.suppression import is_suppressed
from backend.detection.contract import DETECTION


def _ensure_not_production_db() -> None:
    if make_url(config.DATABASE_URL).database == config.PRODUCTION_DB_NAME:
        raise RuntimeError(
            f"alert engine refuses the v1 production database "
            f"({config.PRODUCTION_DB_NAME!r}) by name"
        )


def next_alert_id(db: Session) -> str:
    """Public alert id ALR-<6-digit sequence> - unique, never a dedup key."""
    row = db.scalars(
        select(AlertRecord).order_by(AlertRecord.id.desc()).limit(1)
    ).first()
    return f"ALR-{(row.id if row else 0) + 1:06d}"


def process_detection(
    db: Session,
    detection: DETECTION,
    now: datetime | None = None,
    actor: str = "system",
) -> AlertRecord | None:
    """Run one detection through the alert pipeline.

    Returns the created/updated alert, or None when the detection is not
    eligible or is suppressed. Never creates incidents/risk/SOAR.
    """
    _ensure_not_production_db()
    now = now or datetime.now(timezone.utc)
    detection_time = detection.timestamp or now

    # 1. Eligibility (spec 3.5/3.6) - detector-aware policy.
    decision = evaluate_detection(detection)
    if not decision.eligible:
        return None

    # 2. Suppression (spec 3.25/3.26) - auditable, expiring rules.
    rule = is_suppressed(db, detection, now)
    if rule is not None:
        rule.suppressed_count += 1
        audit.record(
            db,
            alert_id="-",
            action="SUPPRESSED",
            actor=actor,
            details={"policy_id": rule.policy_id, "detection_id": detection.detection_id},
        )
        db.commit()
        return None

    # 3. Fingerprint (spec 3.7).
    fp = fingerprint_mod.fingerprint(detection)

    # 4. Deduplication (spec 3.8-3.10).
    existing = deduplication.find_existing(db, fp, detection.detector_id, detection_time, now)
    if existing is not None:
        deduplication.merge(db, existing, detection_time)
        ids = list(existing.detection_ids or [])
        if detection.detection_id not in ids:
            ids.append(detection.detection_id)
            existing.detection_ids = ids
        occurrence = AlertOccurrence(
            alert_id=existing.alert_id,
            detection_id=detection.detection_id,
            event_ids=_event_ids(detection),
            timestamp=detection_time,
            evidence=_evidence(detection),
        )
        db.add(occurrence)
        audit.record(
            db,
            alert_id=existing.alert_id,
            action="OCCURRENCE",
            previous_status=existing.status,
            new_status=existing.status,
            actor=actor,
            details={"detection_id": detection.detection_id, "occurrence_count": existing.occurrence_count},
        )
        db.commit()
        return existing

    # 5. Create a new alert (spec 3.44/3.45).
    alert = AlertRecord(
        alert_id="",  # assigned from the DB sequence below
        alert_fingerprint=fp,
        detector_id=detection.detector_id,
        detector_version=detection.detector_version,
        title=detection.title,
        description=detection.description,
        severity=detection.severity,
        confidence=detection.confidence,
        status="OPEN",
        first_seen=detection_time,
        last_seen=detection_time,
        occurrence_count=1,
        host_id=detection.host_id,
        host_name=detection.host_name,
        user_id=detection.user_id,
        username=detection.username,
        source_ip=detection.source_ip,
        destination_ip=detection.destination_ip,
        mitre_tactic=detection.mitre_tactic,
        mitre_technique=detection.mitre_technique,
        evidence=_evidence(detection),
        observables=list(detection.observables),
        detection_ids=[detection.detection_id],
        created_at=now,
        updated_at=now,
    )
    db.add(alert)
    db.flush()
    alert.alert_id = f"ALR-{alert.id:06d}"
    db.flush()
    occurrence = AlertOccurrence(
        alert_id=alert.alert_id,
        detection_id=detection.detection_id,
        event_ids=_event_ids(detection),
        timestamp=detection_time,
        evidence=_evidence(detection),
    )
    db.add(occurrence)
    audit.record(
        db,
        alert_id=alert.alert_id,
        action="CREATED",
        previous_status="",
        new_status="OPEN",
        actor=actor,
        details={"detection_id": detection.detection_id, "policy_id": decision.policy_id},
    )
    db.commit()
    return alert


def _event_ids(detection: DETECTION) -> list[str]:
    ids = list(detection.event_ids or [])
    if detection.event_id and detection.event_id not in ids:
        ids.append(detection.event_id)
    return ids


def _evidence(detection: DETECTION) -> list[dict]:
    return [e.to_dict() for e in detection.evidence]


def process_detections(
    db: Session,
    detections: list[DETECTION],
    now: datetime | None = None,
    actor: str = "system",
) -> list[AlertRecord]:
    """Run many detections through the pipeline; return created/updated alerts."""
    alerts = []
    for detection in detections:
        alert = process_detection(db, detection, now, actor)
        if alert is not None:
            alerts.append(alert)
    return alerts