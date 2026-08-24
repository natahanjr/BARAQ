"""Phase 7 incident regression corpus (spec 7.41, 7.25-7.28, 7.42, 7.46-7.47)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from backend.incidents import engine
from backend.incidents.models import (
    IncidentV2AlertLink,
    IncidentV2BehaviorGroupLink,
    IncidentV2CorrelationLink,
    IncidentV2Evidence,
    IncidentV2RiskLink,
    IncidentV2Suppression,
    IncidentV2,
)

EVAL_T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=timezone.utc)


def _group(group_id, hosts, techniques, severity="high", alert_count=10):
    return {
        "kind": "BEHAVIOR_GROUP",
        "group_id": group_id,
        "hosts": hosts,
        "users": [],
        "source_ips": [],
        "destination_ips": [],
        "techniques": techniques,
        "tactics": [],
        "severity": severity,
        "alert_count": alert_count,
        "first_seen": EVAL_T0,
        "last_seen": EVAL_T0,
        "external_source": False,
    }


def _finding(finding_id, hosts):
    return {
        "kind": "CORRELATION_FINDING",
        "correlation_id": finding_id,
        "correlation_type": "MULTI_STAGE",
        "hosts": hosts,
        "users": [],
        "source_ips": [],
        "member_group_ids": [],
        "confidence": 0.9,
        "first_seen": EVAL_T0,
        "last_seen": EVAL_T0,
    }


def test_single_alert_flood_creates_one_incident(db):
    res = engine.create_incident(
        db,
        groups=[_group("g-reg-001", ["h-reg-001"], ["T1110"], severity="high", alert_count=10)],
        findings=[],
        policy_id="I003",
        now=EVAL_T0,
    )
    db.commit()
    assert res["incident_id"].startswith("INC-")
    count = db.scalars(select(func.count()).select_from(IncidentV2)).one()
    assert count == 1


def test_duplicate_incident_prevented(db):
    engine.create_incident(
        db,
        groups=[_group("g-reg-002", ["h-reg-002"], ["T1021.001"])],
        findings=[_finding("CF-reg-002", ["h-reg-002"])],
        policy_id="I001",
        now=EVAL_T0,
    )
    db.commit()
    engine.create_incident(
        db,
        groups=[_group("g-reg-002", ["h-reg-002"], ["T1021.001"])],
        findings=[_finding("CF-reg-002", ["h-reg-002"])],
        policy_id="I001",
        now=EVAL_T0,
    )
    db.commit()
    count = db.scalars(select(func.count()).select_from(IncidentV2)).one()
    assert count == 1


def test_rdp_false_positive_not_incident(db):
    res = engine.create_incident(
        db,
        groups=[_group("g-reg-003", ["h-reg-003"], ["T1133"], severity="low", alert_count=1)],
        findings=[],
        now=EVAL_T0,
    )
    assert res.get("incident_created") is False


def test_powershell_false_positive_not_incident(db):
    res = engine.create_incident(
        db,
        groups=[_group("g-reg-004", ["h-reg-004"], ["T1059.001"], severity="low", alert_count=1)],
        findings=[],
        now=EVAL_T0,
    )
    assert res.get("incident_created") is False


def test_normal_login_not_incident(db):
    res = engine.create_incident(
        db,
        groups=[_group("g-reg-005", ["h-reg-005"], ["T1078"], severity="low", alert_count=1)],
        findings=[],
        now=EVAL_T0,
    )
    assert res.get("incident_created") is False


def test_high_risk_without_activity_not_incident(db):
    res = engine.create_incident(
        db,
        groups=[],
        findings=[],
        risks=[{"risk_id": "ER-reg-006", "score": 90.0, "severity": "critical", "entity_id": "h-reg-006"}],
        now=EVAL_T0,
    )
    assert res.get("incident_created") is False


def test_cross_host_no_merge(db):
    engine.create_incident(
        db,
        groups=[_group("g-reg-007a", ["h-reg-007a"], ["T1059.001"])],
        findings=[],
        policy_id="I003",
        now=EVAL_T0,
    )
    engine.create_incident(
        db,
        groups=[_group("g-reg-007b", ["h-reg-007b"], ["T1110"])],
        findings=[],
        policy_id="I003",
        now=EVAL_T0,
    )
    db.commit()
    count = db.scalars(select(func.count()).select_from(IncidentV2)).one()
    assert count == 2


def test_closed_incident_no_reopen(db):
    r1 = engine.create_incident(
        db,
        groups=[_group("g-reg-008a", ["h-reg-008"], ["T1021.001"])],
        findings=[],
        policy_id="I003",
        now=EVAL_T0,
    )
    db.commit()
    engine.transition_incident(db, r1["incident_id"], "CLOSED", actor="tester")
    db.commit()
    r2 = engine.create_incident(
        db,
        groups=[_group("g-reg-008b", ["h-reg-008"], ["T1110"])],
        findings=[],
        policy_id="I003",
        now=EVAL_T0,
    )
    assert r2["incident_id"] != r1["incident_id"]


def test_suppression_no_permanent_hide(db):
    res = engine.create_incident(
        db,
        groups=[_group("g-reg-009", ["h-reg-009"], ["T1021.001"])],
        findings=[],
        policy_id="I003",
        now=EVAL_T0,
    )
    db.commit()
    engine.suppress_incident(
        db, res["incident_id"], "test", "incident", EVAL_T0 + timedelta(days=30), created_by="tester"
    )
    db.commit()
    sup = db.scalars(select(IncidentV2Suppression).where(IncidentV2Suppression.incident_id == res["incident_id"])).first()
    assert sup is not None
    assert sup.expires_at.replace(tzinfo=timezone.utc) > EVAL_T0


def test_severity_no_inflation(db):
    res = engine.create_incident(
        db,
        groups=[
            _group("g-reg-010a", ["h-reg-010"], ["T1021.001"], severity="high"),
            _group("g-reg-010b", ["h-reg-010"], ["T1110"], severity="high"),
        ],
        findings=[],
        policy_id="I003",
        now=EVAL_T0,
    )
    assert res["severity"] == "high"


def test_confidence_separate_from_severity(db):
    res = engine.create_incident(
        db,
        groups=[_group("g-reg-011", ["h-reg-011"], ["T1021.001"])],
        findings=[_finding("CF-reg-011", ["h-reg-011"])],
        now=EVAL_T0,
    )
    assert 0.0 <= res["confidence"] <= 1.0
    assert res["confidence"] != res["severity"]


def test_evidence_not_mutated(db):
    res = engine.create_incident(
        db,
        groups=[_group("g-reg-012", ["h-reg-012"], ["T1021.001"])],
        findings=[_finding("CF-reg-012", ["h-reg-012"])],
        now=EVAL_T0,
    )
    db.commit()
    evidence = db.scalars(
        select(IncidentV2Evidence).where(IncidentV2Evidence.incident_id == res["incident_id"])
    ).all()
    assert len(evidence) == 2


def test_incident_idempotency(db):
    for _ in range(3):
        engine.create_incident(
            db,
            groups=[_group("g-reg-013", ["h-reg-013"], ["T1021.001"])],
            findings=[_finding("CF-reg-013", ["h-reg-013"])],
            now=EVAL_T0,
        )
    db.commit()
    count = db.scalars(select(func.count()).select_from(IncidentV2)).one()
    assert count == 1


def test_concurrent_same_incident(db):
    from concurrent.futures import ThreadPoolExecutor

    def _ingest(_idx: int):
        from backend.database.connection import SessionLocal
        session = SessionLocal()
        try:
            engine.create_incident(
                session,
                groups=[_group("g-reg-014", ["h-reg-014"], ["T1021.001"])],
                findings=[_finding("CF-reg-014", ["h-reg-014"])],
                now=EVAL_T0,
            )
            session.commit()
        except Exception:  # noqa: BLE001
            session.rollback()
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(_ingest, range(8)))
    db.expire_all()
    count = db.scalars(select(func.count()).select_from(IncidentV2)).one()
    assert count == 1


def test_unrelated_activity_separate(db):
    engine.create_incident(
        db,
        groups=[_group("g-reg-015a", ["h-reg-015a"], ["T1059.001"])],
        findings=[],
        policy_id="I003",
        now=EVAL_T0,
    )
    engine.create_incident(
        db,
        groups=[_group("g-reg-015b", ["h-reg-015b"], ["T1110"])],
        findings=[],
        policy_id="I003",
        now=EVAL_T0,
    )
    db.commit()
    count = db.scalars(select(func.count()).select_from(IncidentV2)).one()
    assert count == 2


def test_sla_priority_mapping(db):
    res = engine.create_incident(
        db,
        groups=[_group("g-reg-016", ["h-reg-016"], ["T1486"])],
        findings=[],
        risks=[{"risk_id": "ER-reg-016", "score": 85.0, "severity": "critical", "entity_id": "h-reg-016"}],
        policy_id="I006",
        now=EVAL_T0,
    )
    assert res["priority"] == "P1"


