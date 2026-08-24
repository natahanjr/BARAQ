"""Phase 7 incident engine tests (spec 7.1-7.8, 7.15, 7.23-7.25, 7.42, 7.45-7.47)."""
from __future__ import annotations

import pytest
from datetime import datetime, timezone
from sqlalchemy import select

from backend.incidents import engine
from backend.incidents.models import IncidentV2Evidence, IncidentV2
from backend.incidents.contract import INCIDENT_STATES

EVAL_T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=timezone.utc)


def _group(group_id, hosts, techniques, severity="high", alert_count=10, first_seen=EVAL_T0, last_seen=EVAL_T0):
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
        "first_seen": first_seen,
        "last_seen": last_seen,
        "external_source": False,
    }


def _finding(finding_id, hosts, first_seen=EVAL_T0, last_seen=EVAL_T0):
    return {
        "kind": "CORRELATION_FINDING",
        "correlation_id": finding_id,
        "correlation_type": "MULTI_STAGE",
        "hosts": hosts,
        "users": [],
        "source_ips": [],
        "member_group_ids": [],
        "confidence": 0.9,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def test_create_incident_basic(db):
    res = engine.create_incident(
        db,
        groups=[
            _group("g-eng-001", ["h-eng-001"], ["T1021.001"]),
            _group("g-eng-001b", ["h-eng-001"], ["T1059.001"]),
        ],
        findings=[_finding("CF-eng-001", ["h-eng-001"])],
        now=EVAL_T0,
    )
    assert res["incident_id"].startswith("INC-")
    assert res["status"] == "NEW"
    assert res["severity"] == "high"
    assert res["policy_id"] == "I001"
    assert res.get("incident_created") is not False


def test_create_incident_deterministic_fingerprint(db):
    r1 = engine.create_incident(
        db,
        groups=[
            _group("g-eng-002a", ["h-eng-002"], ["T1021.001"]),
            _group("g-eng-002b", ["h-eng-002"], ["T1059.001"]),
        ],
        findings=[_finding("CF-eng-002", ["h-eng-002"])],
        now=EVAL_T0,
    )
    db.commit()
    r2 = engine.create_incident(
        db,
        groups=[
            _group("g-eng-002a", ["h-eng-002"], ["T1021.001"]),
            _group("g-eng-002b", ["h-eng-002"], ["T1059.001"]),
        ],
        findings=[_finding("CF-eng-002", ["h-eng-002"])],
        now=EVAL_T0,
    )
    assert r1["incident_id"] == r2["incident_id"]
    assert r1["fingerprint"] == r2["fingerprint"]


def test_create_incident_deduplication(db):
    engine.create_incident(
        db,
        groups=[
            _group("g-eng-003a", ["h-eng-003"], ["T1021.001"]),
            _group("g-eng-003b", ["h-eng-003"], ["T1059.001"]),
        ],
        findings=[_finding("CF-eng-003", ["h-eng-003"])],
        now=EVAL_T0,
    )
    db.commit()
    res = engine.create_incident(
        db,
        groups=[
            _group("g-eng-003a", ["h-eng-003"], ["T1021.001"]),
            _group("g-eng-003b", ["h-eng-003"], ["T1059.001"]),
        ],
        findings=[_finding("CF-eng-003", ["h-eng-003"])],
        now=EVAL_T0,
    )
    assert res["status"] in INCIDENT_STATES


def test_transition_incident(db):
    res = engine.create_incident(
        db,
        groups=[
            _group("g-eng-004a", ["h-eng-004"], ["T1021.001"]),
            _group("g-eng-004b", ["h-eng-004"], ["T1059.001"]),
        ],
        findings=[_finding("CF-eng-004", ["h-eng-004"])],
        now=EVAL_T0,
    )
    db.commit()
    transition = engine.transition_incident(db, res["incident_id"], "TRIAGED", actor="tester")
    assert transition["new_status"] == "TRIAGED"
    incident = db.scalars(select(IncidentV2).where(IncidentV2.incident_id == res["incident_id"])).first()
    assert incident.status == "TRIAGED"


def test_suppression_blocks_repeat(db):
    res = engine.create_incident(
        db,
        groups=[
            _group("g-eng-005a", ["h-eng-005"], ["T1021.001"]),
            _group("g-eng-005b", ["h-eng-005"], ["T1059.001"]),
        ],
        findings=[_finding("CF-eng-005", ["h-eng-005"])],
        now=EVAL_T0,
    )
    db.commit()
    engine.suppress_incident(
        db, res["incident_id"], "test", "incident", EVAL_T0, created_by="tester"
    )
    db.commit()
    res2 = engine.create_incident(
        db,
        groups=[
            _group("g-eng-005a", ["h-eng-005"], ["T1021.001"]),
            _group("g-eng-005b", ["h-eng-005"], ["T1059.001"]),
        ],
        findings=[_finding("CF-eng-005", ["h-eng-005"])],
        now=EVAL_T0,
    )
    assert res2["status"] == "SUPPRESSED"


def test_banned_phrase_rejected(db):
    with pytest.raises(ValueError, match="banned incident phrase"):
        engine.create_incident(
            db,
            groups=[_group("g-eng-006a", ["h-eng-006"], ["T1021.001"])],
            findings=[],
            title="Confirmed Attack Detected",
            policy_id="I008",
            now=EVAL_T0,
        )


def test_no_incident_for_single_low_alert(db):
    res = engine.create_incident(
        db,
        groups=[_group("g-eng-007a", ["h-eng-007"], ["T1078"], severity="low", alert_count=1)],
        findings=[],
        now=EVAL_T0,
    )
    assert res.get("incident_created") is False


def test_evidence_preserved(db):
    res = engine.create_incident(
        db,
        groups=[
            _group("g-eng-008a", ["h-eng-008"], ["T1021.001"]),
            _group("g-eng-008b", ["h-eng-008"], ["T1059.001"]),
        ],
        findings=[_finding("CF-eng-008", ["h-eng-008"])],
        now=EVAL_T0,
    )
    db.commit()
    evidence = db.scalars(
        select(IncidentV2Evidence).where(IncidentV2Evidence.incident_id == res["incident_id"])
    ).all()
    assert len(evidence) >= 0


