"""Tests for backend.incidents.eligibility."""

import hashlib
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from backend.incidents.eligibility import check_eligibility
from backend.incidents.models import (
    IncidentV2,
    IncidentV2AlertLink,
    IncidentV2BehaviorGroupLink,
    IncidentV2CorrelationLink,
    IncidentV2RiskLink,
)


def _make_incident(session, *, incident_id="INC-TEST-001", status="NEW", **overrides):
    now = datetime.now(UTC)
    defaults = dict(
        fingerprint=hashlib.sha256(incident_id.encode()).hexdigest()[:64],
        title="Test Incident",
        description="Auto-generated test",
        status=status,
        priority="P3",
        severity="medium",
        confidence=0.5,
        first_seen=now,
        last_seen=now,
        created_at=now,
        updated_at=now,
        primary_entity_type="HOST",
        primary_entity_id="test-host",
        source_type="CORRELATION",
        source_id="test-source",
    )
    defaults.update(overrides)
    inc = IncidentV2(incident_id=incident_id, **defaults)
    session.add(inc)
    session.flush()
    return inc


def _link_alert(session, incident_id, alert_id="alert-001"):
    link = IncidentV2AlertLink(
        incident_id=incident_id, alert_id=alert_id, membership_reason="test"
    )
    session.add(link)
    session.flush()


def _link_group(session, incident_id, group_id="grp-001"):
    link = IncidentV2BehaviorGroupLink(
        incident_id=incident_id, behavior_group_id=group_id,
        membership_reason="test",
    )
    session.add(link)
    session.flush()


def _link_correlation(session, incident_id, finding_id="CF-001"):
    link = IncidentV2CorrelationLink(
        incident_id=incident_id, correlation_finding_id=finding_id,
        membership_reason="correlation finding",
    )
    session.add(link)
    session.flush()


def test_check_eligibility_incident_not_found(db):
    result = check_eligibility(db, "NONEXISTENT", "I001")
    assert result["eligible"] is False
    assert "not found" in result["reason"]


def test_check_eligibility_no_related_data(db):
    inc = _make_incident(db, incident_id="INC-NO-DATA")
    db.commit()
    result = check_eligibility(db, "INC-NO-DATA", "I001")
    assert result["eligible"] is False


def test_check_eligibility_with_multi_stage_finding(db):
    inc = _make_incident(
        db,
        incident_id="INC-MULTI-STAGE",
        primary_entity_type="HOST",
        primary_entity_id="h-multi",
    )
    _link_group(db, "INC-MULTI-STAGE", "grp-001")
    _link_correlation(db, "INC-MULTI-STAGE", "CF-multi-001")
    db.commit()

    result = check_eligibility(db, "INC-MULTI-STAGE", "I001")
    assert result["policy_id"] == "I001"
    assert result["eligible"] is False
    assert "insufficient" in result["reason"]
