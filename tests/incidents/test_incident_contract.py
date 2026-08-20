"""Phase 7 incident contract tests (spec 7.1-7.4, 7.7-7.11, 7.15, 7.20, 7.29, 7.33, 7.52)."""
from __future__ import annotations

import pytest
from datetime import datetime, timezone

from backend.incidents.contract import (
    AUDIT_ACTIONS,
    BANNED_INCIDENT_PHRASES,
    DEFAULT_SLA,
    EVIDENCE_SOURCE_TYPES,
    GRAPH_RELATIONSHIP_TYPES,
    INCIDENT_PRIORITIES,
    INCIDENT_SEVERITIES,
    INCIDENT_STATES,
    INCIDENT_TRANSITIONS,
)


def test_contract_constants():
    assert INCIDENT_STATES == (
        "NEW", "TRIAGED", "INVESTIGATING", "CONTAINMENT_REQUIRED",
        "CONTAINED", "RESOLVED", "CLOSED", "SUPPRESSED",
    )
    assert INCIDENT_SEVERITIES == ("critical", "high", "medium", "low")
    assert INCIDENT_PRIORITIES == ("P1", "P2", "P3", "P4")
    assert set(EVIDENCE_SOURCE_TYPES) == {
        "ALERT", "BEHAVIOR_GROUP", "CORRELATION", "RISK", "ENTITY", "ANALYST",
    }
    assert set(GRAPH_RELATIONSHIP_TYPES) == {
        "INCIDENT_HAS_ALERT", "INCIDENT_HAS_GROUP", "INCIDENT_HAS_CORRELATION",
        "INCIDENT_HAS_RISK", "INCIDENT_INVOLVES_ENTITY", "INCIDENT_RELATED_TO_INCIDENT",
    }
    assert "INCIDENT_CREATED" in AUDIT_ACTIONS
    assert "INCIDENT_REOPEN_REJECTED" in AUDIT_ACTIONS
    assert DEFAULT_SLA["P1"] == 15
    assert DEFAULT_SLA["P4"] == 480
    assert len(BANNED_INCIDENT_PHRASES) >= 5
    assert "confirmed attack" in BANNED_INCIDENT_PHRASES


def test_transitions():
    from backend.incidents.lifecycle import can_transition
    assert can_transition("NEW", "TRIAGED") is True
    assert can_transition("NEW", "INVESTIGATING") is True
    assert can_transition("NEW", "CLOSED") is True
    assert can_transition("CLOSED", "NEW") is False
    assert can_transition("RESOLVED", "CLOSED") is True
    assert can_transition("RESOLVED", "INVESTIGATING") is False


def test_banned_phrases_rejected():
    from backend.incidents.contract import IncidentContract
    with pytest.raises(ValueError, match="banned incident phrase"):
        IncidentContract(
            incident_id="INC-000001",
            fingerprint="abc",
            title="Confirmed Attack Detected",
            description="details",
            status="NEW",
            priority="P1",
            severity="high",
            confidence=0.5,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            closed_at=None,
            primary_entity_type="HOST",
            primary_entity_id="h1",
            entity_ids=[],
            source_type="CORRELATION",
            source_id="CF-001",
            incident_version="1.0.0",
            model_version="1.0.0",
            created_by="system",
            updated_by="system",
            assigned_to=None,
            assigned_team=None,
            assigned_at=None,
            investigation_state=None,
            suppression_reason=None,
            suppression_scope=None,
            suppression_expires_at=None,
            suppression_created_by=None,
            policy_id="I001",
        )
