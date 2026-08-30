"""Phase 5 contract tests (spec 5.1, 5.3, 5.4, 5.26-5.28, 5.31, 5.63)."""

import pytest

from backend.correlation.contract import (
    BANNED_CORRELATION_PHRASES,
    CORRELATION_ACTIONS,
    CORRELATION_STATUSES,
    CORRELATION_TYPES,
    EDGE_TYPES,
    CorrelationFinding,
    is_progression,
    phase_of,
)
from backend.correlation.models import CorrelationAuditEvent


def test_statuses_match_spec():
    assert CORRELATION_STATUSES == ("NEW", "ACTIVE", "QUIET", "CLOSED")


def test_types_cover_the_nine_spec_types():
    assert set(CORRELATION_TYPES) == {
        "TEMPORAL",
        "ENTITY",
        "HOST_CHAIN",
        "USER_CHAIN",
        "SOURCE_CHAIN",
        "TACTIC_SEQUENCE",
        "TECHNIQUE_SEQUENCE",
        "LATERAL_MOVEMENT",
        "MULTI_STAGE",
    }


def test_edge_types_cover_the_spec_relationships():
    assert set(EDGE_TYPES) == {
        "TEMPORAL",
        "SAME_HOST",
        "SAME_USER",
        "SAME_SOURCE",
        "SAME_ACCOUNT",
        "NETWORK_RELATION",
        "DESTINATION_RELATION",
        "TECHNIQUE_TRANSITION",
        "TACTIC_TRANSITION",
        "LATERAL_MOVEMENT",
    }


def test_banned_phrases_never_claim_confirmation():
    # Every banned phrase asserts a certainty the correlation layer must
    # never emit (spec 5.27): 'confirmed', 'breach', 'proves', 'compromised'.
    assert BANNED_CORRELATION_PHRASES == (
        "confirmed attack",
        "confirmed compromise",
        "attacker confirmed",
        "breach confirmed",
        "apt confirmed",
        "malware confirmed",
        "host compromised",
        "account compromised",
        "confirmed intrusion",
        "proves",
    )


def test_finding_validation_rejects_banned_title():
    with pytest.raises(ValueError):
        CorrelationFinding(
            correlation_id="CF-000001",
            fingerprint="fp",
            title="confirmed attack",
            description="desc",
            status="NEW",
            correlation_type="TEMPORAL",
            first_seen=None,
            last_seen=None,
        )


def test_finding_validation_rejects_bad_status_and_type():
    with pytest.raises(ValueError):
        CorrelationFinding(
            correlation_id="CF-000001",
            fingerprint="fp",
            title="t",
            description="d",
            status="OPEN",
            correlation_type="TEMPORAL",
            first_seen=None,
            last_seen=None,
        )
    with pytest.raises(ValueError):
        CorrelationFinding(
            correlation_id="CF-000001",
            fingerprint="fp",
            title="t",
            description="d",
            status="NEW",
            correlation_type="MAGIC",
            first_seen=None,
            last_seen=None,
        )


def test_finding_validation_rejects_invalid_edge_and_confidence():
    with pytest.raises(ValueError):
        CorrelationFinding(
            correlation_id="CF-000001",
            fingerprint="fp",
            title="t",
            description="d",
            status="NEW",
            correlation_type="TEMPORAL",
            first_seen=None,
            last_seen=None,
            edges=[{"relationship_type": "NOPE"}],
        )
    with pytest.raises(ValueError):
        CorrelationFinding(
            correlation_id="CF-000001",
            fingerprint="fp",
            title="t",
            description="d",
            status="NEW",
            correlation_type="TEMPORAL",
            first_seen=None,
            last_seen=None,
            confidence=1.5,
        )


def test_phase_mapping_and_progression_deterministic():
    assert phase_of("T1133") == "INITIAL_ACCESS"
    assert phase_of("T1110") == "CREDENTIAL_ACCESS"
    assert phase_of("T1021.001") == "LATERAL_MOVEMENT"
    assert phase_of("T1059.001") == "EXECUTION"
    assert phase_of("T9999") == "UNKNOWN_PHASE"
    assert phase_of("") == "UNKNOWN_PHASE"
    assert is_progression("INITIAL_ACCESS", "CREDENTIAL_ACCESS")
    assert is_progression("CREDENTIAL_ACCESS", "LATERAL_MOVEMENT")
    assert is_progression("LATERAL_MOVEMENT", "EXECUTION")
    assert not is_progression("EXECUTION", "INITIAL_ACCESS")
    assert not is_progression("UNKNOWN_PHASE", "EXECUTION")
    assert not is_progression("EXECUTION", "UNKNOWN_PHASE")


def test_audit_actions_match_spec():
    assert set(CORRELATION_ACTIONS) == {
        "CORRELATION_CREATED",
        "GROUP_ADDED",
        "EDGE_CREATED",
        "CORRELATION_UPDATED",
        "CORRELATION_QUIET",
        "CORRELATION_CLOSED",
        "CORRELATION_REOPEN_REJECTED",
    }
    assert CorrelationAuditEvent.__tablename__ == "correlation_audit_events"


def test_correlation_findings_table_has_closed_at():
    from backend.correlation.models import CorrelationFindingRecord

    assert "closed_at" in CorrelationFindingRecord.__table__.columns
