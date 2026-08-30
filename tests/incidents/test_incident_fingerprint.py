"""Phase 7 incident fingerprint tests (spec 7.4)."""

from __future__ import annotations

from backend.incidents.fingerprint import compute_fingerprint


def test_fingerprint_deterministic():
    fp1 = compute_fingerprint(
        incident_type="CORRELATED",
        primary_entity_type="HOST",
        primary_entity_id="h1",
        relevant_entities=["HOST:h1", "USER:u1"],
        correlation_finding_ids=["CF-001"],
        behavior_group_ids=["g1"],
        policy_id="I001",
    )
    fp2 = compute_fingerprint(
        incident_type="CORRELATED",
        primary_entity_type="HOST",
        primary_entity_id="h1",
        relevant_entities=["USER:u1", "HOST:h1"],
        correlation_finding_ids=["CF-001"],
        behavior_group_ids=["g1"],
        policy_id="I001",
    )
    assert fp1 == fp2
    assert len(fp1) == 64


def test_fingerprint_changes_with_inputs():
    fp1 = compute_fingerprint(
        incident_type="CORRELATED",
        primary_entity_type="HOST",
        primary_entity_id="h1",
        relevant_entities=["HOST:h1"],
        correlation_finding_ids=["CF-001"],
        behavior_group_ids=["g1"],
        policy_id="I001",
    )
    fp2 = compute_fingerprint(
        incident_type="CORRELATED",
        primary_entity_type="HOST",
        primary_entity_id="h1",
        relevant_entities=["HOST:h1"],
        correlation_finding_ids=["CF-002"],
        behavior_group_ids=["g1"],
        policy_id="I001",
    )
    assert fp1 != fp2


def test_fingerprint_no_timestamp():
    fp1 = compute_fingerprint(
        incident_type="CORRELATED",
        primary_entity_type="HOST",
        primary_entity_id="h1",
        relevant_entities=["HOST:h1"],
        correlation_finding_ids=["CF-001"],
        behavior_group_ids=["g1"],
        policy_id="I001",
    )
    fp2 = compute_fingerprint(
        incident_type="CORRELATED",
        primary_entity_type="HOST",
        primary_entity_id="h1",
        relevant_entities=["HOST:h1"],
        correlation_finding_ids=["CF-001"],
        behavior_group_ids=["g1"],
        policy_id="I001",
    )
    assert fp1 == fp2
