"""Phase 6 lifecycle tests (spec 6.19, 6.21-6.24, 6.44, 6.66, 6.76)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from backend.risk import engine
from backend.risk.models import (
    EntityRiskV2AuditEvent,
    EntityRiskV2Factor,
)
from tests.risk.helpers import (
    RISK_T0,
    alert_evidence,
    group_evidence,
    stored_audit,
    stored_snapshots,
)


def test_decay_halves_24h_old_evidence(db):
    engine.apply_group(
        db,
        group_evidence(
            "g5",
            "h1",
            ["T1021.001"],
            observed=RISK_T0 - timedelta(hours=24),
        ),
        now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == pytest.approx(17.0)


def test_stale_state_after_window(db):
    engine.apply_group(
        db,
        group_evidence("g5", "h1", ["T1021.001"]),
        now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.state == "HIGH"
    engine.recalculate_entity(db, risk.risk_id, now=RISK_T0 + timedelta(hours=2))
    db.refresh(risk)
    assert risk.state == "STALE"


def test_peak_score_never_decreases(db):
    engine.apply_group(
        db,
        group_evidence("g5", "h1", ["T1021.001"]),
        now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.peak_score == 42.0
    assert risk.peak_at is not None
    engine.recalculate_entity(db, risk.risk_id, now=RISK_T0 + timedelta(hours=24))
    db.refresh(risk)
    assert risk.score == pytest.approx(17.0)
    assert risk.peak_score == 42.0


def test_trend_rising_then_falling(db):
    engine.apply_alert(
        db,
        alert_evidence("ALR-000001", "h1", severity="medium"),
        now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.trend == "UNKNOWN"
    engine.apply_group(
        db,
        group_evidence("g5", "h1", ["T1021.001"]),
        now=RISK_T0,
    )
    db.refresh(risk)
    assert risk.trend == "RISING"
    assert risk.score == pytest.approx(45.0)
    engine.recalculate_entity(db, risk.risk_id, now=RISK_T0 + timedelta(hours=24))
    db.refresh(risk)
    assert risk.trend == "FALLING"


def test_threshold_crossing_audited(db):
    engine.apply_alert(
        db,
        alert_evidence("ALR-000001", "h1", severity="medium"),
        now=RISK_T0,
    )
    engine.apply_group(
        db,
        group_evidence("g5", "h1", ["T1021.001"]),
        now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    events = db.scalars(
        select(EntityRiskV2AuditEvent).where(
            EntityRiskV2AuditEvent.risk_id == risk.risk_id,
            EntityRiskV2AuditEvent.action == "RISK_THRESHOLD_CROSSED",
        )
    ).all()
    assert len(events) == 1
    assert events[0].details["severities"] == ["LOW", "MEDIUM"]
    assert events[0].old_score == 11.0
    assert events[0].new_score == 45.0


def test_state_changed_audited(db):
    engine.apply_group(
        db,
        group_evidence("g5", "h1", ["T1021.001"]),
        now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    events = db.scalars(
        select(EntityRiskV2AuditEvent).where(
            EntityRiskV2AuditEvent.risk_id == risk.risk_id,
            EntityRiskV2AuditEvent.action == "RISK_STATE_CHANGED",
        )
    ).all()
    assert len(events) >= 1
    assert events[0].old_state == "NORMAL"
    assert events[0].new_state == "HIGH"


def test_snapshots_are_append_only(db):
    engine.apply_alert(
        db,
        alert_evidence("ALR-000001", "h1", severity="medium"),
        now=RISK_T0,
    )
    engine.apply_group(
        db,
        group_evidence("g5", "h1", ["T1021.001"]),
        now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    snapshots = [s for s in stored_snapshots(db) if s.risk_id == risk.risk_id]
    scores = [s.score for s in snapshots]
    assert scores == [11.0, 45.0]
    assert all(s.risk_model_version == "1.0.0" for s in snapshots)


def test_failure_boundary_audits_without_losing_state(db):
    engine.apply_group(
        db,
        group_evidence("g5", "h1", ["T1021.001"]),
        now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    engine.failure_boundary(db, risk.risk_id, ValueError("boom"), now=RISK_T0)
    actions = [a.action for a in stored_audit(db) if a.risk_id == risk.risk_id]
    assert "RISK_CALCULATION_FAILED" in actions
    db.refresh(risk)
    assert risk.score == 42.0


def test_audit_carries_model_version_and_actor(db):
    engine.apply_group(
        db,
        group_evidence("g5", "h1", ["T1021.001"]),
        now=RISK_T0,
    )
    for event in stored_audit(db):
        assert event.model_version == "1.0.0"
        assert event.actor == "system"


def test_factors_keep_history_after_expiry(db):
    engine.apply_group(
        db,
        group_evidence(
            "g5",
            "h1",
            ["T1021.001"],
            observed=RISK_T0 - timedelta(days=30),
        ),
        now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    factors = db.scalars(
        select(EntityRiskV2Factor).where(EntityRiskV2Factor.risk_id == risk.risk_id)
    ).all()
    assert len(factors) >= 3
    assert all(f.expires_at < RISK_T0 for f in factors)
