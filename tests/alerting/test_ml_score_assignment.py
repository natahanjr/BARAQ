"""Regression test for ML score assignment in _compute_risk.

Bug: The old code nested `for ev, _ in needs_live:` inside
`for score in detector.score_events([...])`, so every event
received the LAST event's score instead of its own, and
anomaly_scores could contain the same event multiple times.

Fix: call score_events() once on all features, then zip each
event with its own score.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from backend.detection.alerting import AlertingService


def _event(ml_score=None, event_id=1):
    ev = MagicMock()
    ev.ml_score = ml_score
    ev.event_id = event_id
    return ev


def test_each_event_gets_its_own_ml_score(db):
    """Each event must receive its own score, not the last event's score."""
    service = AlertingService(db)

    e1 = _event(ml_score=None, event_id=101)
    e2 = _event(ml_score=None, event_id=102)
    e3 = _event(ml_score=None, event_id=103)

    detector = MagicMock()
    detector.is_ready = True
    # score_events returns scores aligned with input order: [0.2, 0.5, 0.9]
    detector.score_events.return_value = [0.2, 0.5, 0.9]

    from backend.ml.anomaly import event_feature_vector

    service._evidence_events = MagicMock(
        return_value=[e1, e2, e3]
    )

    # Patch event_feature_vector to return a dummy vector per event
    import backend.detection.alerting as A

    orig = A.event_feature_vector
    A.event_feature_vector = lambda ev: [float(ev.event_id)]

    try:
        result = service._compute_risk(
            type("R", (), {"event_ids": [101, 102, 103], "severity": "high", "confidence": 0.9})(),
        )
    finally:
        A.event_feature_vector = orig

    # Each event should have its own score, not the last one (0.9)
    assert e1.ml_score == 0.2, f"e1 should get 0.2, got {e1.ml_score}"
    assert e2.ml_score == 0.5, f"e2 should get 0.5, got {e2.ml_score}"
    assert e3.ml_score == 0.9, f"e3 should get 0.9, got {e3.ml_score}"

    # score_events should be called exactly once, not once per event
    assert detector.score_events.call_count == 1, (
        f"score_events called {detector.score_events.call_count} times, expected 1"
    )

    # Each event should appear exactly once in anomaly_scores
    assert result[0] > 0, "risk should be > 0"


def test_score_events_called_once_not_per_event(db):
    """score_events must be called once total, not once per event."""
    service = AlertingService(db)

    events = [_event(ml_score=None, event_id=i) for i in range(5)]

    detector = MagicMock()
    detector.is_ready = True
    detector.score_events.return_value = [0.1, 0.2, 0.3, 0.4, 0.5]

    service._evidence_events = MagicMock(return_value=events)

    import backend.detection.alerting as A

    orig = A.event_feature_vector
    A.event_feature_vector = lambda ev: [float(ev.event_id)]

    try:
        service._compute_risk(
            type("R", (), {"event_ids": list(range(5)), "severity": "high", "confidence": 0.9})(),
        )
    finally:
        A.event_feature_vector = orig

    assert detector.score_events.call_count == 1, (
        f"score_events called {detector.score_events.call_count} times, expected 1"
    )
