"""Tests for alert aggregation, ML lifecycle staleness and assistant RAG."""
from __future__ import annotations

import pytest

from backend.config import ALERT_ESCALATE_AFTER


def test_repeat_triggers_increment_and_escalate(db):
    """The same finding refreshes one open alert and escalates its severity."""
    from backend.api.system import run_pipeline
    from backend.database.models import Alert
    from tests.conftest import _scenario

    records = _scenario("brute_force")
    for _ in range(ALERT_ESCALATE_AFTER + 1):
        run_pipeline(db, records)

    alert = db.query(Alert).filter(Alert.rule == "brute_force").first()
    assert alert is not None
    assert db.query(Alert).filter(Alert.rule == "brute_force").count() == 1
    assert alert.trigger_count == ALERT_ESCALATE_AFTER + 1
    assert alert.severity == "critical"
    assert alert.status == "open"


def test_repeat_under_threshold_keeps_severity(db):
    from backend.api.system import run_pipeline
    from backend.database.models import Alert
    from tests.conftest import _scenario

    records = _scenario("brute_force")
    for _ in range(ALERT_ESCALATE_AFTER - 1):
        run_pipeline(db, records)

    alert = db.query(Alert).filter(Alert.rule == "brute_force").first()
    assert alert.trigger_count == ALERT_ESCALATE_AFTER - 1
    assert alert.severity == "high"


def test_ml_staleness_lifecycle(db):
    import os

    from backend.config import ML_META_FILE
    from backend.ml.anomaly import MLAnomalyDetector

    # Deterministic start: another test may have trained a model earlier in
    # this session and persisted a fresh meta file.
    if os.path.exists(ML_META_FILE):
        os.unlink(ML_META_FILE)

    detector = MLAnomalyDetector()
    stale, reason = detector.is_stale()
    assert stale is True
    assert reason == "never-trained"

    from backend.database.models import NormalizedEvent
    from tests.conftest import run_simulation

    run_simulation(db)
    result = detector.train(db, hours=24)
    if result.get("trained"):
        stale, reason = detector.is_stale(db)
        assert stale is False
        assert reason == "fresh"
        status = detector.status(db)
        assert status["stale"] is False
        assert status["trained_at"] == detector.trained_at
    else:
        pytest.skip(f"sklearn unavailable: {result.get('status')}")


def test_ml_meta_persisted(db):
    import os

    from backend.config import ML_META_FILE
    from backend.ml.anomaly import MLAnomalyDetector
    from tests.conftest import run_simulation

    run_simulation(db)
    detector = MLAnomalyDetector()
    result = detector.train(db, hours=24)
    if not result.get("trained"):
        pytest.skip("sklearn unavailable")

    assert os.path.exists(ML_META_FILE)
    restored = MLAnomalyDetector()
    assert restored.trained_at == detector.trained_at
    assert restored.n_samples == detector.n_samples


def test_assistant_rag_grounds_in_resolved_incidents(db):
    from backend.ai.assistant import SecurityAssistant
    from backend.database.models import Alert
    from tests.conftest import run_simulation

    run_simulation(db, "brute_force")
    old = db.query(Alert).first()
    old.status = "closed"
    old.evidence = "12 failed logons for account 'administrator' from 192.168.99.77"
    old.recommendation = "Block the source IP and reset the password."
    db.commit()

    run_simulation(db, "brute_force")
    assistant = SecurityAssistant(db)
    reply = assistant.chat("explain alert 1")
    assert "Similar past incidents" in reply
    assert "administrator" in reply or "Block the source IP" in reply
