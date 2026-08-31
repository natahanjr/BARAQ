"""Tests for UEBA engine."""
from backend.ml.ueba import UEBAEngine


def test_build_baseline():
    engine = UEBAEngine()
    events = [{"timestamp": "2026-08-31T10:00:00Z", "host": "PC-01", "src_ip": "10.0.0.1"} for _ in range(10)]
    baseline = engine.build_baseline("alice", events)
    assert baseline.username == "alice"
    assert baseline.event_count_30d == 10
    assert "PC-01" in baseline.typical_hosts


def test_no_anomalies_on_baseline():
    engine = UEBAEngine()
    events = [{"timestamp": "2026-08-31T10:00:00Z", "host": "PC-01", "src_ip": "10.0.0.1"}]
    engine.build_baseline("alice", events)
    anomalies = engine.detect_anomalies("alice", events)
    assert anomalies == []


def test_detect_new_host():
    engine = UEBAEngine()
    events = [{"timestamp": "2026-08-31T10:00:00Z", "host": "PC-01", "src_ip": "10.0.0.1"}]
    engine.build_baseline("alice", events)
    new_events = [{"timestamp": "2026-08-31T10:00:00Z", "host": "PC-99", "src_ip": "10.0.0.1"}]
    anomalies = engine.detect_anomalies("alice", new_events)
    assert any(a["type"] == "new_host" for a in anomalies)


def test_detect_volume_spike():
    engine = UEBAEngine()
    events = [{"timestamp": "2026-08-31T10:00:00Z", "host": "PC-01"} for _ in range(5)]
    engine.build_baseline("alice", events)
    spike = [{"timestamp": "2026-08-31T10:00:00Z", "host": "PC-01"} for _ in range(100)]
    anomalies = engine.detect_anomalies("alice", spike)
    assert any(a["type"] == "event_volume_spike" for a in anomalies)
