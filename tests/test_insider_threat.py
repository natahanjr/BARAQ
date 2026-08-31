"""Tests for insider threat detection."""
from backend.ml.insider_threat import InsiderThreatDetector, ThreatLevel


def test_no_indicators():
    det = InsiderThreatDetector()
    result = det.evaluate("alice", [])
    assert result.threat_level == ThreatLevel.NONE
    assert result.score == 0


def test_low_risk():
    det = InsiderThreatDetector()
    result = det.evaluate("alice", ["unusual_process"])
    assert result.threat_level == ThreatLevel.LOW


def test_critical_risk():
    det = InsiderThreatDetector()
    result = det.evaluate("alice", ["privilege_escalation", "data_staging", "large_transfer"])
    assert result.threat_level == ThreatLevel.CRITICAL
    assert "Disable account immediately" in result.recommended_actions


def test_list_high_risk():
    det = InsiderThreatDetector()
    det.evaluate("alice", ["privilege_escalation", "data_staging"])
    det.evaluate("bob", ["unusual_process"])
    high = det.list_high_risk()
    assert any(s.username == "alice" for s in high)
