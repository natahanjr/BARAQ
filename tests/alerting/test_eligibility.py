"""Alert eligibility tests (spec 3.5, 3.6)."""

from __future__ import annotations

from backend.alerting.eligibility import ALERT_POLICIES, evaluate_detection, policy_for
from backend.detection.contract import make_detection_id
from tests.alerting.helpers import detection


def _d(detector_id="D001", **kw):
    return detection(
        detector_id=detector_id,
        detection_id=make_detection_id(detector_id, "e", "t"),
        **kw,
    )


def test_d001_high_severity_eligible():
    result = evaluate_detection(_d("D001", severity="high", confidence=0.91))
    assert result.eligible
    assert result.policy_id == "ALERT-POLICY-001"
    assert "sufficient confidence" in result.reason


def test_d001_low_severity_rejected():
    result = evaluate_detection(_d("D001", severity="low", confidence=0.99))
    assert not result.eligible
    assert result.policy_id == "ALERT-POLICY-001"


def test_d002_medium_confidence_eligible():
    result = evaluate_detection(_d("D002", severity="medium", confidence=0.65))
    assert result.eligible
    assert result.policy_id == "ALERT-POLICY-003"


def test_d002_below_confidence_rejected():
    result = evaluate_detection(_d("D002", severity="medium", confidence=0.4))
    assert not result.eligible


def test_d003_stricter_threshold_medium_rejected():
    result = evaluate_detection(_d("D003", severity="medium", confidence=0.95))
    assert not result.eligible
    assert result.policy_id == "ALERT-POLICY-004"


def test_d003_high_eligible():
    assert evaluate_detection(_d("D003", severity="high", confidence=0.8)).eligible


def test_d004_stricter_confidence_rejected():
    result = evaluate_detection(_d("D004", severity="medium", confidence=0.5))
    assert not result.eligible
    assert result.policy_id == "ALERT-POLICY-005"


def test_d004_high_confidence_eligible():
    assert evaluate_detection(_d("D004", severity="medium", confidence=0.75)).eligible


def test_d005_lower_threshold():
    result = evaluate_detection(_d("D005", severity="medium", confidence=0.55))
    assert result.eligible
    assert result.policy_id == "ALERT-POLICY-002"


def test_d005_below_minimum_confidence_rejected():
    assert not evaluate_detection(
        _d("D005", severity="medium", confidence=0.3)
    ).eligible


def test_unknown_detector_fails_closed():
    result = evaluate_detection(_d("D999", severity="medium", confidence=0.9))
    assert not result.eligible
    assert result.policy_id == "ALERT-POLICY-000"


def test_unknown_detector_high_severity_eligible():
    assert evaluate_detection(_d("D999", severity="high", confidence=0.95)).eligible


def test_policy_for_explicit_policy_ids():
    assert policy_for("D001").policy_id == "ALERT-POLICY-001"
    assert policy_for("D005").policy_id == "ALERT-POLICY-002"
    assert len(ALERT_POLICIES) == 5
