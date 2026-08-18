"""Phase 4 grouping policy tests (spec 4.8-4.12, 4.19, 4.36, 4.37)."""
import backend.config as config
from backend.aggregation.grouping import (
    behavior_family,
    membership_reason,
    membership_score,
    minimum_relationships,
    window_minutes,
)

from tests.alerting.helpers import detection


def test_family_from_detector_mapping():
    assert behavior_family(detection(detector_id="D001"), "D001") == "authentication"
    assert behavior_family(detection(detector_id="D002"), "D002") == "authentication"
    assert behavior_family(detection(detector_id="D003"), "D003") == "execution"
    assert behavior_family(detection(detector_id="D004"), "D004") == "execution"
    assert behavior_family(detection(detector_id="D005"), "D005") == "encryption"
    assert behavior_family(detection(detector_id="D999"), "D999") == "unknown"


def test_windows_are_config_driven():
    assert window_minutes("authentication") == 15
    assert window_minutes("execution") == 30
    assert window_minutes("encryption") == 10
    assert window_minutes("unknown") == 30
    assert config.AGGREGATION_WINDOWS_MINUTES == {
        "authentication": 15, "execution": 30, "encryption": 10, "unknown": 30,
    }


def test_minimum_relationships_floor():
    assert minimum_relationships("authentication") >= 2
    assert minimum_relationships("unknown") >= 4


def test_membership_score_is_grouping_not_risk():
    score = membership_score(detection(), "authentication")
    assert 0.0 <= score <= 1.0
    assert score == 1.00
    assert config.AGGREGATION_MEMBERSHIP_WEIGHTS["host"] == 0.40
    assert config.AGGREGATION_MEMBERSHIP_WEIGHTS["user"] == 0.25
    assert config.AGGREGATION_MEMBERSHIP_WEIGHTS["source"] == 0.20
    assert config.AGGREGATION_MEMBERSHIP_WEIGHTS["time"] == 0.15


def test_membership_reason_is_explainable():
    reason = membership_reason(detection(host="ml-host", user="ml-online-user"),
                               "authentication", 15)
    assert "same host" in reason
    assert "same user" in reason
    assert "same source" in reason
    assert "same behavior family" in reason
    assert "15-minute" in reason


def test_same_mitre_alone_is_never_grouping():
    """Spec 4.26: MITRE is context, not correlation."""
    a = detection(detector_id="D001", mitre="T1133", host="h1", user="u1", source_ip="1.1.1.1")
    b = detection(detector_id="D003", mitre="T1133", host="h2", user="u2", source_ip="2.2.2.2")
    from backend.aggregation.fingerprint import group_fingerprint

    assert group_fingerprint(a, behavior_family(a, "D001")) != group_fingerprint(
        b, behavior_family(b, "D003")
    )