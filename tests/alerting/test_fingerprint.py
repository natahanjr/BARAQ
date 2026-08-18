"""Alert fingerprint tests (spec 3.7)."""
from __future__ import annotations

from backend.alerting.fingerprint import fingerprint
from backend.detection.contract import make_detection_id

from tests.alerting.helpers import detection


def _d(**kw):
    return detection(detection_id=make_detection_id("D001", "e", "t"), **kw)


def test_deterministic():
    a = fingerprint(_d())
    b = fingerprint(_d())
    assert a == b


def test_stable_and_reproducible():
    first = fingerprint(_d(host="ml-host", user="ml-online-user", source_ip="185.0.0.1"))
    assert fingerprint(_d(host="ml-host", user="ml-online-user", source_ip="185.0.0.1")) == first


def test_independent_of_alert_id_and_timestamp():
    a = fingerprint(_d(minutes_ago=1.0))
    b = fingerprint(_d(minutes_ago=30.0))
    assert a == b


def test_different_host_different_fingerprint():
    assert fingerprint(_d(host="ml-host")) != fingerprint(_d(host="finance-host"))


def test_different_user_different_fingerprint():
    assert fingerprint(_d(user="alice")) != fingerprint(_d(user="bob"))


def test_different_source_ip_different_fingerprint():
    assert fingerprint(_d(source_ip="185.0.0.1")) != fingerprint(_d(source_ip="41.0.0.1"))


def test_different_detector_different_fingerprint():
    assert fingerprint(_d(detector_id="D001")) != fingerprint(_d(detector_id="D002"))


def test_different_mitre_different_fingerprint():
    assert fingerprint(_d(mitre="T1133")) != fingerprint(_d(mitre="T1110"))


def test_not_a_uuid():
    fp = fingerprint(_d())
    assert len(fp) == 64  # sha256 hex
    assert fp.isalnum()