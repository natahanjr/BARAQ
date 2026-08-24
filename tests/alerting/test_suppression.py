"""Alert suppression tests (spec 3.25, 3.26)."""
from __future__ import annotations

from datetime import timedelta

import pytest

from backend.alerting.models import AlertSuppressionRule
from backend.alerting.suppression import create_rule, is_suppressed, matches
from backend.detection.contract import make_detection_id

from tests.alerting.helpers import T0, detection, stored_suppressions


def _d(**kw):
    return detection(detection_id=make_detection_id("D001", "e", "t"), **kw)


def test_rule_requires_reason(db):
    with pytest.raises(ValueError, match="documented reason"):
        create_rule(db, policy_id="SUP-1", reason="  ", expires_at=T0 + timedelta(hours=1))


def test_rule_requires_future_expiration(db):
    with pytest.raises(ValueError, match="must expire in the future"):
        create_rule(db, policy_id="SUP-1", reason="maintenance",
                    expires_at=T0 - timedelta(hours=1), now=T0)


def test_no_permanent_suppression(db):
    """Spec 3.26: permanent silent suppression is not allowed - every rule
    must expire within a bounded, auditable horizon."""
    with pytest.raises(ValueError, match="no permanent suppression"):
        create_rule(db, policy_id="SUP-1", reason="silent",
                    expires_at=T0 + timedelta(days=365 * 10), now=T0)


def test_rule_stored_with_scope(db):
    rule = create_rule(
        db,
        policy_id="SUP-1",
        reason="Approved maintenance on workstation-42",
        expires_at=T0 + timedelta(hours=2),
        scope={"detector_id": "D001", "host": "workstation-42"},
        created_by="analyst@example",
        now=T0,
    )
    db.commit()
    rows = stored_suppressions(db)
    assert len(rows) == 1
    assert rows[0].policy_id == "SUP-1"
    assert rows[0].created_by == "analyst@example"
    assert rows[0].expires_at == T0 + timedelta(hours=2)
    assert rows[0].scope == {"detector_id": "D001", "host": "workstation-42"}


def test_matches_exact_scope(db):
    rule = AlertSuppressionRule(
        policy_id="SUP-1", reason="maintenance",
        expires_at=T0 + timedelta(hours=1),
        scope={"host": "workstation-42"},
    )
    assert matches(rule, _d(host="workstation-42"))
    assert not matches(rule, _d(host="server-01"))


def test_matches_wildcard(db):
    rule = AlertSuppressionRule(
        policy_id="SUP-1", reason="maintenance",
        expires_at=T0 + timedelta(hours=1),
        scope={"detector_id": "D001", "host": "*", "user": "*"},
    )
    assert matches(rule, _d(host="anything", user="anyone"))


def test_matches_source_ip_subnet(db):
    rule = AlertSuppressionRule(
        policy_id="SUP-1", reason="known admin source",
        expires_at=T0 + timedelta(hours=1),
        scope={"source_ip": "185.0.0.0/8"},
    )
    assert matches(rule, _d(source_ip="185.10.20.30"))
    assert not matches(rule, _d(source_ip="41.10.20.30"))


def test_matches_detector_scope(db):
    rule = AlertSuppressionRule(
        policy_id="SUP-1", reason="maint",
        expires_at=T0 + timedelta(hours=1),
        scope={"detector_id": "D002"},
    )
    assert not matches(rule, _d(detector_id="D001"))


def test_is_suppressed_only_active_rules(db):
    create_rule(db, policy_id="SUP-1", reason="active rule",
                expires_at=T0 + timedelta(hours=1), now=T0,
                scope={"detector_id": "D001", "host": "workstation-42"})
    expired = create_rule(db, policy_id="SUP-2", reason="expired rule",
                          expires_at=T0 + timedelta(hours=1), now=T0)
    expired.expires_at = T0 - timedelta(minutes=1)
    db.commit()
    assert is_suppressed(db, _d(host="workstation-42"), now=T0).policy_id == "SUP-1"
    assert is_suppressed(db, _d(host="other-host"), now=T0) is None


def test_expired_rule_never_suppresses(db):
    rule = create_rule(db, policy_id="SUP-1", reason="past maintenance",
                       expires_at=T0 + timedelta(hours=1), now=T0)
    rule.expires_at = T0 - timedelta(minutes=1)
    db.commit()
    assert is_suppressed(db, _d(host="workstation-42"), now=T0) is None