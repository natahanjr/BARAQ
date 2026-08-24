"""Phase 4 window tests (spec 4.13, 4.14)."""
from datetime import timedelta

import backend.config as config
from backend.aggregation.engine import process_alerts
from backend.aggregation.windows import within_window

from tests.aggregation.helpers import GROUP_T0, dt, fabricate_alerts, make_alerts, stored_groups
from tests.alerting.helpers import detection


def test_within_window_math():
    last = GROUP_T0
    assert within_window(last, last + timedelta(minutes=14), "authentication")
    assert not within_window(last, last + timedelta(minutes=16), "authentication")
    assert within_window(last, last + timedelta(minutes=29), "execution")
    assert not within_window(last, last + timedelta(minutes=31), "execution")


def test_sliding_window_three_alerts_one_group(db):
    """10:00 + 10:10 + 10:20 within a 30-min window -> one group (4.14)."""
    alerts = fabricate_alerts(
        db,
        [
            dict(detector_id="D003", minutes_ago=20.0),
            dict(detector_id="D003", minutes_ago=10.0),
            dict(detector_id="D003", minutes_ago=0.0),
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 1
    assert groups[0].alert_count == 3


def test_outside_window_makes_new_group(db):
    """10:00 + 11:30 must not stay in the same group (4.14)."""
    alerts = fabricate_alerts(
        db,
        [
            dict(minutes_ago=0.0),
            dict(minutes_ago=90.0),  # 1.5h later, beyond the 15-min auth window
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 2
    assert groups[0].status == "CLOSED"
    assert groups[0].alert_count == 1
    assert groups[1].status == "ACTIVE"
    assert groups[1].alert_count == 1


def test_windows_are_config_not_hardcoded(db):
    assert config.AGGREGATION_WINDOWS_MINUTES["authentication"] == 15
    assert config.AGGREGATION_WINDOWS_MINUTES["execution"] == 30
    assert config.AGGREGATION_WINDOWS_MINUTES["encryption"] == 10
    for family in config.AGGREGATION_WINDOWS_MINUTES:
        assert config.AGGREGATION_WINDOWS_MINUTES[family] > 0