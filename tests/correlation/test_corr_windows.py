"""Phase 5 window tests (spec 5.9, 5.10)."""

from datetime import UTC, datetime, timedelta

from backend.correlation.windows import window_for, window_minutes, within_window

T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=UTC)


def test_windows_are_configurable_not_hardcoded():
    assert window_minutes("authentication_to_execution") == 30
    assert window_minutes("execution_to_privilege") == 60
    assert window_minutes("host_to_host_lateral_movement") == 60
    assert window_minutes("multi_stage") == 120
    # Unknown keys fail closed to the default, never raise.
    assert window_minutes("no_such_key") == 120


def test_window_is_bounded():
    assert within_window(T0, T0 + timedelta(minutes=29), "authentication_to_execution")
    assert not within_window(
        T0, T0 + timedelta(minutes=31, seconds=1), "authentication_to_execution"
    )
    assert within_window(T0, T0 + timedelta(minutes=59), "execution_to_privilege")
    assert not within_window(
        T0, T0 + timedelta(minutes=61, seconds=1), "execution_to_privilege"
    )
    assert within_window(T0, T0 + timedelta(minutes=119), "multi_stage")
    assert not within_window(T0, T0 + timedelta(minutes=121, seconds=1), "multi_stage")


def test_clock_drift_slack_is_bounded():
    # A small drift allowance, not an unbounded grace period.
    assert within_window(
        T0, T0 + timedelta(minutes=30, seconds=59), "authentication_to_execution"
    )
    assert not within_window(
        T0, T0 + timedelta(minutes=30, seconds=61), "authentication_to_execution"
    )


def test_window_for_returns_timedelta():
    assert window_for("multi_stage") == timedelta(minutes=120)
