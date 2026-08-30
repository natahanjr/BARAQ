"""Tests for the search engine (backend/search/engine.py)."""

from __future__ import annotations

import pytest

from backend.search.engine import SearchError, execute_search, parse_query
from tests.fixtures import full_suite


def _seed_events(db, scenario: str | None = None):
    from backend.api.system import run_pipeline

    run_pipeline(db, full_suite() if scenario is None else _scenario(db, scenario))


def _scenario(db, name: str):
    from tests.fixtures import (
        benign_baseline,
        brute_force,
        lateral_movement,
        privilege_escalation,
        suspicious_powershell,
    )

    return {
        "brute_force": brute_force,
        "powershell": suspicious_powershell,
        "privilege_escalation": privilege_escalation,
        "lateral_movement": lateral_movement,
        "baseline": benign_baseline,
    }[name]()


def test_parse_query_basic():
    q = parse_query('source=sysmon event_id=4625 "failed logon" | stats count by user')
    assert q.index == "events"
    assert ("source", "sysmon") in q.filters
    assert ("event_id", "4625") in q.filters
    assert q.free_text == ["failed logon"]
    assert len(q.pipes) == 1
    assert q.pipes[0].name == "stats"


def test_parse_query_index_alerts():
    q = parse_query("index=alerts rule=brute_force | top 10 host")
    assert q.index == "alerts"
    assert ("rule", "brute_force") in q.filters


def test_parse_query_rejects_empty():
    with pytest.raises(SearchError):
        parse_query("   ")


def test_parse_query_rejects_unterminated_quote():
    with pytest.raises(SearchError):
        parse_query('source=sysmon "oops')


def test_event_filters_and_free_text(db):
    _seed_events(db, "brute_force")
    res = execute_search(db, "event_id=4625", earliest="-30d")
    assert res.index == "events"
    assert res.total > 0
    assert all(r[1] == 4625 for r in res.rows)  # column index 1 = event_id

    res = execute_search(db, 'event_id=4625 "failed"', earliest="-30d")
    assert res.total > 0


def test_stats_count_by(db):
    _seed_events(db, "brute_force")
    res = execute_search(db, "| stats count by category | sort -count", earliest="-30d")
    assert res.columns == ["category", "count"]
    assert res.total >= 1
    counts = [r[1] for r in res.rows]
    assert counts == sorted(counts, reverse=True)


def test_stats_multiple_aggs_by_multiple_fields(db):
    _seed_events(db)
    res = execute_search(
        db, "| stats count, avg(risk_score) by category | sort -count", earliest="-30d"
    )
    assert res.columns == ["category", "count", "avg_risk_score"]
    assert res.total >= 1
    for row in res.rows:
        assert row[2] is None or isinstance(row[2], float)


def test_top_pipe(db):
    _seed_events(db, "brute_force")
    res = execute_search(db, "event_id=4625 | top 3 user", earliest="-30d")
    assert res.columns == ["user", "count"]
    assert len(res.rows) <= 3
    assert res.rows and res.rows[0][1] >= 1


def test_rare_pipe(db):
    _seed_events(db, "brute_force")
    res = execute_search(db, "event_id=4625 | rare 3 user", earliest="-30d")
    assert res.columns == ["user", "count"]
    counts = [r[1] for r in res.rows]
    assert counts == sorted(counts)


def test_table_pipe(db):
    _seed_events(db, "brute_force")
    res = execute_search(
        db, "event_id=4625 | table user, host | limit 5", earliest="-30d"
    )
    assert res.columns == ["user", "host"]
    assert len(res.rows) <= 5


def test_fields_drop(db):
    _seed_events(db, "brute_force")
    res = execute_search(
        db, "event_id=4625 | fields -message, -org | limit 3", earliest="-30d"
    )
    assert "message" not in res.columns
    assert "org" not in res.columns
    assert "user" in res.columns


def test_where_and_sort_on_aggregated(db):
    _seed_events(db)
    res = execute_search(
        db,
        "| stats count by category | sort -count | where count>1",
        earliest="-30d",
    )
    assert all(r[1] > 1 for r in res.rows)
    counts = [r[1] for r in res.rows]
    assert counts == sorted(counts, reverse=True)


def test_limit_pipe(db):
    _seed_events(db, "brute_force")
    res = execute_search(db, "event_id=4625 | limit 3", earliest="-30d")
    assert len(res.rows) <= 3


def test_alerts_index(db):
    _seed_events(db, "brute_force")
    res = execute_search(db, "index=alerts severity=high | top 5 rule", earliest="-30d")
    assert res.index == "alerts"
    assert res.total >= 1
    assert res.columns == ["rule", "count"]


def test_unknown_field_raises(db):
    with pytest.raises(SearchError):
        execute_search(db, "bogus_field=1", earliest="-30d")


def test_unknown_index_raises(db):
    with pytest.raises(SearchError):
        execute_search(db, "index=nosuch | limit 5", earliest="-30d")


def test_unknown_pipe_raises(db):
    with pytest.raises(SearchError):
        execute_search(db, "event_id=4625 | explode", earliest="-30d")


def test_relative_time_window(db):
    _seed_events(db, "brute_force")
    res = execute_search(db, "event_id=4625", earliest="-1h", latest="-1h")
    assert res.total == 0
    res = execute_search(db, "event_id=4625", earliest="-1h")
    assert res.total >= 1
    with pytest.raises(SearchError):
        execute_search(db, "event_id=4625", earliest="now", latest="-1h")


def test_org_scoping(db):
    _seed_events(db, "brute_force")
    res = execute_search(db, "event_id=4625", org="tenant-nope", earliest="-30d")
    assert res.total == 0
    res = execute_search(db, "event_id=4625", org="", earliest="-30d")
    assert res.total > 0


def test_timechart_count(db):
    _seed_events(db, "brute_force")
    res = execute_search(db, "| timechart span=1d count", earliest="-30d")
    assert res.columns == ["_time", "count"]
    assert res.total >= 1
    times = [r[0] for r in res.rows]
    assert times == sorted(times)


def test_timechart_pivot_by(db):
    _seed_events(db, "brute_force")
    res = execute_search(db, "| timechart span=1d count by category", earliest="-30d")
    assert res.columns[0] == "_time"
    assert res.columns[1] == "count"
    cats = res.columns[2:]
    assert cats
    per_cat = {c: sum(r[2 + i] for r in res.rows) for i, c in enumerate(cats)}
    assert sum(per_cat.values()) == sum(r[1] for r in res.rows)


def test_timechart_with_aggregation(db):
    _seed_events(db, "brute_force")
    res = execute_search(db, "| timechart span=1d avg(risk_score)", earliest="-30d")
    assert res.columns == ["_time", "avg_risk_score"]
    assert all(r[1] is None or isinstance(r[1], float) for r in res.rows)


def test_timechart_invalid_span(db):
    _seed_events(db, "brute_force")
    with pytest.raises(SearchError):
        execute_search(db, "| timechart span=banana count", earliest="-30d")


def test_transaction_groups_session(db):
    _seed_events(db, "brute_force")
    res = execute_search(
        db, "event_id=4625 | transaction by host maxspan=30m", earliest="-30d"
    )
    assert res.columns == ["_time", "duration", "count", "host"]
    assert res.total >= 1
    assert all(r[2] >= 1 for r in res.rows)
    assert all(r[3] for r in res.rows)


def test_transaction_no_by_field_raises(db):
    with pytest.raises(SearchError):
        execute_search(db, "event_id=4625 | transaction maxspan=30m", earliest="-30d")


def test_transaction_unknown_field_raises(db):
    with pytest.raises(SearchError):
        execute_search(db, "event_id=4625 | transaction by bogus", earliest="-30d")


def test_timechart_chained_with_sort_and_where(db):
    _seed_events(db, "brute_force")
    res = execute_search(
        db,
        "| timechart span=1d count by category | sort -count | where count>0",
        earliest="-30d",
    )
    assert res.total >= 1
    counts = [r[1] for r in res.rows]
    assert counts == sorted(counts, reverse=True)
    assert all(c > 0 for c in counts)


def test_sort_after_table_on_raw_rows(db):
    _seed_events(db, "brute_force")
    res = execute_search(
        db,
        "event_id=4625 | table user, host, risk_score | sort -risk_score | limit 5",
        earliest="-30d",
    )
    assert res.columns == ["user", "host", "risk_score"]
    assert len(res.rows) <= 5
    scores = [r[2] for r in res.rows]
    assert scores == sorted(scores, reverse=True)


def test_where_after_table_on_raw_rows(db):
    _seed_events(db, "brute_force")
    res = execute_search(
        db,
        "event_id=4625 | table user, risk_score | where risk_score>0 | limit 5",
        earliest="-30d",
    )
    assert res.columns == ["user", "risk_score"]
    assert all(r[1] > 0 for r in res.rows)
