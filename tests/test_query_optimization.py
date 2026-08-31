"""Tests for query optimization."""
from backend.database.optimization import QueryOptimizer


def test_record_slow_query():
    opt = QueryOptimizer()
    opt.record_slow_query("SELECT * FROM alerts", 250)
    assert len(opt.get_slow_queries()) == 1


def test_fast_queries_not_captured():
    opt = QueryOptimizer()
    opt.record_slow_query("SELECT 1", 5)
    assert len(opt.get_slow_queries()) == 0


def test_recommendations():
    opt = QueryOptimizer()
    recs = opt.get_recommendations()
    assert len(recs) > 0
    assert recs[0].table == "alerts"
