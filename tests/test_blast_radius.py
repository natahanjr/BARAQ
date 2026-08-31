"""Tests for blast radius analysis."""
from backend.risk.blast_radius import BlastRadiusAnalyzer


def test_empty_connections():
    analyzer = BlastRadiusAnalyzer()
    result = analyzer.calculate("host-01", "host", [])
    assert result.direct_connections == 0
    assert result.risk_level == "low"


def test_small_blast():
    analyzer = BlastRadiusAnalyzer()
    conns = [{"target": f"entity-{i}", "relationship": "connected_to"} for i in range(3)]
    result = analyzer.calculate("host-01", "host", conns)
    assert result.risk_level == "low"
    assert result.direct_connections == 3


def test_large_blast():
    analyzer = BlastRadiusAnalyzer()
    conns = [{"target": f"entity-{i}", "relationship": "connected_to"} for i in range(30)]
    result = analyzer.calculate("host-01", "host", conns)
    assert result.risk_level == "high"


def test_user_blast_radius():
    analyzer = BlastRadiusAnalyzer()
    result = analyzer.user_blast_radius("alice", ["PC-01", "PC-02"], ["powershell.exe"], ["10.0.0.1"])
    assert result.direct_connections == 4
    assert len(result.attack_paths) == 4
