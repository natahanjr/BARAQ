"""Tests for MITRE gap analysis."""
from backend.mitre.gap_analysis import generate_gap_report, GapReport


def test_gap_report_empty():
    report = generate_gap_report()
    assert isinstance(report, GapReport)
    assert report.total_techniques >= 0


def test_gap_report_structure():
    report = generate_gap_report()
    assert hasattr(report, "covered_pct") or hasattr(report, "coverage_pct")
