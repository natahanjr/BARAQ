"""Tests for compliance gap analysis."""
from backend.compliance.gap_analysis import analyze_gaps
from backend.compliance.frameworks import assess_control


def test_gap_report_unknown():
    assert analyze_gaps("NONEXISTENT") is None


def test_gap_report_all_unassessed():
    report = analyze_gaps("SOC2")
    assert report is not None
    assert report.unassessed == report.total_controls
    assert len(report.gaps) == report.total_controls


def test_gap_report_partial():
    assess_control("SOC2", "CC6.1", "compliant")
    assess_control("SOC2", "CC6.2", "partial")
    assess_control("SOC2", "CC7.1", "non-compliant")
    report = analyze_gaps("SOC2")
    assert report.compliant >= 1
    assert report.partial >= 1
    assert report.non_compliant >= 1
