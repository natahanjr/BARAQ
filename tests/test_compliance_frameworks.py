"""Tests for compliance frameworks."""
from backend.compliance.frameworks import (
    get_framework, list_frameworks, assess_control, compliance_summary,
)


def test_list_frameworks():
    fw = list_frameworks()
    assert "SOC2" in fw
    assert "ISO27001" in fw
    assert "NIST-CSF" in fw


def test_get_framework():
    fw = get_framework("SOC2")
    assert fw is not None
    assert fw.name == "SOC 2"
    assert len(fw.controls) > 0


def test_assess_control():
    result = assess_control("SOC2", "CC6.1", "compliant", evidence=["ACL audit"])
    assert result is not None
    assert result.status == "compliant"


def test_compliance_summary():
    summary = compliance_summary("SOC2")
    assert summary["framework"] == "SOC 2"
    assert summary["total_controls"] > 0
    assert summary["compliance_pct"] >= 0


def test_unknown_framework():
    assert get_framework("NONEXISTENT") is None
    assert compliance_summary("NONEXISTENT") == {"error": "Framework NONEXISTENT not found"}
