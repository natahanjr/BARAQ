"""Tests for the vulnerability scanner module (version logic, CVE matching, rule)."""

from __future__ import annotations

from datetime import UTC

import pytest

from backend.database.connection import SessionLocal
from backend.database.models import VulnFinding
from backend.detection.rules.vulnerability import VulnerabilityRule, _severity_for
from backend.vulnscan.engine import match_product, scan_inventory
from backend.vulnscan.version import compare_versions, version_lt


class TestVersionCompare:
    @pytest.mark.parametrize(
        "a,b,expected",
        [
            ("1.0", "1.0", 0),
            ("1.0", "1.1", -1),
            ("2.14.1", "2.15.0", -1),
            ("2.15.0", "2.15.0", 0),
            ("2.17.1", "2.15.0", 1),
            ("10.0", "9.9", 1),
            ("1.10", "1.9", 1),
        ],
    )
    def test_compare(self, a, b, expected):
        assert compare_versions(a, b) == expected

    def test_lt(self):
        assert version_lt("2.14.1", "2.15.0")
        assert not version_lt("2.15.0", "2.15.0")


class TestCveMatching:
    def test_log4j_vulnerable_and_patched(self, tmp_path):
        cves = [
            {
                "cve_id": "CVE-2021-44228",
                "match": "Log4j",
                "version_lt": "2.15.0",
                "cvss": 10.0,
                "severity": "critical",
                "description": "Log4Shell",
                "remediation": "upgrade",
            }
        ]
        assert len(match_product("Apache Log4j Core", "2.14.1", cves)) == 1
        assert len(match_product("Apache Log4j Core", "2.17.1", cves)) == 0

    def test_match_only_entry_ignores_version(self):
        cves = [
            {
                "cve_id": "CVE-2021-34527",
                "match": "PrintNightmare",
                "version_lt": "999.0",
                "cvss": 8.8,
                "severity": "high",
                "description": "",
                "remediation": "",
            }
        ]
        assert len(match_product("Windows PrintNightmare Pack", "1.0", cves)) == 1

    def test_scan_inventory_sorts_by_cvss(self):
        inventory = {
            "products": [
                {"name": "Apache Log4j Core", "version": "2.12.0"},
                {"name": "Some App", "version": "1.0"},
            ]
        }
        findings = scan_inventory(
            inventory,
            [
                {
                    "cve_id": "CVE-A",
                    "match": "log4j",
                    "version_lt": "2.15.0",
                    "cvss": 6.0,
                    "severity": "medium",
                    "description": "",
                    "remediation": "",
                },
                {
                    "cve_id": "CVE-B",
                    "match": "log4j",
                    "version_lt": "2.15.0",
                    "cvss": 10.0,
                    "severity": "critical",
                    "description": "",
                    "remediation": "",
                },
            ],
        )
        assert [f["cve_id"] for f in findings] == ["CVE-B", "CVE-A"]


class TestSeverityMapping:
    def test_cvss_map(self):
        assert _severity_for(10.0) == "critical"
        assert _severity_for(8.0) == "high"
        assert _severity_for(5.0) == "medium"
        assert _severity_for(2.0) == "low"


class TestVulnerabilityRule:
    def _seed(self):
        from datetime import datetime

        db = SessionLocal()
        db.add(
            VulnFinding(
                host="labhost",
                product="Apache Log4j Core",
                version="2.14.1",
                cve_id="CVE-2021-44228",
                cvss=10.0,
                severity="critical",
                description="Log4Shell",
                remediation="upgrade",
                found_at=datetime.now(UTC),
            )
        )
        db.commit()
        db.close()

    def test_rule_creates_finding(self):
        self._seed()
        db = SessionLocal()
        rule = VulnerabilityRule(db)
        results = rule.evaluate(window_minutes=10)
        db.close()
        assert len(results) == 1
        assert results[0].mitre_id == "T1190"
        assert "CVE-2021-44228" in results[0].evidence
        assert results[0].severity == "critical"
