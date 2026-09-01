"""Tests for P3 ML enhancements: community rules, retention, archival, remediation, comparison."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from backend.ml.community_rules import (
    CommunityRuleManager,
    ContributedRule,
    RuleValidator,
    RuleType,
    RuleStatus,
)
from backend.ml.retention import (
    MLDataRetention,
    RetentionPolicy,
    MLDashboardConfig,
    ArchiveEntry,
)
from backend.ml.remediation import (
    RemediationEngine,
    FNReport,
    RemediationAction,
)
from backend.ml.comparison import (
    SOCComparison,
    SOCPlatform,
    PlatformCapability,
    PLATFORM_PROFILES,
)


class TestCommunityRules:
    """Test community rule contribution framework."""

    def test_validator_sigma_valid(self):
        validator = RuleValidator()
        rule = """
title: Test Rule
detection:
  selection:
    EventID: 4625
  condition: selection
level: medium
"""
        valid, errors, warnings = validator.validate_sigma(rule)
        assert valid is True
        assert len(errors) == 0

    def test_validator_sigma_missing_fields(self):
        validator = RuleValidator()
        rule = "title: Test\n"
        valid, errors, warnings = validator.validate_sigma(rule)
        assert valid is False
        assert any("Missing" in e for e in errors)

    def test_validator_sigma_invalid_yaml(self):
        validator = RuleValidator()
        valid, errors, warnings = validator.validate_sigma("{{invalid yaml")
        assert valid is False

    def test_validator_correlation_valid(self):
        validator = RuleValidator()
        rule = """
name: Test Correlation
description: Test correlation rule
window_minutes: 30
stages:
  - label: stage1
    rules: [rule1]
  - label: stage2
    rules: [rule2]
"""
        valid, errors, warnings = validator.validate_correlation(rule)
        assert valid is True

    def test_validator_python_valid(self):
        validator = RuleValidator()
        rule = """
class TestRule:
    def evaluate(self):
        return []
"""
        valid, errors, warnings = validator.validate_python_native(rule)
        assert valid is True

    def test_validator_python_syntax_error(self):
        validator = RuleValidator()
        valid, errors, warnings = validator.validate_python_native("def foo(")
        assert valid is False
        assert any("syntax" in e.lower() for e in errors)

    def test_manager_submit_rule(self):
        manager = CommunityRuleManager()
        rule = manager.submit_rule(
            rule_type=RuleType.SIGMA,
            title="Test Rule",
            description="A test rule",
            content="title: Test\ndetection:\n  sel:\n    EventID: 1\n  condition: sel\nlevel: low",
            author="test_user",
        )
        assert rule.status == RuleStatus.PENDING
        assert rule.rule_id.startswith("CR-SIG-")

    def test_manager_submit_invalid_rule(self):
        manager = CommunityRuleManager()
        rule = manager.submit_rule(
            rule_type=RuleType.SIGMA,
            title="Bad Rule",
            description="Invalid",
            content="not yaml",
            author="test_user",
        )
        assert rule.status == RuleStatus.REJECTED

    def test_manager_review_approve(self):
        manager = CommunityRuleManager()
        rule = manager.submit_rule(
            rule_type=RuleType.SIGMA,
            title="Test Rule",
            description="Test",
            content="title: Test\ndetection:\n  sel:\n    EventID: 1\n  condition: sel\nlevel: low",
            author="user1",
        )
        reviewed = manager.review_rule(rule.rule_id, reviewer="analyst1", approved=True)
        assert reviewed.status == RuleStatus.APPROVED

    def test_manager_review_reject(self):
        manager = CommunityRuleManager()
        rule = manager.submit_rule(
            rule_type=RuleType.SIGMA,
            title="Test Rule",
            description="Test",
            content="title: Test\ndetection:\n  sel:\n    EventID: 1\n  condition: sel\nlevel: low",
            author="user1",
        )
        reviewed = manager.review_rule(rule.rule_id, reviewer="analyst1", approved=False, notes="Not needed")
        assert reviewed.status == RuleStatus.REJECTED

    def test_manager_statistics(self):
        manager = CommunityRuleManager()
        manager.submit_rule(
            rule_type=RuleType.SIGMA, title="R1", description="",
            content="title: T\ndetection:\n  s:\n    EventID: 1\n  condition: s\nlevel: low",
            author="u1",
        )
        stats = manager.get_statistics()
        assert stats["total_submitted"] == 1
        assert "sigma" in stats["by_type"]


class TestRetention:
    """Test ML data retention and archival."""

    def test_retention_policy_defaults(self):
        policy = RetentionPolicy()
        assert policy.max_age_days == 90
        assert policy.max_versions == 10

    def test_archive_and_restore(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            retention = MLDataRetention(
                model_dir=tmpdir,
                archive_dir=str(Path(tmpdir) / "archives"),
            )
            model_data = b"test model data"
            entry = retention.archive_version(
                version=1,
                model_data=model_data,
                n_samples=100,
                streams=["login", "process"],
            )
            assert entry.version == 1
            assert entry.n_samples == 100

            restored = retention.restore_version(1)
            assert restored == model_data

    def test_prune_old_versions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            retention = MLDataRetention(
                model_dir=tmpdir,
                archive_dir=str(Path(tmpdir) / "archives"),
            )
            result = retention.prune_old_versions()
            assert "pruned_models" in result

    def test_storage_metrics(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            retention = MLDataRetention(
                model_dir=tmpdir,
                archive_dir=str(Path(tmpdir) / "archives"),
            )
            metrics = retention.get_storage_metrics()
            assert "active_models" in metrics
            assert "archive_size_mb" in metrics

    def test_dashboard_config(self):
        config = MLDashboardConfig()
        assert config.show_feature_importance is True
        assert config.refresh_interval_seconds == 60

        d = config.to_dict()
        assert d["show_anomaly_scores"] is True

        config2 = MLDashboardConfig.from_dict(d)
        assert config2.show_drift_metrics is True


class TestRemediation:
    """Test automated remediation suggestions."""

    def test_engine_initialization(self):
        engine = RemediationEngine()
        assert len(engine._fn_reports) == 0

    def test_add_fn_report(self):
        engine = RemediationEngine()
        report = FNReport(
            report_id="FN-001",
            event_id=4625,
            timestamp="2026-01-01T00:00:00Z",
            attack_type="brute_force",
            mitre_technique="T1110",
            features_present=["source_ip", "logon_type"],
            features_missing=["geo_distance", "time_pattern"],
            ml_score=0.3,
            threshold=0.5,
            stream="login",
        )
        engine.add_fn_report(report)
        assert len(engine._fn_reports) == 1

    def test_analyze_patterns(self):
        engine = RemediationEngine()
        for i in range(5):
            engine.add_fn_report(FNReport(
                report_id=f"FN-{i:03d}",
                event_id=4625,
                timestamp=f"2026-01-0{i+1}T00:00:00Z",
                attack_type="brute_force",
                mitre_technique="T1110",
                features_missing=["geo_distance"],
                ml_score=0.35,
                threshold=0.5,
                stream="login",
            ))
        patterns = engine.analyze_patterns()
        assert patterns["total_fns"] == 5
        assert "brute_force" in patterns["attack_types"]

    def test_generate_remediations(self):
        engine = RemediationEngine()
        for i in range(5):
            engine.add_fn_report(FNReport(
                report_id=f"FN-{i:03d}",
                event_id=4625,
                timestamp=f"2026-01-0{i+1}T00:00:00Z",
                attack_type="brute_force",
                mitre_technique="T1110",
                features_missing=["geo_distance", "time_pattern"],
                ml_score=0.35,
                threshold=0.5,
                stream="login",
            ))
        actions = engine.generate_remediations()
        assert len(actions) > 0
        assert all(isinstance(a, RemediationAction) for a in actions)

    def test_get_summary(self):
        engine = RemediationEngine()
        engine.add_fn_report(FNReport(
            report_id="FN-001",
            event_id=4625,
            timestamp="2026-01-01T00:00:00Z",
            attack_type="lateral_movement",
            ml_score=0.4,
            threshold=0.5,
        ))
        summary = engine.get_summary()
        assert "fn_summary" in summary
        assert "remediation_actions" in summary


class TestComparison:
    """Test SOC comparison framework."""

    def test_platform_profiles_exist(self):
        assert "baraq" in PLATFORM_PROFILES
        assert "wazuh" in PLATFORM_PROFILES
        assert "datadog_security" in PLATFORM_PROFILES

    def test_baraq_overall_score(self):
        baraq = PLATFORM_PROFILES["baraq"]
        score = baraq.overall_score()
        assert 0 <= score <= 10
        assert score > 7.0  # BARAQ should score well

    def test_comparison(self):
        comp = SOCComparison()
        result = comp.compare(["baraq", "wazuh"])
        assert "platforms" in result
        assert "baraq" in result["platforms"]
        assert "wazuh" in result["platforms"]

    def test_radar_chart_data(self):
        comp = SOCComparison()
        data = comp.get_radar_chart_data(["baraq", "wazuh"])
        assert "labels" in data
        assert "datasets" in data
        assert len(data["datasets"]) == 2

    def test_recommendation(self):
        comp = SOCComparison()
        rec = comp.get_recommendation()
        assert "recommendation" in rec
        assert "key_advantages" in rec

    def test_add_custom_platform(self):
        comp = SOCComparison()
        custom = SOCPlatform(
            name="Custom SOC",
            vendor="Custom",
            category="siem",
            capabilities=[
                PlatformCapability("rule_count", 5.0),
                PlatformCapability("ml_detection", 3.0),
            ],
        )
        comp.add_platform(custom)
        assert "custom_soc" in comp.platforms
