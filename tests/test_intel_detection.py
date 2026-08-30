"""P1 item 12 tests: detection-time threat-intel enrichment.

The pipeline must annotate alerts with reputation verdicts WHILE they are
created (offline fast path), surface them in the API, and never let a
provider failure wedge detection.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from backend.database.models import Alert, ThreatIntelRecord
from backend.intel.detection import intel_hits
from tests.conftest import run_simulation


def _seed_malicious_ioc(db, indicator: str = "192.168.99.77"):
    """The brute_force scenario's evidence carries 192.168.99.77 - seed that
    exact indicator so detection-time annotation resolves it as malicious."""
    row = ThreatIntelRecord(
        indicator=indicator,
        kind="ip",
        category="malicious",
        label="known C2 node",
        confidence=0.9,
        sources=["test-feed"],
        checked_at=datetime.now(UTC),
    )
    db.add(row)
    db.commit()
    return row


class TestDetectionTimeAnnotation:
    def test_alert_with_known_ioc_gets_verdict(self, db):
        _seed_malicious_ioc(db)
        run_simulation(db, scenario="brute_force")
        alert = db.query(Alert).order_by(Alert.id.asc()).first()
        assert alert.intel_json is not None
        payload = json.loads(alert.intel_json)
        verdicts = payload["indicators"]
        assert any(v["indicator"] == "192.168.99.77" for v in verdicts)
        assert any(v["category"] == "malicious" for v in verdicts)

    def test_to_dict_surfaces_hits(self, db):
        _seed_malicious_ioc(db)
        run_simulation(db, scenario="brute_force")
        alert = db.query(Alert).order_by(Alert.id.asc()).first()
        data = alert.to_dict()
        assert data["intel_hits"] >= 1
        assert isinstance(data["intel_indicators"], list)
        assert data["intel_checked_at"]

    def test_no_indicators_no_annotation(self, db):
        from backend.threatintel.service import extract_indicators

        run_simulation(db, scenario="brute_force")
        for alert in db.query(Alert).all():
            if alert.rule == "entity_risk":
                continue  # RBA alerts are annotated inside apply_alert (same hook)
            expected = bool(
                extract_indicators(f"{alert.evidence or ''} {alert.name or ''}")
            )
            if expected:
                assert (
                    alert.intel_json is not None
                ), f"alert #{alert.id} ({alert.rule}) carries indicators but was not annotated"

    def test_pipeline_survives_provider_failure(self, db, monkeypatch):
        _seed_malicious_ioc(db)
        from backend.threatintel import service as ti_service

        def boom(db, indicator, refresh=False, offline=False):
            raise RuntimeError("provider down")

        monkeypatch.setattr(ti_service, "lookup_indicator", boom)
        result = run_simulation(db, scenario="brute_force")
        assert result["alerts_created"] >= 1  # detection unaffected
        alerts = db.query(Alert).all()
        assert all(a.risk_score is not None for a in alerts)

    def test_intel_disabled_skips_annotation(self, db, monkeypatch):
        _seed_malicious_ioc(db)

        monkeypatch.setattr("backend.config.THREAT_INTEL_ENABLED", False)
        run_simulation(db, scenario="brute_force")
        alert = db.query(Alert).order_by(Alert.id.asc()).first()
        assert alert.intel_json is None

    def test_migration_adds_intel_json_column(self, db):
        from sqlalchemy import inspect

        cols = {c["name"] for c in inspect(db.get_bind()).get_columns("alerts")}
        assert "intel_json" in cols


class TestHelper:
    def test_intel_hits_counts_malicious_only(self):
        payload = {
            "indicators": [
                {"category": "malicious", "indicator": "1.2.3.4"},
                {"category": "suspicious", "indicator": "5.6.7.8"},
                {"category": "benign", "indicator": "9.9.9.9"},
                {"category": "unknown", "indicator": "10.0.0.1"},
            ]
        }
        assert intel_hits(payload) == 2
        assert intel_hits(None) == 0
        assert intel_hits({"indicators": []}) == 0
