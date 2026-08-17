"""P1 item 14 tests: false-positive lifecycle.

Verdicts feed the feedback loop, expected-behaviour verdicts can create
scoped suppression rules, the fp-analysis endpoint ranks tuning candidates,
and feedback-stats turns analyst verdicts into per-rule precision metrics.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from backend.database.models import AuditLog, SuppressionRule
from backend.main import app


def _client():
    return TestClient(app, headers={"X-API-Key": "baraq-dev-admin"})


def _create_alert(db, rule="Detection Rule A", host="ws01"):
    from backend.database.models import Alert

    alert = Alert(
        name=f"{rule} - {host}",
        description="test",
        severity="medium",
        status="open",
        rule=rule,
        host=host,
        org="univ-a",
        mitre_id="T1110",
        mitre_name="Credential Access",
        risk_score=50.0,
        risk_level="MEDIUM",
    )
    db.add(alert)
    db.flush()
    return alert


class TestFeedbackStats:
    def test_empty_state(self, db):
        with _client() as client:
            payload = client.get("/api/alerts/feedback-stats").json()
        assert payload["total_feedback"] == 0
        assert payload["rules"] == []
        assert payload["suppressed_rules"] == []

    def test_per_rule_precision(self, db):
        for _ in range(3):
            alert = _create_alert(db, rule="R1")
            db.add(alert)
        db.commit()
        with _client() as client:
            for a in db.query(type(alert)).filter(type(alert).rule == "R1").all()[:2]:
                client.post(
                    f"/api/alerts/{a.id}/verdict",
                    json={"verdict": "true_positive", "note": "real"},
                )
            client.post(
                f"/api/alerts/{alert.id}/verdict",
                json={"verdict": "false_positive", "note": "noise"},
            )
        with _client() as client:
            payload = client.get("/api/alerts/feedback-stats").json()
        r1 = next(r for r in payload["rules"] if r["rule"] == "R1")
        assert r1["true_positive"] == 2
        assert r1["false_positive"] == 1
        assert r1["total"] == 3
        assert r1["precision"] == round(2 / 3, 3)
        assert payload["total_feedback"] == 3
        assert len(payload["recent"]) == 3

    def test_suppression_verdict_creates_rule_and_lists_it(self, db):
        alert = _create_alert(db)
        db.commit()
        with _client() as client:
            r = client.post(
                f"/api/alerts/{alert.id}/verdict",
                json={"verdict": "expected_behavior", "suppress": True},
            )
        assert r.status_code == 200
        assert r.json()["verdict"] == "expected_behavior"
        rule = db.query(SuppressionRule).filter(
            SuppressionRule.rule == "Detection Rule A"
        ).first()
        assert rule is not None
        assert rule.host == "ws01"
        with _client() as client:
            stats = client.get("/api/alerts/feedback-stats").json()
            assert "Detection Rule A" in stats["suppressed_rules"]

    def test_verdict_is_audited(self, db):
        alert = _create_alert(db)
        db.commit()
        with _client() as client:
            client.post(
                f"/api/alerts/{alert.id}/verdict",
                json={"verdict": "false_positive", "note": "test note"},
            )
        entries = db.query(AuditLog).filter(
            AuditLog.action == "alert.verdict"
        ).all()
        assert any("false_positive" in (e.detail or "") for e in entries)


class TestFpAnalysis:
    def test_ranks_tuning_candidates(self, db):
        for _ in range(4):
            alert = _create_alert(db, rule="Noisy Rule", host="ws01")
            alert.status = "closed"
            db.add(alert)
        db.commit()
        with _client() as client:
            payload = client.get("/api/alerts/fp-analysis").json()
        assert isinstance(payload.get("items"), list)
        assert len(payload["items"]) >= 1
        top = max(payload["items"], key=lambda i: i["fp_candidate_score"])
        assert top["rule"] == "Noisy Rule"
        assert top["total"] == 4

    def test_requires_auth(self):
        import fastapi.testclient as tc

        with tc.TestClient(app) as client:
            r = client.get("/api/alerts/feedback-stats")
        assert r.status_code in (401, 403)