"""Test end-to-end pipeline, alerting, MITRE enrichment, reports and AI."""

from __future__ import annotations

from backend.ai.assistant import SecurityAssistant
from backend.mitre.attack import get_recommendation, get_tactic, get_technique_name
from tests.conftest import run_simulation


def test_full_suite_end_to_end(db):
    result = run_simulation(db)
    assert (
        result["alerts_created"] >= 5
    )  # brute force, PS, priv-esc, persistence, recon
    assert result["saved_events"] > 0
    assert result["saved_connections"] > 0


def test_all_scenarios_detected(db):
    """Each fixture scenario must produce its corresponding alert."""
    from backend.api.system import run_pipeline
    from backend.database.models import Alert
    from tests.conftest import _scenario

    scenarios = {
        "brute_force": "Brute Force Attack",
        "powershell": "Suspicious PowerShell Activity",
        "privilege_escalation": "Suspicious Privilege Escalation",
        "persistence": "Persistence Mechanism Installed",
        "port_scan": "Network Service Discovery (Port Scan)",
    }
    for scenario in scenarios:
        run_pipeline(db, _scenario(scenario))

    alerts = db.query(Alert).all()
    names = {a.name for a in alerts}
    for alert_name in scenarios.values():
        assert alert_name in names, f"Missing alert: {alert_name}"

    assert all(a.mitre_id for a in alerts)
    assert all(a.mitre_tactic for a in alerts)
    assert all(a.recommendation for a in alerts)


def test_mitre_helpers():
    assert get_tactic("T1110") == "Credential Access"
    assert "Brute Force" in get_technique_name("T1110")
    assert get_recommendation("T1059.001") != ""
    assert get_tactic("T1021") == "Lateral Movement"
    assert get_tactic("T1074") == "Collection"


def test_alert_evidence_links(db):
    from backend.database.models import Alert

    run_simulation(db, "brute_force")
    alert = db.query(Alert).filter(Alert.rule == "brute_force").first()
    assert alert is not None
    assert len(alert.events) == 12


def test_reports_generate_all_formats(db):
    from backend.reports.generator import generate_report

    run_simulation(db)
    for fmt in ("pdf", "html", "json", "csv"):
        report = generate_report(db, "executive", fmt)
        assert report["file_path"].endswith(f".{fmt}")
    technical = generate_report(db, "technical", "json")
    assert technical["report_type"] == "technical"


def test_ai_assistant_explains_alert(db):
    run_simulation(db, "brute_force")
    assistant = SecurityAssistant(db)
    reply = assistant.chat("explain alert 1")
    assert "Brute Force" in reply or "authentication" in reply.lower()


def test_ai_assistant_summarizes(db):
    assistant = SecurityAssistant(db)
    reply = assistant.chat("summarize the current incidents")
    assert "alert" in reply.lower()


def test_dashboard_analytics(db):
    from backend.analyzers import dashboard

    run_simulation(db)
    summary = dashboard.dashboard_summary(db)
    assert summary["active_alerts"] >= 5
    assert 0 <= summary["security_score"] <= 100
    assert summary["system_status"] in ("CRITICAL", "ATTENTION", "HEALTHY")
    assert dashboard.threat_categories(db)
    assert dashboard.severity_distribution(db)
    assert dashboard.attack_stats(db)


def test_ml_trains_and_scores(db):
    from backend.ml.anomaly import MLAnomalyDetector

    run_simulation(db)
    detector = MLAnomalyDetector()
    result = detector.train(db)
    assert result["trained"] is True or result["status"] == "sklearn-not-installed"
    if detector.is_ready:
        score = detector.score_event([4625, 3, 3])
        assert 0.0 <= score <= 1.0
        analysis = detector.analyze_events(db, hours=24)
        assert analysis["status"] == "ok"
