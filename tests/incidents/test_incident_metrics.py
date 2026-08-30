"""Phase 7 incident metrics tests (spec 7.36, 7.37, 7.49)."""

from __future__ import annotations

from datetime import UTC, datetime

from backend.incidents import engine
from backend.incidents.metrics import incident_metrics

EVAL_T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=UTC)


def _group(group_id, hosts, techniques, severity="high", alert_count=10):
    return {
        "kind": "BEHAVIOR_GROUP",
        "group_id": group_id,
        "hosts": hosts,
        "users": [],
        "source_ips": [],
        "destination_ips": [],
        "techniques": techniques,
        "tactics": [],
        "severity": severity,
        "alert_count": alert_count,
        "first_seen": EVAL_T0,
        "last_seen": EVAL_T0,
        "external_source": False,
    }


def _finding(finding_id, hosts):
    return {
        "kind": "CORRELATION_FINDING",
        "correlation_id": finding_id,
        "correlation_type": "MULTI_STAGE",
        "hosts": hosts,
        "users": [],
        "source_ips": [],
        "member_group_ids": [],
        "confidence": 0.9,
        "first_seen": EVAL_T0,
        "last_seen": EVAL_T0,
    }


def test_metrics_totals(db):
    engine.create_incident(
        db,
        groups=[
            _group("g-metrics-001", ["h-metrics-001"], ["T1021.001"]),
            _group("g-metrics-001b", ["h-metrics-001"], ["T1059.001"]),
        ],
        findings=[_finding("CF-metrics-001", ["h-metrics-001"])],
        now=EVAL_T0,
    )
    db.commit()
    metrics = incident_metrics(db, now=EVAL_T0)
    assert metrics["total_incidents"] >= 1
    assert metrics["active_incidents"] >= 1
    assert metrics["sample_size"] >= 1
    assert metrics["creation_latency"]["p50_ms"] >= 0


def test_metrics_no_fake_accuracy(db):
    engine.create_incident(
        db,
        groups=[
            _group("g-metrics-002", ["h-metrics-002"], ["T1021.001"]),
            _group("g-metrics-002b", ["h-metrics-002"], ["T1059.001"]),
        ],
        findings=[_finding("CF-metrics-002", ["h-metrics-002"])],
        now=EVAL_T0,
    )
    db.commit()
    metrics = incident_metrics(db, now=EVAL_T0)
    assert "accuracy" not in metrics
    assert "precision" not in metrics
    assert "recall" not in metrics
