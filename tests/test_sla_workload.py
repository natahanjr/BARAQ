"""P1 item 13 tests: incident SLA + analyst workload.

First response is measured with a ``responded_at`` clock (set when the case
leaves "open" or an owner is assigned, never overwritten), and the workload
endpoint reports per-owner and per-severity SLA posture from the backend.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from backend.api.incidents import SLA_MINUTES
from backend.database.models import AuditLog, Incident
from backend.main import app


def _mk_incident(
    db,
    title="SLA case",
    severity="critical",
    status="open",
    owner="",
    minutes_ago=0,
    org="univ-a",
) -> Incident:
    incident = Incident(
        title=title,
        description="test",
        severity=severity,
        status=status,
        owner=owner,
        host="ws01",
        org=org,
        mitre_id="T1110",
        mitre_name="Credential Access",
        risk_score=80.0,
        risk_level="CRITICAL",
        opened_at=datetime.now(UTC),
    )
    if minutes_ago:
        incident.opened_at = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    incident.created_at = incident.opened_at
    db.add(incident)
    db.flush()
    return incident


def _client():
    return TestClient(app, headers={"X-API-Key": "baraq-dev-admin"})


class TestRespondedAt:
    def test_status_transition_sets_responded_at(self, db):
        inc = _mk_incident(db)
        db.commit()
        assert inc.responded_at is None
        with _client() as client:
            r = client.patch(
                f"/api/incidents/{inc.id}", json={"status": "investigating"}
            )
        assert r.status_code == 200
        assert r.json()["responded_at"] is not None

    def test_responded_at_never_overwritten(self, db):
        inc = _mk_incident(db, status="investigating")
        first = datetime.now(UTC) - timedelta(hours=2)
        inc.responded_at = first
        db.commit()
        with _client() as client:
            client.patch(f"/api/incidents/{inc.id}", json={"status": "contained"})
        db.refresh(inc)
        assert inc.responded_at == first

    def test_owner_assignment_sets_responded_at(self, db):
        inc = _mk_incident(db)
        db.commit()
        with _client() as client:
            r = client.patch(f"/api/incidents/{inc.id}", json={"owner": "analyst-1"})
        assert r.status_code == 200
        assert r.json()["responded_at"] is not None

    def test_plain_open_update_does_not_respond(self, db):
        inc = _mk_incident(db)
        db.commit()
        with _client() as client:
            r = client.patch(f"/api/incidents/{inc.id}", json={"severity": "high"})
        assert r.status_code == 200
        assert r.json()["responded_at"] is None

    def test_migration_adds_responded_at_column(self, db):
        from sqlalchemy import inspect

        cols = {c["name"] for c in inspect(db.get_bind()).get_columns("incidents")}
        assert "responded_at" in cols


class TestWorkloadEndpoint:
    def test_overdue_critical_beyond_sla(self, db):
        _mk_incident(db, severity="critical", minutes_ago=SLA_MINUTES["critical"] + 5)
        db.commit()
        with _client() as client:
            payload = client.get("/api/incidents/workload").json()
        assert payload["active_total"] == 1
        assert payload["sla"]["critical"]["overdue"] == 1
        assert payload["sla"]["critical"]["within"] == 0
        assert payload["aging"]["15-60"] == 1

    def test_within_sla_and_owner_rollup(self, db):
        _mk_incident(db, severity="high", owner="analyst-1", minutes_ago=5)
        _mk_incident(db, severity="high", owner="analyst-1", minutes_ago=10)
        _mk_incident(db, severity="low", minutes_ago=2)
        db.commit()
        with _client() as client:
            payload = client.get("/api/incidents/workload").json()
        assert payload["active_total"] == 3
        owner = next(o for o in payload["owners"] if o["owner"] == "analyst-1")
        assert owner["open"] == 2
        assert owner["overdue"] == 0
        assert payload["unassigned"] == 1
        assert payload["sla"]["high"]["within"] == 2
        assert payload["aging"]["0-15"] == 3

    def test_response_time_stats(self, db):
        inc = _mk_incident(db, status="investigating", minutes_ago=30)
        inc.responded_at = inc.opened_at + timedelta(minutes=12)
        inc2 = _mk_incident(db, title="second", status="investigating", minutes_ago=60)
        inc2.responded_at = inc2.opened_at + timedelta(minutes=48)
        db.commit()
        with _client() as client:
            payload = client.get("/api/incidents/workload").json()
        stats = payload["response"]
        assert stats["count"] == 2
        assert stats["median_minutes"] == 48  # [12, 48] -> upper median
        assert stats["avg_minutes"] == 30.0

    def test_resolved_cases_excluded_from_active(self, db):
        _mk_incident(db, status="closed", severity="critical", minutes_ago=500)
        db.commit()
        with _client() as client:
            payload = client.get("/api/incidents/workload").json()
        assert payload["active_total"] == 0
        assert payload["sla"]["critical"]["open"] == 0

    def test_sla_change_is_audited(self, db):
        inc = _mk_incident(db, status="open")
        db.commit()
        with _client() as client:
            client.patch(f"/api/incidents/{inc.id}", json={"status": "contained"})
        entries = (
            db.query(AuditLog)
            .filter(
                AuditLog.action == "incident.update",
                AuditLog.detail.contains("responded_at"),
            )
            .all()
        )
        assert len(entries) >= 1
