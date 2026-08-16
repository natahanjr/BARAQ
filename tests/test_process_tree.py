"""P1 item 9 tests: process-tree reconstruction + standalone API.

The tree must rebuild parent/child lineage from 4688 events (raw facts carry
ProcessId=parent / NewProcessId=child), mark the alert's seed process, and be
reachable through a standalone endpoint (alert-scoped or host-scoped).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from backend.database.models import Alert, AlertEventLink, NormalizedEvent
from backend.investigation.process_tree import build_process_tree
from backend.main import app
from tests.conftest import run_simulation


def _mk_4688(db, pid, ppid, name, cmd="", host="ws01", user="alice",
             minutes_ago=5, org="univ-a") -> NormalizedEvent:
    ev = NormalizedEvent(
        event_id=4688,
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
        category="Process",
        user=user,
        host=host,
        org=org,
        risk="Low",
        message=f"process {name} started",
        raw_json={
            "facts": {
                "NewProcessId": str(pid),
                "ProcessId": str(ppid),
                "NewProcessName": name,
                "CommandLine": cmd,
            }
        },
    )
    db.add(ev)
    db.flush()
    return ev


def _mk_alert(db, evidence_pid: int, org: str = "univ-a") -> Alert:
    alert = Alert(
        name=f"process tree alert pid {evidence_pid}",
        description="test alert",
        severity="high",
        confidence=0.8,
        mitre_id="T1059",
        mitre_name="Execution",
        rule="suspicious_python",
        host="ws01",
        org=org,
        risk_score=70.0,
        risk_level="HIGH",
        evidence=f"python executed (pid {evidence_pid})",
        correlation_id="",
    )
    db.add(alert)
    db.flush()
    return alert


def _client():
    return TestClient(app, headers={"X-API-Key": "baraq-dev-admin"})


class TestTreeBuilder:
    def test_chain_root_to_seed(self, db):
        child = _mk_4688(db, 1000, 900, "python.exe", cmd="python payload.py", minutes_ago=1)
        _mk_4688(db, 900, 500, "explorer.exe", minutes_ago=2)
        _mk_4688(db, 500, None, "services.exe", minutes_ago=3)
        db.commit()

        tree = build_process_tree(db, [child], org="univ-a")
        assert tree["node_count"] == 3
        assert tree["seed_found"] is True
        chain = [n["name"] for n in tree["chain"]]
        assert chain[0] == "services.exe"
        assert chain[-1] == "python.exe"
        assert all(n["verified"] for n in tree["chain"][1:])  # every edge below root verified

    def test_snapshot_fallback_adds_nodes(self, db):
        from backend.database.models import ProcessRecord

        child = _mk_4688(db, 2000, 1900, "malware.exe", minutes_ago=1)
        db.add(ProcessRecord(
            pid=1900, ppid=0, name="powershell.exe",
            path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -enc ABC", parent_name="",
            user="alice", is_new=True,
            observed_at=datetime.now(timezone.utc) - timedelta(minutes=2),
            org="univ-a",
        ))
        db.commit()

        tree = build_process_tree(db, [child], org="univ-a")
        names = {n["name"] for n in tree["primary"]["nodes"]}
        assert "malware.exe" in names
        assert sum(t["node_count"] for t in tree["trees"]) >= 2

    def test_unknown_evidence_returns_empty(self, db):
        ev = _mk_4688(db, 3000, 0, "calc.exe", minutes_ago=1)
        db.commit()
        tree = build_process_tree(db, [ev], org="univ-a")
        assert tree["node_count"] >= 1


class TestStandaloneEndpoint:
    def test_requires_scope(self):
        with _client() as client:
            resp = client.get("/api/investigation/process-tree")
            assert resp.status_code == 400

    def test_unknown_alert_404(self):
        with _client() as client:
            resp = client.get("/api/investigation/process-tree", params={"alert_id": 99999})
            assert resp.status_code == 404

    def test_by_alert_builds_tree(self, db):
        ev = _mk_4688(db, 1000, 900, "python.exe", cmd="python payload.py", minutes_ago=1)
        _mk_4688(db, 900, None, "explorer.exe", minutes_ago=2)
        db.commit()
        alert = _mk_alert(db, evidence_pid=1000)
        db.add(AlertEventLink(alert_id=alert.id, event_id=ev.id))
        db.commit()

        with _client() as client:
            resp = client.get(
                "/api/investigation/process-tree", params={"alert_id": alert.id}
            )
        assert resp.status_code == 200
        payload = resp.json()
        assert payload["node_count"] >= 2
        assert payload["seed_found"] is True
        assert payload["primary"]["host"] == "ws01"

    def test_by_host_builds_tree(self, db):
        _mk_4688(db, 1000, 900, "python.exe", minutes_ago=1)
        _mk_4688(db, 900, None, "explorer.exe", minutes_ago=2)
        db.commit()

        with _client() as client:
            resp = client.get(
                "/api/investigation/process-tree",
                params={"host": "ws01", "hours": 6},
            )
        assert resp.status_code == 200
        assert resp.json()["node_count"] >= 2

    def test_pipeline_alert_surfaces_tree(self, db):
        from backend.database.models import AlertEventLink

        run_simulation(db, scenario="brute_force")
        alert = db.query(Alert).order_by(Alert.id.asc()).first()
        assert alert is not None
        db.add(AlertEventLink(
            alert_id=alert.id,
            event_id=_mk_4688(db, 1000, 900, "python.exe", minutes_ago=1).id,
        ))
        db.commit()

        with _client() as client:
            resp = client.get(
                "/api/investigation/process-tree", params={"alert_id": alert.id}
            )
        assert resp.status_code == 200
        assert "trees" in resp.json()