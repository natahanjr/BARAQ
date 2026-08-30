"""Data-quality validation + auto-repair (corrupted event data)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from backend.collectors import quality as quality_mod
from backend.collectors import repair as repair_mod
from backend.collectors import validation
from backend.database.models import DataQualitySnapshot, NormalizedEvent


# ---------------------------------------------------------------------------
# Validation rules (R1-R7)
# ---------------------------------------------------------------------------
def test_debris_process_name_flagged():
    assert validation.is_corrupted_facts({"new_process": "C"})[0] is True
    assert validation.is_corrupted_facts({"new_process": "C"})[1].startswith(
        "new_process"
    )
    assert validation.is_corrupted_facts({"NewProcessName": "\\"})[0] is True
    assert validation.is_corrupted_facts({"image_path": "g"})[0] is True
    assert validation.is_corrupted_facts({"creator_process": "F"})[0] is True


def test_short_stub_flagged_but_full_paths_valid():
    assert validation.is_corrupted_facts({"new_process": "ab"})[0] is True
    assert (
        validation.is_corrupted_facts(
            {"new_process": "C:\\Windows\\System32\\cmd.exe"}
        )[0]
        is False
    )
    assert (
        validation.is_corrupted_facts(
            {"image_path": "C:\\Program Files\\App\\tool.exe"}
        )[0]
        is False
    )


def test_short_command_line_flagged_but_real_cmdline_valid():
    assert validation.is_corrupted_facts({"command_line": "-"})[0] is True
    assert validation.is_corrupted_facts({"command_line": "--"})[0] is True
    assert (
        validation.is_corrupted_facts(
            {"command_line": "C:\\Windows\\System32\\cmd.exe /c whoami"}
        )[0]
        is False
    )
    assert validation.is_corrupted_facts({"script_block": "Write-Output x"})[0] is False


def test_missing_values_not_corruption():
    assert validation.is_corrupted_facts({})[0] is False
    assert validation.is_corrupted_facts({"new_process": ""})[0] is False
    assert validation.is_corrupted_facts({"command_line": None})[0] is False


def test_normalized_user_empty_is_corrupted_but_dash_ok():
    assert (
        validation.normalized_is_corrupted({"user": "", "raw_json": {"facts": {}}})[0]
        is True
    )
    assert (
        validation.normalized_is_corrupted({"user": "-", "raw_json": {"facts": {}}})[0]
        is False
    )
    assert (
        validation.normalized_is_corrupted(
            {"user": "HAARAPHEL\\Haaraphel", "raw_json": {"facts": {}}}
        )[0]
        is False
    )


def test_structured_record_validation():
    good = {
        "source": "process",
        "name": "cmd.exe",
        "path": "C:\\Windows\\System32\\cmd.exe",
    }
    assert validation.structured_record_is_corrupted(good)[0] is False
    bad = {"source": "process", "name": "C", "path": "C:\\Windows\\System32\\cmd.exe"}
    assert validation.structured_record_is_corrupted(bad)[0] is True
    bad_cmdline = {"source": "process", "name": "cmd.exe", "raw": {"cmdline": "x"}}
    assert validation.structured_record_is_corrupted(bad_cmdline)[0] is True


def test_raw_record_structural_validation():
    assert validation.validate_raw_record("nope")[0] is False
    assert validation.validate_raw_record({"event_id": "abc"})[0] is False
    assert (
        validation.validate_raw_record({"source": "eventlog", "event_id": 4688})[0]
        is True
    )
    assert validation.validate_raw_record({"source": "process"})[0] is True


# ---------------------------------------------------------------------------
# Quality tracker
# ---------------------------------------------------------------------------
def test_window_rate_and_status():
    quality_mod.quality.reset()
    for _ in range(8):
        quality_mod.quality.record("Security", True)
    for _ in range(2):
        quality_mod.quality.record("Security", False, "new_process is rendering debris")
    summary = quality_mod.quality.summary()
    assert summary["total"] == 10
    assert summary["valid"] == 8
    assert summary["corrupted"] == 2
    assert summary["corruption_rate"] == 0.2
    assert summary["status"] == "warning"
    assert summary["reasons"]["new_process is rendering debris"] == 2
    assert summary["channels"]["Security"]["corrupted"] == 2


def test_status_boundaries():
    assert quality_mod.status_for_rate(0.05) == "healthy"
    assert quality_mod.status_for_rate(0.10) == "warning"
    assert quality_mod.status_for_rate(0.30) == "degraded"
    assert quality_mod.status_for_rate(0.55) == "critical"


def test_snapshot_persistence(db):
    quality_mod.quality.reset()
    quality_mod.quality.record("Security", True)
    quality_mod.quality.record("System", False, "debris")
    snapshot = quality_mod.persist_snapshot(db)
    assert snapshot["corrupted"] == 1
    assert snapshot["status"] in ("healthy", "warning", "degraded", "critical")
    row = db.query(DataQualitySnapshot).first()
    assert row is not None
    history = quality_mod.snapshot_history(db)
    assert len(history) == 1
    assert history[0]["total"] == 2


# ---------------------------------------------------------------------------
# Pipeline: corrupted events are discarded before detection
# ---------------------------------------------------------------------------
def test_pipeline_discards_corrupted_event(db):
    from backend.api.system import run_pipeline

    corrupted = {
        "source": "eventlog",
        "channel": "Security",
        "event_id": 4688,
        "timestamp": "2026-08-14T12:00:00Z",
        "user": "HAARAPHEL\\Haaraphel",
        # Message-only record: SafeFormatMessage truncated the image to "C".
        "message": "New Process Name:\tC",
        "raw": {"provider": "Microsoft-Windows-Security-Auditing", "record_number": 1},
    }
    result = run_pipeline(db, [corrupted], org="")
    assert result["corrupted_events"] == 1
    assert result["saved_events"] == 0
    assert db.query(NormalizedEvent).count() == 0


def test_pipeline_keeps_valid_event(db):
    from backend.api.system import run_pipeline

    valid = {
        "source": "eventlog",
        "channel": "Security",
        "event_id": 4688,
        "timestamp": "2026-08-14T12:00:00Z",
        "user": "HAARAPHEL\\Haaraphel",
        "message": "New Process Name:\tC:\\Windows\\System32\\cmd.exe",
        "raw": {
            "provider": "Microsoft-Windows-Security-Auditing",
            "record_number": 2,
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
        },
    }
    result = run_pipeline(db, [valid], org="")
    assert result["corrupted_events"] == 0
    assert result["saved_events"] == 1
    assert db.query(NormalizedEvent).count() == 1


def test_pipeline_discards_corrupted_structured_process(db):
    from backend.api.system import run_pipeline

    bad = {
        "source": "process",
        "pid": 1,
        "name": "C",
        "path": "C:\\Windows\\System32\\cmd.exe",
        "user": "HAARAPHEL\\Haaraphel",
        "is_new": True,
        "timestamp": "2026-08-14T12:00:00Z",
    }
    result = run_pipeline(db, [bad], org="")
    assert result["corrupted_events"] == 1
    assert result["saved_processes"] == 0


# ---------------------------------------------------------------------------
# Repair sequence
# ---------------------------------------------------------------------------
def _reset_repair():
    repair_mod._last_repair_ts = 0.0


def test_clear_log_skipped_off_windows(monkeypatch):
    monkeypatch.setattr(repair_mod, "is_windows", lambda: False)
    result = repair_mod.clear_log("Security")
    assert result["status"] == "skipped"


def test_run_repair_full_sequence(db, monkeypatch):
    _reset_repair()
    monkeypatch.setattr(repair_mod, "is_windows", lambda: False)
    monkeypatch.setattr(
        repair_mod,
        "_retrain_model",
        lambda: {"step": "retrain ML", "status": "ok", "detail": "stub"},
    )
    result = repair_mod.run_repair(db, "test")
    assert result["triggered"] is True
    steps = {s["step"]: s for s in result["steps"]}
    assert steps["clear Security"]["status"] == "skipped"
    assert steps["clear System"]["status"] == "skipped"
    assert steps["restart EventLog service"]["status"] == "skipped"
    assert steps["retrain ML"]["status"] == "ok"


def test_repair_cooldown_blocks_second_run(db, monkeypatch):
    _reset_repair()
    monkeypatch.setattr(repair_mod, "is_windows", lambda: False)
    monkeypatch.setattr(
        repair_mod,
        "_retrain_model",
        lambda: {"step": "retrain ML", "status": "ok", "detail": "stub"},
    )
    repair_mod.run_repair(db, "first")
    second = repair_mod.run_repair(db, "second")
    assert second["triggered"] is False
    assert "cooldown" in second["detail"]


def test_repair_windows_failure_does_not_abort(db, monkeypatch):
    _reset_repair()
    monkeypatch.setattr(repair_mod, "is_windows", lambda: True)
    monkeypatch.setattr(
        repair_mod, "_run", lambda cmd, timeout=60: (5, "access denied")
    )
    monkeypatch.setattr(
        repair_mod,
        "_retrain_model",
        lambda: {"step": "retrain ML", "status": "ok", "detail": "stub"},
    )
    result = repair_mod.run_repair(db, "perm test")
    assert result["triggered"] is True
    assert result["success"] is False
    assert all(s["status"] in ("failed", "ok") for s in result["steps"])
    assert any(s["status"] == "failed" for s in result["steps"])


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------
def test_data_quality_api(db, monkeypatch):
    from fastapi.testclient import TestClient

    from backend.main import app

    monkeypatch.setattr(
        "backend.collectors.repair.run_repair",
        lambda db, reason="manual", clear_logs=True, restart_service=True, retrain=True: {
            "triggered": True,
            "reason": reason,
            "success": True,
            "steps": [],
            "started_at": "now",
        },
    )
    quality_mod.quality.reset()
    quality_mod.quality.record("Security", False, "debris")
    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.get("/api/system/data-quality")
        assert r.status_code == 200
        body = r.json()
        assert body["current"]["corrupted"] == 1
        assert "history" in body

        r = client.get("/api/system/data-quality/history?limit=5")
        assert r.status_code == 200
        assert "items" in r.json()

        r = client.post(
            "/api/system/data-quality/repair", json={"reason": "manual test"}
        )
        assert r.status_code == 200
        assert r.json()["triggered"] is True

    with TestClient(app, headers={"X-API-Key": "baraq-dev-analyst"}) as client:
        r = client.post("/api/system/data-quality/repair", json={"reason": "nope"})
        assert r.status_code == 403


def test_health_includes_data_quality():
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.get("/api/health")
        assert r.status_code == 200
        dq = r.json()["data_quality"]
        assert dq["status"] in ("healthy", "warning", "degraded", "critical")
        assert 0.0 <= dq["corruption_rate"] <= 1.0


# ---------------------------------------------------------------------------
# ML integration: corrupted history is never trained on
# ---------------------------------------------------------------------------
def test_ml_loader_skips_corrupted_events(db):
    from backend.ml.anomaly import _load_behavior_features

    db.add(
        NormalizedEvent(
            event_id=4688,
            category="Process",
            risk="Medium",
            risk_score=40,
            severity="medium",
            source="eventlog",
            user="Haaraphel",
            host="host1",
            message="x",
            timestamp=datetime.now(UTC),
            data_integrity="complete",
            raw_json={"facts": {"new_process": "C"}},
        )
    )
    db.commit()
    X = _load_behavior_features(db, datetime.now(UTC) - timedelta(hours=24), {4688})
    assert X.shape[0] == 0


def test_orm_event_is_corrupted_from_stored_row(db):
    from types import SimpleNamespace

    assert (
        validation.orm_event_is_corrupted(
            SimpleNamespace(
                raw_json={"facts": {"new_process": "C"}},
                user="x",
                data_integrity="complete",
            )
        )[0]
        is True
    )
    assert (
        validation.orm_event_is_corrupted(
            SimpleNamespace(
                raw_json={"facts": {"new_process": "C:\\Windows\\System32\\cmd.exe"}},
                user="x",
                data_integrity="complete",
            )
        )[0]
        is False
    )
    assert (
        validation.orm_event_is_corrupted(
            SimpleNamespace(raw_json={}, user="x", data_integrity="corrupted")
        )[0]
        is True
    )
