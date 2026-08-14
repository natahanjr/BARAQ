"""Scheduled reports (roadmap 6.2): due logic, email delivery, API."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.database.models import ReportRecord, ReportSchedule


def _mk(db, **kwargs) -> ReportSchedule:
    row = ReportSchedule(**{"name": "test", "report_type": "executive",
                            "fmt": "html", "every_hours": 24,
                            "hour_of_day": -1, "enabled": True, **kwargs})
    db.add(row)
    db.commit()
    return row


def test_schedule_is_due_when_never_run(db):
    from backend.reports.schedule import _is_due

    now = datetime.now(timezone.utc)
    s = _mk(db, every_hours=24, last_run_at=None)
    assert _is_due(s, now) is True


def test_schedule_not_due_within_window(db):
    from backend.reports.schedule import _is_due

    now = datetime.now(timezone.utc)
    s = _mk(db, every_hours=24, last_run_at=now - timedelta(hours=2))
    assert _is_due(s, now) is False


def test_schedule_due_after_window(db):
    from backend.reports.schedule import _is_due

    now = datetime.now(timezone.utc)
    s = _mk(db, every_hours=24, last_run_at=now - timedelta(hours=25))
    assert _is_due(s, now) is True


def test_disabled_schedule_never_due(db):
    from backend.reports.schedule import _is_due

    now = datetime.now(timezone.utc)
    s = _mk(db, every_hours=1, enabled=False, last_run_at=None)
    assert _is_due(s, now) is False


def test_hour_of_day_due_only_at_hour(db):
    from backend.reports.schedule import _is_due

    now = datetime.now(timezone.utc)
    s = _mk(db, hour_of_day=now.hour, last_run_at=None)
    assert _is_due(s, now) is True
    s2 = _mk(db, hour_of_day=(now.hour + 1) % 24, last_run_at=None)
    assert _is_due(s2, now) is False


def test_run_schedule_generates_and_records(db):
    from backend.reports.schedule import run_schedule

    s = _mk(db, name="nightly", fmt="html", email_to="")
    result = run_schedule(db, s, email=False)
    assert result["report_type"] == "executive"
    assert result["format"] == "html"
    assert db.query(ReportRecord).count() == 1
    assert s.runs_total == 1
    assert s.last_run_at is not None


def test_run_due_schedules_runs_only_due(db):
    from backend.reports.schedule import run_due_schedules

    _mk(db, name="due", fmt="html", every_hours=24, last_run_at=None)
    _mk(db, name="recent", fmt="html", every_hours=24,
        last_run_at=datetime.now(timezone.utc) - timedelta(hours=1))
    summary = run_due_schedules(db)
    assert summary["due"] == 1
    assert summary["results"][0]["name"] == "due"
    assert summary["results"][0]["status"] == "ok"


def test_email_report_smpt_monkeypatched(db, monkeypatch):
    import smtplib

    import backend.reports.schedule as sched_mod

    sent = {}

    class FakeSMTP:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self):
            pass

        def starttls(self, **k):
            pass

        def login(self, u, p):
            sent["login"] = (u, p)

        def send_message(self, msg):
            sent["msg"] = msg

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(sched_mod, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(sched_mod, "SMTP_PORT", 587)
    monkeypatch.setattr(sched_mod, "SMTP_USERNAME", "u")
    monkeypatch.setattr(sched_mod, "SMTP_PASSWORD", "p")
    monkeypatch.setattr(sched_mod, "SMTP_FROM", "baraq@test")
    monkeypatch.setattr(sched_mod, "SMTP_STARTTLS", True)

    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "report.html"
        path.write_text("<h1>report</h1>", encoding="utf-8")
        ok = sched_mod.email_report(str(path), "analyst@test", "BARAQ report")
        assert ok is True
        assert sent["login"] == ("u", "p")
        assert "analyst@test" in str(sent["msg"])


def test_email_report_skipped_without_smtp(monkeypatch):
    import backend.reports.schedule as sched_mod

    monkeypatch.setattr(sched_mod, "SMTP_HOST", "")
    assert sched_mod.email_report("none.html", "x@y.z", "s") is False


def test_schedule_api_crud_and_run():
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.get("/api/reports/schedules")
        assert r.status_code == 200
        assert "items" in r.json()

        r = client.post("/api/reports/schedules", json={
            "name": "daily-exec", "report_type": "executive",
            "format": "html", "every_hours": 24, "email_to": "",
        })
        assert r.status_code == 200, r.text
        sid = r.json()["id"]
        assert r.json()["enabled"] is True

        r = client.patch(f"/api/reports/schedules/{sid}", json={
            "name": "daily-exec", "report_type": "technical",
            "format": "html", "every_hours": 12, "hour_of_day": -1, "email_to": "",
            "enabled": True,
        })
        assert r.status_code == 200
        assert r.json()["report_type"] == "technical"

        r = client.post(f"/api/reports/schedules/{sid}/run")
        assert r.status_code == 200, r.text
        assert r.json()["format"] == "html"

        r = client.delete(f"/api/reports/schedules/{sid}")
        assert r.status_code == 200
        r = client.get(f"/api/reports/schedules")
        assert all(s["id"] != sid for s in r.json()["items"])


def test_schedule_crud_requires_admin():
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-analyst"}) as client:
        r = client.post("/api/reports/schedules", json={
            "name": "x", "every_hours": 24,
        })
        assert r.status_code == 403


def test_reports_package_reexports_generate_report():
    from backend.reports import generate_report

    assert callable(generate_report)