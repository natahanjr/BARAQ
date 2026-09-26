"""Prove the alert->human delivery path: raise a real alert, assert it pages.

Test-only. Runs the detection pipeline on a synthetic brute-force scenario
against the configured database and checks that the configured webhook sink
actually received the notification.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database.connection import SessionLocal  # noqa: E402


def main() -> int:
    from backend.api.system import run_pipeline
    from tests.fixtures import brute_force

    sink_file = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    records = brute_force()

    db = SessionLocal()
    try:
        before = len(db.query(__import__("backend.database.models", fromlist=["Alert"]).Alert).all())
        result = run_pipeline(db, records)
        from backend.database.models import Alert

        db.commit()
        alerts = db.query(Alert).order_by(Alert.id.desc()).limit(10).all()
        print(f"pipeline result: {result}")
        print(f"alerts before={before} newest:")
        for a in alerts[:5]:
            print(f"  #{a.id} {a.severity:8} {a.name[:50]}")
    finally:
        db.close()

    # The notify worker is asynchronous; give it time to deliver.
    deadline = time.time() + 25
    while time.time() < deadline:
        if sink_file and sink_file.exists() and sink_file.stat().st_size > 0:
            break
        time.sleep(1)

    if not sink_file or not sink_file.exists() or sink_file.stat().st_size == 0:
        print("RESULT: NO WEBHOOK DELIVERED")
        return 1

    lines = [json.loads(x) for x in sink_file.read_text(encoding="utf-8").splitlines() if x.strip()]
    print(f"RESULT: {len(lines)} webhook(s) delivered")
    for rec in lines:
        p = rec.get("payload", {})
        name = p.get("name") or p.get("alert_name") or "(no name)"
        sev = p.get("severity", "?")
        print(f"  -> severity={sev} name={name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
