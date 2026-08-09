"""Migrations CI: the baseline must bootstrap a fresh database end-to-end."""
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_migrations_baseline_bootstraps_fresh_sqlite(tmp_path):
    db = tmp_path / "migrate.db"
    import os

    env = dict(os.environ)  # keep SystemRoot etc. or winsock breaks (WinError 10106)
    env.update({
        "SENTINEL_DATABASE_URL": f"sqlite:///{db}",
        "SENTINEL_SKIP_SECRET_GEN": "1",
    })
    run = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "migrate_db.py")],
        capture_output=True, text=True, check=False, env=env,
        cwd=ROOT,
    )
    assert run.returncode == 0, run.stderr[-1500:]
    conn = sqlite3.connect(db)
    try:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
    finally:
        conn.close()
    for expected in (
        "users", "alerts", "events", "entity_nodes", "entity_edges",
        "threat_intel_records", "audit_log", "alembic_version",
    ):
        assert expected in tables, f"missing table after upgrade: {expected}"


def test_baseline_revision_exists():
    versions = ROOT / "alembic" / "versions"
    baselines = list(versions.glob("*baseline*.py"))
    assert baselines, "no baseline migration"
    text = baselines[0].read_text(encoding="utf-8")
    assert "down_revision = None" in text
    assert "def upgrade" in text