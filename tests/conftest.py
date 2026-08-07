"""Shared test fixtures - isolated database per test session.

Set the database URL BEFORE importing any backend module so tests never
touch the production sentinel.db file.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TEST_DB = Path(tempfile.gettempdir()) / "sentinel_test.db"
if _TEST_DB.exists():
    try:
        _TEST_DB.unlink()
    except PermissionError:  # another process may still hold a stale handle
        pass
_TEST_ML_META = Path(tempfile.gettempdir()) / "sentinel_model_meta.json"
if _TEST_ML_META.exists():
    try:
        _TEST_ML_META.unlink()
    except PermissionError:
        pass

# Opt-in override: run the suite against PostgreSQL (e.g. the migrated fleet
# cluster) by setting SENTINEL_TEST_DATABASE_URL. Defaults to an isolated
# SQLite file in %TEMP% so the real database/sentinel.db is never touched.
os.environ["SENTINEL_DATABASE_URL"] = os.environ.get(
    "SENTINEL_TEST_DATABASE_URL",
    f"sqlite:///{_TEST_DB.as_posix()}",
)
print(f"[conftest] test DB URL -> {os.environ['SENTINEL_DATABASE_URL']}")
os.environ["SENTINEL_INTERVAL"] = "60"
os.environ["SENTINEL_ML_META_FILE"] = _TEST_ML_META.as_posix()
# Never let first-run secret generation write to / modify the real project .env.
os.environ["SENTINEL_SKIP_SECRET_GEN"] = "1"
# Override the project .env credentials so tests always run with the dev keys
# (the config loader is non-overriding, so these take precedence over .env).
os.environ["SENTINEL_API_KEYS"] = '{"sentinel-dev-admin": "admin", "sentinel-dev-analyst": "analyst"}'
os.environ["SENTINEL_ADMIN_PASSWORD"] = "sentinel-test-admin"
os.environ["SENTINEL_TOKEN_SECRET"] = "sentinel-test-token-secret"
# Deterministic test runs: never spawn the background scheduler thread and use
# the fully-local assistant engine (no dependence on a live AI endpoint).
os.environ["SENTINEL_NO_SCHEDULER"] = "1"
os.environ["SENTINEL_AI_API_URL"] = ""
os.environ["SENTINEL_SCHEDULER_ENABLED"] = "0"  # no background collector in tests
# Never spam Windows toasts / webhooks / email from synthetic test alerts.
os.environ["SENTINEL_TOAST_ENABLED"] = "0"

import pytest  # noqa: E402

from backend.database.connection import SessionLocal, init_db  # noqa: E402
from backend.database.models import Base  # noqa: E402

_TABLE_NAMES = list(Base.metadata.tables.keys())


@pytest.fixture(scope="session", autouse=True)
def _init_database():
    init_db()
    yield


@pytest.fixture(autouse=True)
def _clean_database():
    """Reset every table before each test for full isolation."""
    session = SessionLocal()
    try:
        for table in _TABLE_NAMES:
            session.execute(Base.metadata.tables[table].delete())
        session.commit()
    finally:
        session.close()
    yield


@pytest.fixture()
def db():
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


def run_simulation(db, scenario: str | None = None) -> dict:
    """Execute a fixture-driven pipeline run inside a test database."""
    from backend.api.system import run_pipeline
    from tests.fixtures import full_suite

    return run_pipeline(db, full_suite() if scenario is None else _scenario(scenario))


def _scenario(name: str) -> list[dict]:
    from tests import fixtures

    mapping = {
        "brute_force": fixtures.brute_force,
        "powershell": fixtures.suspicious_powershell,
        "privilege_escalation": fixtures.privilege_escalation,
        "persistence": fixtures.persistence,
        "port_scan": fixtures.port_scan,
        "lateral_movement": fixtures.lateral_movement,
        "data_staging": fixtures.data_staging,
        "baseline": fixtures.benign_baseline,
    }
    if name not in mapping:
        raise KeyError(f"Unknown fixture scenario: {name}")
    return mapping[name]()
