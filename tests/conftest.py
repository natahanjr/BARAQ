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
os.environ["SENTINEL_DATABASE_URL"] = f"sqlite:///{_TEST_DB.as_posix()}"
os.environ["SENTINEL_INTERVAL"] = "60"
# Deterministic test runs: never spawn the background scheduler thread and use
# the fully-local assistant engine (no dependence on a live AI endpoint).
os.environ["SENTINEL_NO_SCHEDULER"] = "1"
os.environ["SENTINEL_AI_API_URL"] = ""
os.environ["SENTINEL_SCHEDULER_ENABLED"] = "0"  # no background collector in tests

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
