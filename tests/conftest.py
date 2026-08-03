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
    _TEST_DB.unlink()
os.environ["SENTINEL_DATABASE_URL"] = f"sqlite:///{_TEST_DB.as_posix()}"
os.environ["SENTINEL_INTERVAL"] = "60"

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
    """Execute the simulation pipeline inside a test database."""
    from backend.api.system import run_pipeline
    from backend.collectors.simulator import AttackSimulator

    simulator = AttackSimulator()
    records = simulator.collect() if scenario is None else simulator.scenario(scenario)
    return run_pipeline(db, records)
