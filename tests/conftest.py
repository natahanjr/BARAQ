"""Shared test fixtures - isolated database per test session.

Set the database URL BEFORE importing any backend module so tests never
touch the production database.

Isolation uses the dedicated ``baraq_test`` database on the local
PostgreSQL cluster (service ``BARAQ-PostgreSQL``). Every table is
truncated (with identity restart) before each test, so primary keys stay
deterministic and the suite is fully isolated from ``baraq``.
"""
from __future__ import annotations

import os
import tempfile

os.environ["BARAQ_DATABASE_URL"] = os.environ.get(
    "BARAQ_TEST_DATABASE_URL",
    "postgresql+psycopg://postgres@127.0.0.1:55432/baraq_test",
)
print(f"[conftest] test DB URL -> {os.environ['BARAQ_DATABASE_URL']}")
os.environ["BARAQ_INTERVAL"] = "60"
# Isolate ML model persistence from the production database folder.
_test_tmp = os.path.join(tempfile.gettempdir(), "baraq_test_meta")
os.makedirs(_test_tmp, exist_ok=True)
os.environ["BARAQ_ML_META_FILE"] = os.path.join(_test_tmp, "model_meta.json")
# Never let first-run secret generation write to / modify the real project .env.
os.environ["BARAQ_SKIP_SECRET_GEN"] = "1"
# Override the project .env credentials so tests always run with the dev keys
# (the config loader is non-overriding, so these take precedence over .env).
os.environ["BARAQ_API_KEYS"] = '{"baraq-dev-admin": "admin", "baraq-dev-analyst": "analyst"}'
os.environ["BARAQ_ADMIN_PASSWORD"] = "baraq-test-admin"
os.environ["BARAQ_TOKEN_SECRET"] = "baraq-test-token-secret"
# Pin agent keys too: _secret() falls back to the real DPAPI vault, which
# still holds the pre-rename agent keys - tests must never depend on them.
os.environ["BARAQ_AGENT_KEYS"] = (
    '{"baraq-agent-dev": "agent-dev", "baraq-agent-laptop2": "laptop2"}'
)
# Deterministic test runs: never spawn the background scheduler thread and use
# the fully-local assistant engine (no dependence on a live AI endpoint).
os.environ["BARAQ_NO_SCHEDULER"] = "1"
os.environ["BARAQ_AI_API_URL"] = ""
os.environ["BARAQ_SCHEDULER_ENABLED"] = "0"  # no background collector in tests
# Never spam Windows toasts / webhooks / email from synthetic test alerts.
os.environ["BARAQ_TOAST_ENABLED"] = "0"

import pytest  # noqa: E402

from sqlalchemy import text  # noqa: E402

from backend.config import DATABASE_URL  # noqa: E402
from backend.database.connection import SessionLocal, engine, init_db  # noqa: E402
from backend.database.models import Base  # noqa: E402

_TABLE_NAMES = list(Base.metadata.tables.keys())


@pytest.fixture(scope="session", autouse=True)
def _init_database():
    init_db()
    yield


@pytest.fixture(autouse=True)
def _clean_database():
    """Reset every table before each test for full isolation."""
    # Close any pooled connections left in an open transaction by the previous
    # test (e.g. a session that was never closed): otherwise the TRUNCATE below
    # blocks forever waiting for the ACCESS SHARE lock they still hold.
    engine.dispose()
    session = SessionLocal()
    try:
        for table in _TABLE_NAMES:
            session.execute(text(f'TRUNCATE TABLE "{table}" RESTART IDENTITY CASCADE'))
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
