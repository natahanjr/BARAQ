"""Database engine / session management (SQLite-first)."""
from __future__ import annotations

import logging

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import sessionmaker

from backend.config import DATABASE_URL, ECHO_SQL
from backend.database.models import Base

logger = logging.getLogger("sentinel.db")

# In-place migrations for existing SQLite files (additive columns only).
_ADDITIVE_MIGRATIONS = {
    "events": [
        ("risk_score", "REAL"),
    ],
    "alerts": [
        ("detection_method", "VARCHAR(16) DEFAULT 'rule'"),
        ("risk_score", "REAL"),
        ("risk_level", "VARCHAR(16) DEFAULT 'MEDIUM'"),
        ("trigger_count", "INTEGER DEFAULT 1"),
        ("host", "VARCHAR(128) DEFAULT ''"),
    ],
    "network_connections": [
        ("bytes_sent", "INTEGER DEFAULT 0"),
        ("bytes_recv", "INTEGER DEFAULT 0"),
        ("duration_seconds", "REAL DEFAULT 0"),
    ],
}


def _sqlite_pragmas(dbapi_connection, connection_record):  # noqa: ARG001
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


engine = create_engine(
    DATABASE_URL,
    echo=ECHO_SQL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)

if DATABASE_URL.startswith("sqlite"):
    event.listen(engine, "connect", _sqlite_pragmas)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    """Create all tables, apply additive migrations and analytics indexes."""
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    for table, columns in _ADDITIVE_MIGRATIONS.items():
        existing = {c["name"] for c in inspector.get_columns(table)} if inspector.has_table(table) else set()
        with engine.begin() as conn:
            for column, ddl_type in columns:
                if column not in existing:
                    conn.exec_driver_sql(
                        f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}"
                    )
                    logger.info("Migration: added %s.%s", table, column)
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS idx_events_ts ON events (timestamp)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status)"
        )
    logger.info("Database initialised at %s", DATABASE_URL)


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db():
    """FastAPI dependency alias."""
    yield from get_session()
