"""Database engine / session management (SQLite by default, PostgreSQL for fleets).

The backend is dialect-portable through SQLAlchemy 2.0 ORM: switch to
PostgreSQL by setting ``SENTINEL_DATABASE_URL=postgresql://user:pass@host:5432/db``
and installing the driver (``pip install "psycopg[binary]"``). All schema,
migrations and analytics queries are dialect-aware.
"""
from __future__ import annotations

import logging

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import sessionmaker

from backend.config import DATABASE_URL, ECHO_SQL
from backend.database.models import Base

logger = logging.getLogger("sentinel.db")


def normalize_database_url(url: str) -> str:
    """Prefer the psycopg3 driver for plain postgres:// URLs.

    SQLAlchemy would otherwise default to psycopg2, which is not installed.
    ``postgresql://`` / ``postgres://`` are rewritten to the psycopg3 scheme;
    URLs with an explicit driver (``+psycopg``, ``+psycopg2``) and SQLite
    URLs pass through untouched.
    """
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url


IS_SQLITE = normalize_database_url(DATABASE_URL).startswith("sqlite")
IS_POSTGRES = not IS_SQLITE

# In-place migrations for existing SQLite files (additive columns only).
_ADDITIVE_MIGRATIONS = {
    "events": [
        ("risk_score", "REAL"),
        ("is_anomaly", "BOOLEAN DEFAULT 0"),
        ("ml_score", "REAL"),
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
    "audit_log": [
        ("prev_hash", "VARCHAR(64) DEFAULT '" + ("0" * 64) + "'"),
        ("hash", "VARCHAR(64) DEFAULT '" + ("0" * 64) + "'"),
    ],
    "users": [
        ("totp_secret", "TEXT DEFAULT ''"),
        ("totp_enabled", "BOOLEAN DEFAULT 0"),
        ("last_login_at", "DATETIME"),
    ],
}


def _sqlite_pragmas(dbapi_connection, connection_record):  # noqa: ARG001
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


engine = create_engine(
    normalize_database_url(DATABASE_URL),
    echo=ECHO_SQL,
    connect_args={"check_same_thread": False} if IS_SQLITE else {},
    pool_pre_ping=True,
)

if IS_SQLITE:
    event.listen(engine, "connect", _sqlite_pragmas)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _backfill_audit_chain() -> None:
    """Chain existing (pre-hardening) audit rows so verify_chain passes."""
    from sqlalchemy import select

    from backend.database.models import AuditLog

    with SessionLocal() as db:
        rows = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
        expected_prev = "0" * 64
        changed = False
        for row in rows:
            if row.hash and row.hash != "0" * 64:
                expected_prev = row.hash
                continue
            from backend.audit import _chain_hash
            from backend.database.models import canonical_timestamp

            canonical = "|".join(
                [
                    expected_prev,
                    row.actor or "",
                    row.action or "",
                    row.entity_type or "",
                    row.entity_id or "",
                    row.detail or "",
                    row.ip or "",
                    canonical_timestamp(row.created_at),
                ]
            )
            row.prev_hash = expected_prev
            row.hash = _chain_hash(canonical)
            expected_prev = row.hash
            changed = True
        if changed:
            db.commit()
            logger.info("Audit chain backfilled (%d rows)", len(rows))


def _ddl_default(ddl_type: str) -> str:
    """Translate boolean defaults for PostgreSQL (BOOLEAN DEFAULT 0 is
    SQLite syntax; Postgres requires TRUE/FALSE)."""
    if not IS_POSTGRES:
        return ddl_type
    if "BOOLEAN" in ddl_type.upper() and "DEFAULT 0" in ddl_type.upper():
        return ddl_type.replace("DEFAULT 0", "DEFAULT FALSE")
    return ddl_type


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
                        f"ALTER TABLE {table} ADD COLUMN {column} {_ddl_default(ddl_type)}"
                    )
                    logger.info("Migration: added %s.%s", table, column)
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS idx_events_ts ON events (timestamp)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status)"
        )
        # Composite entity-graph indexes: the BFS resolves neighbours via
        # (src_kind, src_name) / (dst_kind, dst_name) pairs - the single-column
        # indexes alone turn an entity subgraph query into a full scan.
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS idx_edges_src ON entity_edges (src_kind, src_name)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS idx_edges_dst ON entity_edges (dst_kind, dst_name)"
        )
    _backfill_audit_chain()
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
