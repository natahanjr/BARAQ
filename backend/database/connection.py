"""Database engine / session management (PostgreSQL).

The backend runs on PostgreSQL via SQLAlchemy 2.0 ORM:
``BARAQ_DATABASE_URL=postgresql://user:pass@host:5432/db`` with the
psycopg3 driver (``pip install "psycopg[binary]"``).
"""
from __future__ import annotations

import logging

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import sessionmaker

from backend.config import DATABASE_URL, ECHO_SQL
from backend.database.models import (
    Alert,
    Base,
    DnsQuery,
    EmailMessage,
    EntityRisk,
    EntityRiskEvent,
    FileScan,
    HttpRequest,
    Incident,
    NetworkConnection,
    NormalizedEvent,
    ProcessRecord,
    UsbDevice,
    VulnFinding,
)

logger = logging.getLogger("baraq.db")


def normalize_database_url(url: str) -> str:
    """Prefer the psycopg3 driver for plain postgres:// URLs.

    SQLAlchemy would otherwise default to psycopg2, which is not installed.
    ``postgresql://`` / ``postgres://`` are rewritten to the psycopg3 scheme;
    URLs with an explicit driver (``+psycopg``, ``+psycopg2``) pass through
    untouched.
    """
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url

# In-place additive column migrations (idempotent; used for pre-Alembic DDL).
_ADDITIVE_MIGRATIONS = {
    "v2_events": [
        ("event_id", "VARCHAR(64) DEFAULT ''"),
        ("event_type", "VARCHAR(32) DEFAULT ''"),
        ("destination", "VARCHAR(128) DEFAULT ''"),
        ("process", "JSONB"),
        ("network", "JSONB"),
        ("outcome", "VARCHAR(16) DEFAULT ''"),
        ("schema_version", "VARCHAR(8) DEFAULT '1.1'"),
    ],
    "events": [
        ("risk_score", "REAL"),
        ("is_anomaly", "BOOLEAN DEFAULT 0"),
        ("ml_score", "REAL"),
        ("org", "VARCHAR(64) DEFAULT ''"),
        ("data_integrity", "VARCHAR(16) DEFAULT 'complete'"),
        ("demo", "BOOLEAN DEFAULT 0"),
    ],
    "alerts": [
        ("detection_method", "VARCHAR(16) DEFAULT 'rule'"),
        ("risk_score", "REAL"),
        ("risk_level", "VARCHAR(16) DEFAULT 'MEDIUM'"),
        ("trigger_count", "INTEGER DEFAULT 1"),
        ("host", "VARCHAR(128) DEFAULT ''"),
        ("org", "VARCHAR(64) DEFAULT ''"),
        ("ticket_links", "JSONB DEFAULT '[]'::jsonb"),
        ("demo", "BOOLEAN DEFAULT 0"),
        ("correlation_id", "VARCHAR(64) DEFAULT ''"),
        ("risk_json", "TEXT"),
        ("intel_json", "TEXT"),
    ],
    "entity_risk": [
        ("demo", "BOOLEAN DEFAULT 0"),
        ("last_escalated_level", "VARCHAR(16) DEFAULT ''"),
        ("last_escalated_score", "REAL DEFAULT 0"),
        ("last_escalated_at", "TIMESTAMP"),
    ],
    "entity_risk_events": [
        ("demo", "BOOLEAN DEFAULT 0"),
    ],
    "incidents": [
        ("org", "VARCHAR(64) DEFAULT ''"),
        ("demo", "BOOLEAN DEFAULT 0"),
        ("confidence", "REAL DEFAULT 0.5"),
        ("correlation_key", "VARCHAR(96) DEFAULT ''"),
        ("chain_json", "TEXT"),
        ("chain_confidence", "REAL DEFAULT 0"),
        ("chain_risk", "INTEGER DEFAULT 0"),
        ("responded_at", "TIMESTAMP"),
    ],
    "network_connections": [
        ("bytes_sent", "INTEGER DEFAULT 0"),
        ("bytes_recv", "INTEGER DEFAULT 0"),
        ("duration_seconds", "REAL DEFAULT 0"),
        ("org", "VARCHAR(64) DEFAULT ''"),
        ("demo", "BOOLEAN DEFAULT 0"),
    ],
    "processes": [
        ("org", "VARCHAR(64) DEFAULT ''"),
        ("demo", "BOOLEAN DEFAULT 0"),
        ("guid", "VARCHAR(64) DEFAULT ''"),
        ("parent_guid", "VARCHAR(64) DEFAULT ''"),
    ],
    "dns_queries": [
        ("org", "VARCHAR(64) DEFAULT ''"),
        ("demo", "BOOLEAN DEFAULT 0"),
    ],
    "http_requests": [
        ("org", "VARCHAR(64) DEFAULT ''"),
        ("demo", "BOOLEAN DEFAULT 0"),
    ],
    "emails": [
        ("org", "VARCHAR(64) DEFAULT ''"),
        ("demo", "BOOLEAN DEFAULT 0"),
    ],
    "usb_devices": [
        ("org", "VARCHAR(64) DEFAULT ''"),
        ("demo", "BOOLEAN DEFAULT 0"),
    ],
    "file_scans": [
        ("org", "VARCHAR(64) DEFAULT ''"),
        ("demo", "BOOLEAN DEFAULT 0"),
    ],
    "vuln_findings": [
        ("org", "VARCHAR(64) DEFAULT ''"),
        ("demo", "BOOLEAN DEFAULT 0"),
    ],
    "audit_log": [
        ("prev_hash", "VARCHAR(64) DEFAULT '" + ("0" * 64) + "'"),
        ("hash", "VARCHAR(64) DEFAULT '" + ("0" * 64) + "'"),
    ],
    "users": [
        ("totp_secret", "TEXT DEFAULT ''"),
        ("totp_enabled", "BOOLEAN DEFAULT 0"),
        ("last_login_at", "DATETIME"),
        ("org", "VARCHAR(64) DEFAULT ''"),
        ("registration_status", "VARCHAR(16) DEFAULT ''"),
        ("must_change_password", "BOOLEAN DEFAULT 0"),
    ],
    "endpoints": [
        ("org", "VARCHAR(64) DEFAULT ''"),
        ("agent_version", "VARCHAR(32) DEFAULT ''"),
        ("os_info", "VARCHAR(128) DEFAULT ''"),
        ("tags", "VARCHAR(256) DEFAULT ''"),
        ("health_status", "VARCHAR(16) DEFAULT 'unknown'"),
        ("update_status", "VARCHAR(16) DEFAULT 'none'"),
        ("errors_total", "INTEGER DEFAULT 0"),
    ],
}


def _ddl_default(ddl_type: str) -> str:
    """Translate boolean defaults for PostgreSQL (BOOLEAN DEFAULT 0 requires
    TRUE/FALSE)."""
    if "BOOLEAN" in ddl_type.upper() and "DEFAULT 0" in ddl_type.upper():
        return ddl_type.replace("DEFAULT 0", "DEFAULT FALSE")
    return ddl_type


engine = create_engine(
    normalize_database_url(DATABASE_URL),
    echo=ECHO_SQL,
    pool_pre_ping=True,
    connect_args={"options": "-c timezone=UTC"},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _readonly_engine():
    """Build the read-replica engine once (BARAQ_READONLY_DATABASE_URL)."""
    from backend.config import READONLY_DATABASE_URL

    if not READONLY_DATABASE_URL:
        return None
    return create_engine(
        normalize_database_url(READONLY_DATABASE_URL),
        echo=ECHO_SQL,
        pool_pre_ping=True,
        connect_args={"options": "-c timezone=UTC"},
    )


readonly_engine = _readonly_engine()

SessionReadonly = sessionmaker(bind=readonly_engine or engine, autoflush=False, expire_on_commit=False)


#: Demo-aware tables: every ORM query against these is restricted to the
#: matching partition when the session carries a ``baraq_demo`` flag.
_DEMO_PARTITION_MODELS = (
    NormalizedEvent,
    Alert,
    EntityRisk,
    EntityRiskEvent,
    Incident,
    ProcessRecord,
    NetworkConnection,
    DnsQuery,
    HttpRequest,
    EmailMessage,
    UsbDevice,
    FileScan,
    VulnFinding,
)

#: Table-name -> model lookup used by the partition hook (portable across
#: SQLAlchemy builds that do not expose ``Select.find_entities()``).
_TABLE_TO_MODEL = {model.__tablename__: model for model in _DEMO_PARTITION_MODELS}


@event.listens_for(SessionLocal.class_, "do_orm_execute")
def _demo_partition(orm_execute_state) -> None:
    """Restrict a session's queries to one demo partition (soft-delete style).

    Detection (``run_detection``), the scheduler cycle and demo seeding set
    ``session.info["baraq_demo"]`` (True for demo/test data, False for
    production) around their work. Every SELECT issued while the flag is set
    is rewritten with ``<model>.demo IS <mode>`` so:

    * demo events are never re-detected as production alerts (window-based
      native rules, the correlation engine and RBA all query on the same
      session), and
    * demo detection never merges into production alerting/RBA state.

    Cursor bookkeeping (``max_event_id``/``set_cursor``) runs with the flag
    cleared so the watermark stays global.

    Note: registered on the ``sessionmaker`` class (``SessionLocal.class_``),
    not on the ``sqlalchemy.orm.Session`` symbol - the sessionmaker resolves
    its own class object which is not guaranteed to be the imported one.
    Entity extraction walks the statement tree via ``get_children()`` and maps
    table names to models instead of using ``find_entities()``, which is not
    available on every SQLAlchemy build.
    """
    mode = orm_execute_state.session.info.get("baraq_demo")
    if mode is None or not orm_execute_state.is_select:
        return
    conds = []
    seen: set = set()

    def walk(node, depth: int = 0) -> None:
        if node is None or depth > 8:
            return
        if id(node) in seen:
            return
        seen.add(id(node))
        model = _TABLE_TO_MODEL.get(getattr(node, "name", None))
        if model is not None:
            conds.append(model.demo.is_(mode))
            return
        for child in node.get_children(column_collections=False):
            walk(child, depth + 1)

    walk(orm_execute_state.statement)
    if conds:
        orm_execute_state.statement = orm_execute_state.statement.where(*conds)


# Mirror the partition onto the read-replica session class as well (no-op when
# the readonly sessionmaker resolves the very same class).
if SessionReadonly.class_ is not SessionLocal.class_:
    event.listen(SessionReadonly.class_, "do_orm_execute", _demo_partition)


def get_db_readonly():
    """FastAPI dependency: a read-only session (replica when configured)."""
    db = SessionReadonly()
    try:
        yield db
    finally:
        db.close()


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
    """Translate boolean defaults for PostgreSQL (Postgres requires TRUE/FALSE)."""
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
        # Tenant-scoped reads: every alert/event/incident query filters on org.
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS idx_events_org ON events (org)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS idx_alerts_org ON alerts (org)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS idx_incidents_org ON incidents (org)"
        )
        # Tenant-scoped detection: rules filter every telemetry table by org.
        for _aux_table in (
            "processes", "network_connections", "dns_queries", "http_requests",
            "emails", "usb_devices", "file_scans", "vuln_findings",
        ):
            conn.exec_driver_sql(
                f"CREATE INDEX IF NOT EXISTS idx_{_aux_table}_org ON {_aux_table} (org)"
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
