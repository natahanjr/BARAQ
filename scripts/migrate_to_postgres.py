"""Migrate the existing SQLite database into PostgreSQL.

One-time migration for fleet-scale deployments (100+ endpoints). Copies every
table from the current SQLite ``sentinel.db`` into a target PostgreSQL
database, preserving primary keys and relationships, then fixes the identity
sequences so future inserts never collide.

Usage:
    python scripts/migrate_to_postgres.py --pg-url postgresql://user:pass@host:5432/sentinel

Options:
    --pg-url    target PostgreSQL URL (or env SENTINEL_PG_URL)
    --sqlite    source SQLite file (default: current SENTINEL_DATABASE_URL)
    --force     overwrite target tables that already contain rows
    --batch     rows per insert batch (default 1000)
"""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-7s | %(message)s")
logger = logging.getLogger("sentinel.migrate")

_BATCH = 1000


def _as_aware(value):
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _tables(engine):
    from sqlalchemy import inspect

    return sorted(inspect(engine).get_table_names())


def _copy_table(src_engine, dst_engine, table_name: str, force: bool) -> tuple[int, int]:
    from sqlalchemy import MetaData, func, select

    meta = MetaData()
    meta.reflect(bind=src_engine, only=[table_name])
    table = meta.tables[table_name]

    with dst_engine.connect() as dst:
        existing = dst.execute(select(func.count()).select_from(table)).scalar() if force else None
        if not force and existing:
            raise SystemExit(
                f"Table '{table_name}' already has {existing} row(s) on the target. "
                "Re-run with --force to truncate and re-copy."
            )
        if force:
            dst.execute(table.delete())
            dst.commit()

    source_rows = 0
    copied = 0
    buffer: list[dict] = []
    with src_engine.connect() as src, dst_engine.begin() as dst:
        for row in src.execution_options(stream_results=True).execute(select(table)):
            source_rows += 1
            buffer.append({c.key: _as_aware(row._mapping[c.key]) for c in table.columns})
            if len(buffer) >= _BATCH:
                dst.execute(table.insert(), buffer)
                copied += len(buffer)
                buffer = []
        if buffer:
            dst.execute(table.insert(), buffer)
            copied += len(buffer)
    return source_rows, copied


def _fix_sequences(dst_engine) -> None:
    """Advance Postgres identity sequences past the migrated PKs.

    Reflection does not reliably report ``autoincrement`` for SERIAL columns,
    so every single-column integer PK is probed with
    ``pg_get_serial_sequence`` - tables without a backing sequence (plain
    INTEGER columns) are skipped naturally by the NULL result.
    """
    from sqlalchemy import MetaData, func, select

    with dst_engine.begin() as conn:
        meta = MetaData()
        meta.reflect(bind=dst_engine)
        for table in meta.sorted_tables:
            pk_cols = list(table.primary_key.columns)
            if len(pk_cols) != 1:
                continue
            col = pk_cols[0]
            if col.type.python_type is not int:
                continue
            seq_name = conn.execute(
                select(func.pg_get_serial_sequence(table.name, col.name))
            ).scalar()
            if not seq_name:
                continue
            max_id = conn.execute(select(func.max(col))).scalar()
            if max_id is None:
                continue
            conn.exec_driver_sql(f"SELECT setval('{seq_name}', {int(max_id)})")
            logger.info("Sequence %s advanced to %d", seq_name, int(max_id))


def main() -> None:
    from sqlalchemy import create_engine

    from backend.database.connection import normalize_database_url
    from backend.database.models import Base

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg-url", default=None, help="Target PostgreSQL URL")
    parser.add_argument("--sqlite", default=None, help="Source SQLite file path")
    parser.add_argument("--force", action="store_true", help="Overwrite non-empty target tables")
    parser.add_argument("--batch", type=int, default=1000)
    args = parser.parse_args()
    global _BATCH
    _BATCH = args.batch

    pg_url = args.pg_url or __import__("os").environ.get("SENTINEL_PG_URL", "")
    if not pg_url:
        raise SystemExit("Provide --pg-url or set SENTINEL_PG_URL")

    if args.sqlite:
        sqlite_url = f"sqlite:///{Path(args.sqlite).resolve().as_posix()}"
    else:
        from backend.config import DATABASE_URL

        sqlite_url = DATABASE_URL
    if not sqlite_url.startswith("sqlite"):
        raise SystemExit("Source is not SQLite; pass --sqlite pointing at the .db file")

    src = create_engine(sqlite_url)
    dst = create_engine(normalize_database_url(pg_url), pool_pre_ping=True)

    src_tables = set(_tables(src))
    logger.info("Creating schema on target (existing tables are kept)")
    Base.metadata.create_all(bind=dst)

    total = 0
    for table_name in src_tables:
        source_rows, copied = _copy_table(src, dst, table_name, args.force)
        total += copied
        marker = "OK" if source_rows == copied else "MISMATCH"
        logger.info("%-24s %8d -> %8d rows  %s", table_name, source_rows, copied, marker)
        if source_rows != copied:
            logger.warning("Table %s: copied %d of %d rows - re-run to retry", table_name, copied, source_rows)

    _fix_sequences(dst)
    logger.info("Migration complete: %d rows copied in total", total)
    logger.info("Point SentinelSOC at the new database:")
    logger.info('  set SENTINEL_DATABASE_URL=%s', pg_url)
    logger.info("  python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000")


if __name__ == "__main__":
    main()
