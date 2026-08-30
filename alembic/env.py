"""Alembic environment for BARAQ.

The target URL follows the same resolution order as the application itself:
``BARAQ_DATABASE_URL`` (env / .env) with the SQLAlchemy driver suffix
normalised, so ``alembic upgrade head`` always migrates the *configured*
database (no duplicate connection settings to keep in sync).
"""

from __future__ import annotations

import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool

from alembic import context

# Make the backend package importable when alembic runs from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

from backend.config import DATABASE_URL
from backend.database.connection import normalize_database_url
from backend.database.models import Base

target_metadata = Base.metadata


_PLACEHOLDER_URL = "driver://user:pass@localhost/dbname"


def _resolved_url() -> str:
    """Configured URL, with the SQLAlchemy driver suffix normalised.

    The ``alembic.ini`` value is a placeholder; the real connection string
    always comes from the application's ``BARAQ_DATABASE_URL``.
    """
    ini_url = (config.get_main_option("sqlalchemy.url") or "").strip()
    if ini_url and not ini_url.startswith(_PLACEHOLDER_URL):
        return normalize_database_url(ini_url)
    return normalize_database_url(DATABASE_URL)


def run_migrations_offline() -> None:
    context.configure(
        url=_resolved_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = _resolved_url()
    connectable = engine_from_config(cfg, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
