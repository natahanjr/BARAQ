"""Apply schema migrations to the configured database.

Convenience wrapper around Alembic so operators never handle CLI details::

    venv\\Scripts\\python scripts\\migrate_db.py            # upgrade to head
    venv\\Scripts\\python scripts\\migrate_db.py --stamp   # mark head on existing DBs

Migrations read ``SENTINEL_DATABASE_URL`` exactly like the application.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402


def _config() -> Config:
    root = Path(__file__).resolve().parent.parent
    cfg = Config(str(root / "alembic.ini"))
    return cfg


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply SentinelSOC schema migrations")
    parser.add_argument("--stamp", action="store_true",
                        help="mark the current schema as head without running DDL "
                             "(for deployments that predate Alembic)")
    args = parser.parse_args(argv)
    cfg = _config()
    if args.stamp:
        command.stamp(cfg, "head")
    else:
        command.upgrade(cfg, "head")
    print("migrations: schema at head")
    return 0


if __name__ == "__main__":
    sys.exit(main())