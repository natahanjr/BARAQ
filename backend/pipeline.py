"""Standalone pipeline runner: collect -> normalize -> detect -> persist.

Usage:
    py -m backend.pipeline            # live collection (Windows)
"""
from __future__ import annotations

import argparse
import logging
import sys

from backend.database.connection import SessionLocal, init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-7s | %(message)s")
logger = logging.getLogger("sentinel.pipeline")


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelSOC pipeline runner")
    parser.parse_args()

    init_db()
    db = SessionLocal()
    try:
        from backend.api.system import run_pipeline
        from backend.collectors import CollectorManager

        manager = CollectorManager()
        records = manager.collect()
        logger.info("Live collection cycle")

        result = run_pipeline(db, records)
        for f in result["findings"]:
            logger.warning(
                "ALERT [%s] %s | MITRE %s | %s",
                f["severity"].upper(), f["name"], f["mitre_id"], f["evidence"][:160],
            )
        print(f"\nPipeline complete: {result['collected']} records, "
              f"{result['alerts_created']} new alerts, "
              f"{len(result['findings'])} findings.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
