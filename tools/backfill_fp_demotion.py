"""One-time backfill: demote pre-existing dev-workflow false positives.

Re-assesses every OPEN alert with the current context engine and downgrades
severity where the strong-developer-context verdict says so. Idempotent:
alerts already at/below the computed severity are left untouched.

Usage:
    venv\\Scripts\\python tools\\backfill_fp_demotion.py [--dry-run]
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

LADDER = ("low", "medium", "high", "critical")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    from sqlalchemy import select

    from backend.context.engine import assess_for_alert
    from backend.database.connection import SessionLocal
    from backend.database.models import Alert

    session = SessionLocal()
    demoted = 0
    inspected = 0
    try:
        alerts = session.scalars(
            select(Alert).where(Alert.status == "open").order_by(Alert.id.desc())
        ).all()
        for alert in alerts:
            inspected += 1
            facts = assess_for_alert(session, alert)
            if not facts.strong_dev_context:
                continue
            if facts.severity_adjust(alert.confidence) != "demote":
                continue
            try:
                cur = LADDER.index(str(alert.severity).lower())
            except ValueError:
                continue
            new_sev = LADDER[max(0, cur - 1)]
            if new_sev == alert.severity:
                continue
            print(f"#{alert.id} {alert.severity} -> {new_sev}  {alert.name[:60]}")
            if not args.dry_run:
                alert.severity = new_sev
                alert.score = {"critical": 10, "high": 7, "medium": 4, "low": 1}.get(
                    new_sev, alert.score
                )
                alert.updated_at = datetime.now(timezone.utc)
            demoted += 1
        if not args.dry_run:
            session.commit()
        print(f"\ninspected={inspected} demoted={demoted} dry_run={args.dry_run}")
    finally:
        session.close()


if __name__ == "__main__":
    main()
