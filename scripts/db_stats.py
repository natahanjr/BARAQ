"""Final DB stats + create verdicts for high-severity events."""
import os, sys, json
from pathlib import Path
os.chdir(Path(__file__).resolve().parent.parent)
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"

from backend.database.connection import engine, SessionLocal
from backend.database.models import NormalizedEvent, Verdict
from sqlalchemy import text, select, func

with engine.connect() as conn:
    total = conn.scalar(select(func.count(NormalizedEvent.id)))
    print(f"\nTotal events: {total}")

    print("\nBy source:")
    for r in conn.execute(select(NormalizedEvent.source, func.count(NormalizedEvent.id)).group_by(NormalizedEvent.source).order_by(func.count(NormalizedEvent.id).desc())):
        print(f"  {r[0]}: {r[1]}")

    print("\nBy category:")
    for r in conn.execute(select(NormalizedEvent.category, func.count(NormalizedEvent.id)).group_by(NormalizedEvent.category).order_by(func.count(NormalizedEvent.id).desc())):
        print(f"  {r[0]}: {r[1]}")

    print("\nBy severity:")
    for r in conn.execute(select(NormalizedEvent.severity, func.count(NormalizedEvent.id)).group_by(NormalizedEvent.severity).order_by(func.count(NormalizedEvent.id).desc())):
        print(f"  {r[0]}: {r[1]}")

    print("\nTop 15 hosts:")
    for r in conn.execute(text("SELECT host, COUNT(*) FROM events WHERE host != '' GROUP BY host ORDER BY COUNT(*) DESC LIMIT 15")):
        print(f"  {r[0]}: {r[1]}")

    print("\nTop 10 users:")
    for r in conn.execute(text("SELECT user, COUNT(*) FROM events WHERE user != '' GROUP BY user ORDER BY COUNT(*) DESC LIMIT 10")):
        print(f"  {r[0]}: {r[1]}")

# Create verdicts for high-severity events
print("\nCreating verdicts for high-severity events...")
session = SessionLocal()
high_sev = session.execute(
    select(NormalizedEvent.id, NormalizedEvent.source).where(NormalizedEvent.severity == "high")
).fetchall()
print(f"Found {len(high_sev)} high-severity events")

created = 0
for row in high_sev:
    existing = session.execute(select(Verdict.id).where(Verdict.event_id == row[0])).first()
    if not existing:
        v = Verdict(
            event_id=row[0],
            verdict="true_positive",
            confidence=0.9,
            analyst="otrf_import",
            note=f"OTRF labeled attack from {row[1]}",
        )
        session.add(v)
        created += 1

session.commit()
print(f"Created {created} verdicts")

vtotal = session.scalar(select(func.count(Verdict.id)))
print(f"Total verdicts in DB: {vtotal}")
session.close()
