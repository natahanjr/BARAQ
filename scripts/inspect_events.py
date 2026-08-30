"""Inspect imported external dataset events."""
from __future__ import annotations
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent
from sqlalchemy import func, select

s = SessionLocal()

# Categories
cats = s.execute(
    select(NormalizedEvent.category, func.count(NormalizedEvent.id))
    .where(NormalizedEvent.source == "external_dataset")
    .group_by(NormalizedEvent.category)
).all()
print("Categories:")
for c, cnt in cats:
    print(f"  {c}: {cnt:,}")

# Sample raw_json
rows = s.execute(
    select(NormalizedEvent.id, NormalizedEvent.raw_json, NormalizedEvent.event_id)
    .where(NormalizedEvent.source == "external_dataset")
    .limit(3)
).all()
print("\nSample raw_json:")
for r in rows:
    raw = r.raw_json or {}
    print(f"  ID={r.id} event_id={r.event_id}")
    print(f"    keys: {list(raw.keys())}")
    facts = raw.get("facts", {})
    print(f"    facts keys: {list(facts.keys())[:10]}")
    print(f"    dataset_label: {raw.get('dataset_label', 'none')}")

# Hosts from raw_json
hosts_raw = s.execute(
    select(func.distinct(NormalizedEvent.host))
    .where(NormalizedEvent.source == "external_dataset")
).scalars().all()
print(f"\nHosts ({len(hosts_raw)}): {hosts_raw}")

s.close()
