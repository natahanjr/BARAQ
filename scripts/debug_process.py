"""Debug: check process feature vector length."""
import sys
sys.path.insert(0, r"F:\My Project\Baraq")
from scripts.train_full_bulk import build_process_features, precompute_temporals, bulk_load_events
from backend.database.connection import SessionLocal
from collections import defaultdict

session = SessionLocal()
events = bulk_load_events(session)
session.close()
tc = precompute_temporals(events)

process_indices = tc["process_indices"]
print(f"Process events: {len(process_indices)}")

# Check first process event
if process_indices:
    idx = process_indices[0]
    ev = events[idx]
    vec = build_process_features(ev, idx, tc)
    print(f"Feature vector length: {len(vec)}")
    print(f"Features: {vec}")
