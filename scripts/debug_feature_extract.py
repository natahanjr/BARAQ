"""Debug: test feature extraction on synthetic events one at a time."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent
from backend.ml.anomaly import event_feature_vector, LOGIN_EVENTS, PROCESS_EVENTS
from sqlalchemy import select

session = SessionLocal()

# Get 10 synthetic login events
stmt = select(NormalizedEvent).where(
    NormalizedEvent.source == "baraq-synthetic-100k",
    NormalizedEvent.event_id.in_(LOGIN_EVENTS),
).limit(10)
events = session.scalars(stmt).all()
print(f"Found {len(events)} synthetic login events", flush=True)

for i, ev in enumerate(events):
    t0 = time.time()
    try:
        vec = event_feature_vector(ev, _shared_session=session)
        print(f"  [{i}] eid={ev.event_id} -> vec_len={len(vec) if vec else 0} in {time.time()-t0:.3f}s", flush=True)
    except Exception as e:
        print(f"  [{i}] eid={ev.event_id} -> ERROR: {e} in {time.time()-t0:.3f}s", flush=True)
        try:
            session.rollback()
        except:
            pass

# Get 10 synthetic process events
stmt = select(NormalizedEvent).where(
    NormalizedEvent.source == "baraq-synthetic-100k",
    NormalizedEvent.event_id.in_(PROCESS_EVENTS),
).limit(10)
events = session.scalars(stmt).all()
print(f"\nFound {len(events)} synthetic process events", flush=True)

for i, ev in enumerate(events):
    t0 = time.time()
    try:
        vec = event_feature_vector(ev, _shared_session=session)
        print(f"  [{i}] eid={ev.event_id} -> vec_len={len(vec) if vec else 0} in {time.time()-t0:.3f}s", flush=True)
    except Exception as e:
        print(f"  [{i}] eid={ev.event_id} -> ERROR: {e} in {time.time()-t0:.3f}s", flush=True)
        try:
            session.rollback()
        except:
            pass

session.close()
print("\nDone!", flush=True)
