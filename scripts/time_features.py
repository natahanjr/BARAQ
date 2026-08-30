"""Time feature extraction on synthetic events to estimate total."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent
from backend.ml.anomaly import event_feature_vector, LOGIN_EVENTS, PROCESS_EVENTS
from sqlalchemy import select, func

session = SessionLocal()

# Count events
login_count = session.scalar(select(func.count()).where(NormalizedEvent.event_id.in_(LOGIN_EVENTS)))
process_count = session.scalar(select(func.count()).where(NormalizedEvent.event_id.in_(PROCESS_EVENTS)))
print(f"Login events: {login_count}, Process events: {process_count}", flush=True)

# Test on 100 events
stmt = select(NormalizedEvent).where(
    NormalizedEvent.event_id.in_(LOGIN_EVENTS),
).limit(100)
events = session.scalars(stmt).all()
print(f"\nTiming 100 login events...", flush=True)
t0 = time.time()
success = 0
for ev in events:
    try:
        vec = event_feature_vector(ev)
        if vec:
            success += 1
    except:
        pass
elapsed = time.time() - t0
print(f"  {success}/100 succeeded in {elapsed:.2f}s ({elapsed/100*1000:.1f}ms each)", flush=True)
print(f"  Estimated for {login_count} events: {login_count * elapsed / 100 / 60:.1f} minutes", flush=True)

session.close()
