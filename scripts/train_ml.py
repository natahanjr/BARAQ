"""Train ML on real OTRF data."""
import os, sys, time, logging

os.chdir(r"F:\My Project\Baraq")
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

from backend.ml.tasks import _bulk_train
from backend.database.connection import SessionLocal

db = SessionLocal()
t0 = time.time()
result = _bulk_train(db, kind="manual")
elapsed = time.time() - t0
db.close()

print(f"Done in {elapsed:.1f}s")
print(f"Status: {result['status']}")
print(f"Streams: {result.get('streams', [])}")
print(f"Samples: {result.get('samples', 0)}")
print(f"Supervised: {result.get('supervised', 'none')}")
if "thresholds" in result:
    for k, v in result["thresholds"].items():
        print(f"  Threshold {k}: {v:.3f}")
