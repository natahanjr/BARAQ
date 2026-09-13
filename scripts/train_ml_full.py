"""Train ML using the full detector.train() with all features."""
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

print(f"\n=== TRAINING RESULT ({elapsed:.0f}s) ===")
for k, v in result.items():
    if k == "thresholds":
        print(f"  {k}:")
        for sk, sv in v.items():
            print(f"    {sk}: {sv:.4f}")
    else:
        print(f"  {k}: {v}")
