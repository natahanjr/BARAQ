"""Train ML on the full 133K dataset."""
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

log_file = Path(__file__).parent / "train_output.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(log_file, mode="w"),
        logging.StreamHandler(sys.stdout),
    ],
)

from backend.database.connection import SessionLocal
from backend.ml.anomaly import get_detector

print("=== ML Training on Full Dataset ===", flush=True)
db = SessionLocal()

from sqlalchemy import func, select
from backend.database.models import NormalizedEvent, Verdict

total = db.scalar(select(func.count(NormalizedEvent.id)))
att = db.scalar(select(func.count(Verdict.id)).where(Verdict.verdict == "true_positive"))
ben = db.scalar(select(func.count(Verdict.id)).where(Verdict.verdict == "false_positive"))
print(f"Events: {total} | Attack: {att} | Benign: {ben}", flush=True)
db.close()

t0 = time.time()
print(f"[{time.time()-t0:.0f}s] Starting full train()...", flush=True)
result = get_detector().train(None, hours=None, validate=False)
print(f"[{time.time()-t0:.0f}s] Result: {result}", flush=True)

d = get_detector()
print(f"[{time.time()-t0:.0f}s] version={d.version} samples={d.n_samples} models={list(d.models.keys())}", flush=True)
print(f"[{time.time()-t0:.0f}s] Done.", flush=True)
