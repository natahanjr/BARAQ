"""Check ML status directly."""
import json, sys, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.ml.anomaly import get_detector
from backend.database.connection import SessionLocal

d = get_detector()
print(f"Version: {d.version}")
print(f"Trained at: {d.trained_at}")
print(f"Samples: {d.n_samples}")
print(f"Events at train: {d.events_at_train}")
print(f"Model source: {d.model_source}")
print(f"Models: {list(d.models.keys())}")
print(f"Supervised: {d.supervised_name}")
print(f"Thresholds: {d.thresholds}")
print(f"Robustness: {d.robustness}")

db = SessionLocal()
from sqlalchemy import func, select
from backend.database.models import NormalizedEvent
total = db.scalar(select(func.count(NormalizedEvent.id)))
print(f"\nTotal events in DB: {total:,}")
db.close()
