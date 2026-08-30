import sys
sys.path.insert(0, r"F:\My Project\Baraq")
from backend.ml.anomaly import get_detector
d = get_detector()
print(f"Models: {list(d.models.keys())}")
print(f"Thresholds: {d.thresholds}")
print(f"Supervised: {d.supervised_name}")
print(f"Ready: {d.is_ready}")
print(f"Version: {d.version}")
print(f"Samples: {d.n_samples}")
print(f"Trained: {d.trained_at}")
for k, m in d.models.items():
    name = type(m).__name__
    params = {p: getattr(m, p, "?") for p in ["n_estimators", "contamination", "max_samples"] if hasattr(m, p)}
    print(f"  {k}: {name} {params}")
print()
for k, m in d.supervised_by_stream.items():
    print(f"  supervised[{k}]: {type(m).__name__}")
print()
print(f"Streams: {list(d.models.keys())}")
print(f"Status: {d.status()}")
