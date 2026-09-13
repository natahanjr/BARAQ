"""Check ML status."""
import os, sys
os.chdir(r"F:\My Project\Baraq")
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"

from backend.ml.anomaly import get_detector
d = get_detector()
print(f"Ready: {d.is_ready}")
print(f"Version: {d.version}")
print(f"Samples: {d.n_samples}")
print(f"Streams: {list(d.models.keys())}")
print(f"Supervised: {d.supervised_name}")
print(f"Trained: {d.trained_at}")
print(f"Thresholds: {d.thresholds}")
rob = d.robustness
if rob:
    print(f"Robustness keys: {list(rob.keys())}")
else:
    print("Robustness: none")
