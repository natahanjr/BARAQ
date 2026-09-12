"""Debug: check why compound events are all skipped."""
import os, sys, json
from pathlib import Path
os.chdir(Path(__file__).resolve().parent.parent)
sys.path.insert(0, ".")
from backend.ml.dataset_adapters import ADAPTERS

adapter = ADAPTERS["security_datasets"]()
d = Path("F:/My Project/Baraq/tmp_data/otrf/datasets/compound")

files = list(d.rglob("*.json"))[:5]
for f in files:
    print(f"File: {f.name}")
    content = f.read_text(encoding="utf-8", errors="replace").strip()
    if not content:
        print("  EMPTY")
        continue
    if content.startswith("["):
        data = json.loads(content)
    else:
        data = [json.loads(line) for line in content.splitlines() if line.strip()]

    if not isinstance(data, list):
        data = [data]

    print(f"  {len(data)} items")
    if data:
        item = data[0]
        if isinstance(item, dict):
            keys = list(item.keys())[:15]
            print(f"  Top keys: {keys}")
            if "_source" in item:
                src = item["_source"]
                if isinstance(src, dict):
                    print(f"  _source keys: {list(src.keys())[:15]}")
                    ts = src.get("time") or src.get("@timestamp") or src.get("timestamp")
                    print(f"  timestamp: {ts}")
                    parsed = adapter.parse_event(item)
                    print(f"  Parsed OK: {parsed is not None}")
                    if not parsed:
                        # Try to figure out why
                        ts2 = src.get("time")
                        print(f"  time field: {ts2} (type: {type(ts2).__name__})")
                        activity_id = src.get("activity_id")
                        print(f"  activity_id: {activity_id}")
                        class_name = src.get("class_name")
                        print(f"  class_name: {class_name}")
            else:
                ts = item.get("time") or item.get("@timestamp") or item.get("timestamp")
                print(f"  timestamp: {ts}")
                parsed = adapter.parse_event(item)
                print(f"  Parsed OK: {parsed is not None}")
    print()
