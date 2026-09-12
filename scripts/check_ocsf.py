import json
from pathlib import Path

extracted = Path("F:/My Project/Baraq/tmp_data/extracted/compound_zips")
jsons = list(extracted.rglob("*.json"))[:3]

for jf in jsons:
    print(f"=== {jf.name} ===")
    content = jf.read_text(encoding="utf-8", errors="replace").strip()
    if content.startswith("["):
        data = json.loads(content)
    else:
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        data = [json.loads(l) for l in lines[:5]]
    if isinstance(data, list) and data:
        item = data[0]
    elif isinstance(data, dict):
        item = data
    else:
        continue
    print(f"Top keys: {list(item.keys())[:20]}")
    # Check nested structures
    for key in ["process", "network", "dns", "http", "user", "host", "source",
                "class_name", "category_name", "activity_id", "category_uid",
                "time", "@timestamp", "timestamp", "message", "scenario",
                "attack"]:
        if key in item:
            val = item[key]
            if isinstance(val, dict):
                print(f"  {key} (dict): {list(val.keys())[:10]}")
            elif isinstance(val, str) and len(val) > 100:
                print(f"  {key}: {val[:100]}...")
            else:
                print(f"  {key}: {val}")
    print()
