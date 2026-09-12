import os, sys, json
os.chdir(r"F:\My Project\Baraq")
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"
from backend.database.connection import engine
from sqlalchemy import text

with engine.connect() as c:
    rows = c.execute(text("SELECT raw_json, message FROM events WHERE source='otrf_compound' LIMIT 3")).fetchall()
    for i, row in enumerate(rows):
        print(f"=== Event {i+1} ===")
        print(f"Message: {str(row[1])[:200]}")
        try:
            d = json.loads(row[0]) if row[0] else {}
            print(f"Keys: {list(d.keys())[:20]}")
            for k in list(d.keys())[:10]:
                v = d[k]
                if isinstance(v, str) and len(v) > 100:
                    v = v[:100] + "..."
                print(f"  {k}: {v}")
        except:
            print(f"Raw (first 300): {str(row[0])[:300]}")
        print()

    # Also check atomic
    rows2 = c.execute(text("SELECT raw_json, message FROM events WHERE source='otrf_atomic' LIMIT 2")).fetchall()
    for i, row in enumerate(rows2):
        print(f"=== Atomic Event {i+1} ===")
        print(f"Message: {str(row[1])[:200]}")
        try:
            d = json.loads(row[0]) if row[0] else {}
            print(f"Keys: {list(d.keys())[:20]}")
            for k in list(d.keys())[:10]:
                v = d[k]
                if isinstance(v, str) and len(v) > 100:
                    v = v[:100] + "..."
                print(f"  {k}: {v}")
        except:
            print(f"Raw (first 300): {str(row[0])[:300]}")
        print()
