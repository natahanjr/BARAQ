"""Manual dataset sweep to catch up with raw events."""

from backend.database.connection import SessionLocal
from backend.dataset.collector import sweep

db = SessionLocal()
try:
    for i in range(5):
        result = sweep(db)
        c = result["collected"]
        d = result.get("deduplicated", 0)
        t = result["total"]
        print(f"Sweep {i+1}: collected={c}, dedup={d}, total={t}")
        if c == 0:
            break
    print("Done")
finally:
    db.close()
