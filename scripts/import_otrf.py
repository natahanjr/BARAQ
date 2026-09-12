"""Import OTRF Security-Datasets into BARAQ (runs standalone, no server needed)."""

import sys
import os
import time
import logging

# Ensure we're in the project root
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ".")

# Set up env before importing backend
os.environ.setdefault("BARAQ_DATABASE_URL", "postgresql+psycopg://postgres:password@127.0.0.1:55432/baraq")
os.environ.setdefault("BARAQ_TELEMETRY_V2", "1")
os.environ.setdefault("BARAQ_NO_SCHEDULER", "1")

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
log = logging.getLogger("import_otrf")

def main():
    from backend.ml.dataset_import import ImportManager, DATASET_SOURCES

    mgr = ImportManager()

    print("\n=== Available Datasets ===")
    for src in mgr.list_sources():
        print(f"  {src['id']:35s} {src['name']}")

    # Start import of OTRF Security-Datasets (atomic attack scenarios — smaller, faster)
    dataset = "security_datasets_atomic"
    max_events = 50000

    print(f"\n=== Starting Import: {dataset} (max {max_events} events) ===")
    task = mgr.start_import(dataset, max_events=max_events)
    print(f"Task ID: {task.task_id}")

    # Poll progress
    while task.status.value not in ("completed", "failed", "cancelled"):
        time.sleep(5)
        t = mgr.get_task(task.task_id)
        if t:
            print(f"  [{t.status.value}] progress={t.progress:.1f}% "
                  f"loaded={t.loaded_events} skipped={t.skipped_events} "
                  f"errors={len(t.errors)}")
        else:
            break

    t = mgr.get_task(task.task_id)
    print(f"\n=== Import Complete ===")
    print(f"  Status: {t.status.value}")
    print(f"  Loaded: {t.loaded_events} events")
    print(f"  Skipped: {t.skipped_events}")
    print(f"  Errors: {len(t.errors)}")
    if t.errors:
        for e in t.errors[:5]:
            print(f"    - {e}")

    return t.status.value == "completed"

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
