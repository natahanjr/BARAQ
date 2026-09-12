"""Load OTRF Security-Datasets (already cloned locally) into DB.
577 MB, 493 files of real attack data.
"""
import os, sys, json, hashlib, logging, time
from pathlib import Path
from datetime import UTC, datetime

os.chdir(Path(__file__).resolve().parent.parent)
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("otrf_load")

OTRF_DIR = Path("F:/My Project/Baraq/tmp_data/otrf/datasets")

def main():
    from backend.ml.dataset_adapters import ADAPTERS
    from backend.database.connection import SessionLocal, engine
    from backend.database.models import NormalizedEvent, Verdict
    from sqlalchemy import select, func

    adapter = ADAPTERS["security_datasets"]()

    # Load atomic datasets
    log.info("=" * 60)
    log.info("Loading OTRF Atomic datasets...")
    t0 = time.time()
    atomic_result = adapter.load(OTRF_DIR / "atomic", max_events=500000)
    log.info("Atomic: total=%d loaded=%d skipped=%d errors=%d (%.1fs)",
             atomic_result["total"], atomic_result["loaded"],
             atomic_result["skipped"], len(atomic_result["errors"]),
             time.time() - t0)

    # Load compound datasets
    log.info("Loading OTRF Compound datasets...")
    t0 = time.time()
    compound_result = adapter.load(OTRF_DIR / "compound", max_events=500000)
    log.info("Compound: total=%d loaded=%d skipped=%d errors=%d (%.1fs)",
             compound_result["total"], compound_result["loaded"],
             compound_result["skipped"], len(compound_result["errors"]),
             time.time() - t0)

    all_events = atomic_result["events"] + compound_result["events"]
    log.info("Total events to insert: %d", len(all_events))

    if not all_events:
        log.error("No events parsed!")
        return

    # Insert into DB
    log.info("Inserting into database...")
    session = SessionLocal()
    inserted = 0
    verdicts = 0
    batch_size = 500

    for i in range(0, len(all_events), batch_size):
        batch = all_events[i:i+batch_size]
        for ev in batch:
            ts_raw = ev.get("timestamp")
            if isinstance(ts_raw, str):
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                except:
                    ts = datetime.now(UTC)
            elif isinstance(ts_raw, datetime):
                ts = ts_raw if ts_raw.tzinfo else ts_raw.replace(tzinfo=UTC)
            else:
                ts = datetime.now(UTC)

            label = ev.get("label", 0)
            raw_dict = ev.get("raw", {})
            if not isinstance(raw_dict, dict):
                raw_dict = {}
            raw_dict["source_ip"] = ev.get("source_ip", "")
            raw_dict["channel"] = ev.get("channel", "")

            ne = NormalizedEvent(
                event_id=int(ev.get("event_id", 0) or 0),
                category=ev.get("source", "other"),
                source="otrf_security_datasets",
                user=ev.get("user", ""),
                host=ev.get("host", ""),
                severity="high" if label else "info",
                message=str(ev.get("message", ""))[:1024],
                timestamp=ts,
                raw_json=json.dumps(raw_dict, default=str)[:10000],
                org="",
            )
            session.add(ne)
            inserted += 1

            if label:
                v = Verdict(
                    event_id=ne.id,
                    verdict="true_positive",
                    confidence=0.95,
                    analyst="otrf_import",
                    note="OTRF labeled attack dataset",
                )
                session.add(v)
                verdicts += 1

        session.commit()
        if inserted % 5000 == 0:
            log.info("  %d / %d inserted...", inserted, len(all_events))

    log.info("Inserted %d events, %d verdicts", inserted, verdicts)

    # Stats by attack scenario
    with engine.connect() as conn:
        total = conn.scalar(select(func.count(NormalizedEvent.id)))
        v_total = conn.scalar(select(func.count(Verdict.id)))
        sources = conn.execute(
            select(NormalizedEvent.source, func.count(NormalizedEvent.id))
            .group_by(NormalizedEvent.source)
            .order_by(func.count(NormalizedEvent.id).desc())
        ).fetchall()
        severities = conn.execute(
            select(NormalizedEvent.severity, func.count(NormalizedEvent.id))
            .group_by(NormalizedEvent.severity)
            .order_by(func.count(NormalizedEvent.id).desc())
        ).fetchall()

    log.info("=" * 60)
    log.info("DATABASE STATUS:")
    log.info("  Total events: %d", total)
    log.info("  Total verdicts: %d", v_total)
    log.info("  By source:")
    for src, cnt in sources:
        log.info("    %s: %d", src, cnt)
    log.info("  By severity:")
    for sev, cnt in severities:
        log.info("    %s: %d", sev, cnt)
    log.info("=" * 60)

    session.close()

if __name__ == "__main__":
    main()
