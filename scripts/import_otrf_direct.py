"""Direct OTRF import via ZIP download — avoids GitHub API rate limits."""

import os, sys, tempfile, zipfile, json, logging, time
from pathlib import Path

os.chdir(Path(__file__).resolve().parent.parent)
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("otrf_direct")

def main():
    import urllib.request
    from backend.database.connection import SessionLocal, engine
    from backend.database.models import NormalizedEvent, Verdict, Base, utcnow
    from backend.ml.dataset_adapters import ADAPTERS
    from datetime import UTC, datetime

    adapter = ADAPTERS["security_datasets"]()

    # Use a known small atomic dataset ZIP from OTRF
    zip_urls = [
        "https://github.com/OTRF/Security-Datasets/archive/refs/heads/master.zip",
    ]

    tmp = Path(tempfile.mkdtemp(prefix="otrf_"))
    zip_path = tmp / "otrf.zip"

    for url in zip_urls:
        log.info("Downloading: %s", url)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "BARAQ/1.0"})
            with urllib.request.urlopen(req, timeout=300) as resp:
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                with open(zip_path, "wb") as f:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total > 0 and downloaded % (1024*1024) == 0:
                            log.info("  Downloaded %d / %d MB", downloaded // (1024*1024), total // (1024*1024))
            log.info("Download complete: %d MB", downloaded // (1024*1024))
            break
        except Exception as e:
            log.warning("Download failed: %s", e)
            continue
    else:
        log.error("All downloads failed")
        return

    # Parse via adapter
    log.info("Parsing via adapter...")
    result = adapter.load(str(zip_path), max_events=50000)
    events = result["events"]
    log.info("Parsed: total=%d loaded=%d skipped=%d errors=%d",
             result["total"], result["loaded"], result["skipped"], len(result["errors"]))

    if not events:
        log.error("No events parsed!")
        return

    # Load into DB
    log.info("Loading %d events into database...", len(events))
    session = SessionLocal()
    batch_size = 500
    inserted = 0
    try:
        for i in range(0, len(events), batch_size):
            batch = events[i:i+batch_size]
            for ev in batch:
                ts = ev.get("timestamp")
                if isinstance(ts, str):
                    try:
                        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except (ValueError, TypeError):
                        ts = datetime.now(UTC)
                if ts is None:
                    ts = datetime.now(UTC)

                ne = NormalizedEvent(
                    event_id=str(ev.get("event_id", "")),
                    category=ev.get("category", ""),
                    source=ev.get("source", "otrf_security_datasets"),
                    user=ev.get("user", ""),
                    host=ev.get("host", ""),
                    severity=ev.get("severity", "medium"),
                    message=ev.get("message", ""),
                    timestamp=ts,
                    raw_json=json.dumps(ev, default=str)[:10000],
                    org="",
                )
                session.add(ne)
                inserted += 1

            session.commit()
            if inserted % 2000 == 0:
                log.info("  Inserted %d / %d", inserted, len(events))

        log.info("Done! Inserted %d events into NormalizedEvent", inserted)

        # Create verdicts for labeled events
        labeled = 0
        for ev in events:
            label = ev.get("label")
            if label is not None and ev.get("_event_id_for_verdict"):
                v = Verdict(
                    event_id=ev["_event_id_for_verdict"],
                    verdict="true_positive" if label == 1 else "false_positive",
                    note="OTRF dataset label",
                )
                session.add(v)
                labeled += 1
        session.commit()
        log.info("Created %d verdict labels", labeled)

    finally:
        session.close()

    # Stats
    with engine.connect() as conn:
        from sqlalchemy import select, func
        count = conn.scalar(select(func.count(NormalizedEvent.id)))
        log.info("Total events in DB: %d", count)

if __name__ == "__main__":
    main()
