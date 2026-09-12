"""Load ALL OTRF data: atomic JSON + compound ZIPs + compound logs + BOTES CSVs.
Target: 100k+ real events.
"""
import os, sys, json, hashlib, logging, time, zipfile, csv
from pathlib import Path
from datetime import UTC, datetime

os.chdir(Path(__file__).resolve().parent.parent)
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("load_all")

OTRF = Path("F:/My Project/Baraq/tmp_data/otrf/datasets")
BOTES = Path("F:/My Project/Baraq/tmp_data/botes")
TMP = Path("F:/My Project/Baraq/tmp_data/extracted")
TMP.mkdir(exist_ok=True)

def insert_events(events, source, session):
    from backend.database.models import NormalizedEvent, Verdict
    inserted = 0
    verdicts = 0
    for ev in events:
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
            source=source,
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
                note=f"Real labeled data from {source}",
            )
            session.add(v)
            verdicts += 1

    session.commit()
    return inserted, verdicts

def extract_compound_zips():
    """Extract .zip files inside compound datasets."""
    extract_dir = TMP / "compound_zips"
    extract_dir.mkdir(exist_ok=True)
    zip_files = list((OTRF / "compound").rglob("*.zip"))
    log.info("Found %d ZIP files in compound, extracting...", len(zip_files))
    extracted_count = 0
    for zf in zip_files:
        try:
            with zipfile.ZipFile(zf, "r") as z:
                z.extractall(extract_dir / zf.stem)
            extracted_count += 1
        except Exception as e:
            pass
    log.info("Extracted %d ZIPs", extracted_count)
    return extract_dir

def load_compound_logs():
    """Parse .log files from compound datasets (they're JSON lines)."""
    from backend.ml.dataset_adapters import ADAPTERS as _ADAPTERS
    adapter = _ADAPTERS["security_datasets"]()
    all_events = []
    log_files = list((OTRF / "compound").rglob("*.log"))
    log.info("Parsing %d .log files from compound...", len(log_files))
    for lf in log_files:
        try:
            content = lf.read_text(encoding="utf-8", errors="replace").strip()
            if not content:
                continue
            raw_events = []
            if content.startswith("["):
                raw_events = json.loads(content)
            else:
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            raw_events.append(obj)
                    except json.JSONDecodeError:
                        continue

            for raw in raw_events:
                if isinstance(raw, dict):
                    parsed = adapter.parse_event(raw)
                    if parsed:
                        all_events.append(parsed)
        except:
            continue
    log.info("Compound logs: %d events parsed", len(all_events))
    return all_events

def load_botes_csvs():
    """Parse BOTES CSV mapping files."""
    csv_files = list((BOTES / "botes-csv-map").rglob("*.csv"))
    log.info("Parsing %d BOTES CSV files...", len(csv_files))
    all_events = []
    for cf in csv_files:
        try:
            with open(cf, encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if not row:
                        continue
                    # Map CSV row to a basic event
                    event = {
                        "event_id": 0,
                        "channel": row.get("source", cf.stem),
                        "timestamp": row.get("time", row.get("@timestamp", "")),
                        "host": row.get("host", row.get("host.name", "")),
                        "user": row.get("user", row.get("user.name", "")),
                        "message": row.get("message", row.get("event.original", "")),
                        "source_ip": row.get("source.ip", row.get("source_ip", "")),
                        "source": "other",
                        "label": 0,
                        "raw": dict(row),
                    }
                    if event["timestamp"]:
                        all_events.append(event)
        except:
            continue
    log.info("BOTES CSVs: %d events parsed", len(all_events))
    return all_events


def main():
    from backend.ml.dataset_adapters import ADAPTERS
    from backend.database.connection import SessionLocal, engine
    from backend.database.models import NormalizedEvent, Verdict
    from sqlalchemy import select, func

    session = SessionLocal()
    grand_total = 0
    grand_verdicts = 0

    # ═══ SOURCE 1: OTRF Atomic JSON ═══
    log.info("=" * 60)
    log.info("SOURCE 1: OTRF Atomic (JSON)")
    log.info("=" * 60)
    adapter = ADAPTERS["security_datasets"]()
    t0 = time.time()
    atomic = adapter.load(OTRF / "atomic", max_events=500000)
    log.info("Atomic: total=%d loaded=%d (%.1fs)", atomic["total"], atomic["loaded"], time.time()-t0)
    if atomic["events"]:
        ins, vids = insert_events(atomic["events"], "otrf_atomic", session)
        grand_total += ins
        grand_verdicts += vids
        log.info("  Inserted %d events, %d verdicts", ins, vids)

    # ═══ SOURCE 2: OTRF Compound ZIPs → extract & parse ═══
    log.info("=" * 60)
    log.info("SOURCE 2: OTRF Compound (extract ZIPs + parse)")
    log.info("=" * 60)
    extract_dir = extract_compound_zips()
    # Check what was extracted
    json_files = list(extract_dir.rglob("*.json"))
    jsonl_files = list(extract_dir.rglob("*.jsonl"))
    log.info("Extracted: %d JSON + %d JSONL files", len(json_files), len(jsonl_files))
    if json_files or jsonl_files:
        compound_extracted = adapter.load(extract_dir, max_events=500000)
        log.info("Compound extracted: total=%d loaded=%d", compound_extracted["total"], compound_extracted["loaded"])
        if compound_extracted["events"]:
            ins, vids = insert_events(compound_extracted["events"], "otrf_compound", session)
            grand_total += ins
            grand_verdicts += vids
            log.info("  Inserted %d events, %d verdicts", ins, vids)

    # ═══ SOURCE 3: OTRF Compound .log files ═══
    log.info("=" * 60)
    log.info("SOURCE 3: OTRF Compound (.log files)")
    log.info("=" * 60)
    compound_logs = load_compound_logs()
    if compound_logs:
        ins, vids = insert_events(compound_logs, "otrf_compound_log", session)
        grand_total += ins
        grand_verdicts += vids
        log.info("  Inserted %d events, %d verdicts", ins, vids)

    # ═══ SOURCE 4: BOTES CSVs ═══
    log.info("=" * 60)
    log.info("SOURCE 4: BOTES CSV mappings")
    log.info("=" * 60)
    botes_events = load_botes_csvs()
    if botes_events:
        ins, vids = insert_events(botes_events, "botes", session)
        grand_total += ins
        grand_verdicts += vids
        log.info("  Inserted %d events, %d verdicts", ins, vids)

    # ═══ FINAL STATS ═══
    with engine.connect() as conn:
        total = conn.scalar(select(func.count(NormalizedEvent.id)))
        v_total = conn.scalar(select(func.count(Verdict.id)))
        sources = conn.execute(
            select(NormalizedEvent.source, func.count(NormalizedEvent.id))
            .group_by(NormalizedEvent.source)
            .order_by(func.count(NormalizedEvent.id).desc())
        ).fetchall()

    log.info("=" * 60)
    log.info("COMPLETE")
    log.info("  Inserted this run: %d events, %d verdicts", grand_total, grand_verdicts)
    log.info("  Total in DB: %d events, %d verdicts", total, v_total)
    log.info("  By source:")
    for src, cnt in sources:
        log.info("    %s: %d", src, cnt)
    log.info("=" * 60)

    session.close()

if __name__ == "__main__":
    main()
