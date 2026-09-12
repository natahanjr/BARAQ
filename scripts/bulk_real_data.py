"""Download ALL real SOC datasets from multiple sources into DB.
Sources: OTRF Security-Datasets, BOTES, BOTSv1, plus OTRF repo full scan.
"""
import os, sys, json, tempfile, zipfile, shutil, logging, time, hashlib, csv
from pathlib import Path
from datetime import UTC, datetime

os.chdir(Path(__file__).resolve().parent.parent)
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("bulk")

def download_file(url, dest, label=""):
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BARAQ/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
            dest.write_bytes(data)
            return len(data)
    except Exception as e:
        log.warning("[%s] Failed %s: %s", label, url[:80], str(e)[:100])
        return 0

def extract_zip_to(zip_path, dest):
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest)
    dirs = [d for d in dest.iterdir() if d.is_dir()]
    return dirs[0] if len(dirs) == 1 else dest

def insert_batch(events, source, session):
    from backend.database.models import NormalizedEvent, Verdict
    inserted = 0
    verdicts = 0
    for ev in events:
        ts_raw = ev.get("timestamp")
        if isinstance(ts_raw, str):
            try: ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except: ts = datetime.now(UTC)
        elif isinstance(ts_raw, datetime):
            ts = ts_raw if ts_raw.tzinfo else ts_raw.replace(tzinfo=UTC)
        else:
            ts = datetime.now(UTC)

        label = ev.get("label", 0)
        ne = NormalizedEvent(
            event_id=int(ev.get("event_id", 0) or 0),
            category=ev.get("source", "other"),
            source=source,
            channel=ev.get("channel", ""),
            user=ev.get("user", ""),
            host=ev.get("host", ""),
            severity="high" if label else "info",
            message=str(ev.get("message", ""))[:1024],
            timestamp=ts,
            source_ip=ev.get("source_ip", ""),
            raw_json=json.dumps(ev.get("raw", {}), default=str)[:10000],
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

def main():
    from backend.ml.dataset_adapters import ADAPTERS
    from backend.database.connection import SessionLocal, engine
    from backend.database.models import NormalizedEvent
    from sqlalchemy import select, func
    import urllib.request

    tmp = Path(tempfile.mkdtemp(prefix="barq_real_"))
    session = SessionLocal()
    grand_total = 0
    grand_verdicts = 0

    # ════════════════════════════════════════════════════════════════
    # SOURCE 1: OTRF Security-Datasets — download individual files
    # ════════════════════════════════════════════════════════════════
    log.info("=" * 60)
    log.info("SOURCE 1: OTRF Security-Datasets (individual files)")
    log.info("=" * 60)

    # Get full file tree
    tree_url = "https://api.github.com/repos/OTRF/Security-Datasets/git/trees/master?recursive=1"
    req = urllib.request.Request(tree_url, headers={"User-Agent": "BARAQ/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        tree_data = json.loads(resp.read())

    all_files = tree_data.get("tree", [])
    # Get ALL data files (json, csv, jsonl, log)
    data_exts = (".json", ".jsonl", ".csv", ".log")
    data_files = [f for f in all_files if f.get("type") == "blob"
                  and any(f["path"].endswith(ext) for ext in data_exts)
                  and f.get("size", 0) > 100]  # Skip tiny files
    log.info("Found %d data files in OTRF", len(data_files))

    # Sort by size, download largest first
    data_files.sort(key=lambda x: x.get("size", 0), reverse=True)

    # Download files that fit within ~500MB total
    max_download_bytes = 500 * 1024 * 1024
    downloaded_bytes = 0
    otrf_dir = tmp / "otrf"
    otrf_dir.mkdir(exist_ok=True)

    downloaded_files = []
    for f in data_files:
        if downloaded_bytes >= max_download_bytes:
            break
        if f.get("size", 0) > 50 * 1024 * 1024:  # Skip files > 50MB
            continue
        downloaded_files.append(f)

    log.info("Downloading %d files (up to 500MB)...", len(downloaded_files))
    for i, f in enumerate(downloaded_files):
        path = f["path"]
        raw_url = f"https://raw.githubusercontent.com/OTRF/Security-Datasets/master/{path}"
        safe_name = path.replace("/", "_")
        local = otrf_dir / safe_name
        size = download_file(raw_url, local, "otrf")
        downloaded_bytes += size
        if (i + 1) % 20 == 0:
            log.info("  Downloaded %d/%d (%d MB)", i + 1, len(downloaded_files), downloaded_bytes // (1024*1024))

    log.info("OTRF: Downloaded %d files, %.1f MB", len(downloaded_files), downloaded_bytes / (1024*1024))

    # Parse OTRF files
    adapter = ADAPTERS["security_datasets"]()
    log.info("Parsing OTRF files...")
    otrf_result = adapter.load(otrf_dir, max_events=200000)
    log.info("OTRF parsed: total=%d loaded=%d skipped=%d errors=%d",
             otrf_result["total"], otrf_result["loaded"],
             otrf_result["skipped"], len(otrf_result["errors"]))

    if otrf_result["events"]:
        ins, vids = insert_batch(otrf_result["events"], "otrf", session)
        grand_total += ins
        grand_verdicts += vids
        log.info("OTRF: Inserted %d events, %d verdicts", ins, vids)

    # ════════════════════════════════════════════════════════════════
    # SOURCE 2: BOTES — download ZIP
    # ════════════════════════════════════════════════════════════════
    log.info("=" * 60)
    log.info("SOURCE 2: BOTES (Boss of Elastic SOC)")
    log.info("=" * 60)

    botes_zip = tmp / "botes.zip"
    url = "https://github.com/Seblhd/BOTES/archive/refs/heads/main.zip"
    size = download_file(url, botes_zip, "botes")
    if size > 0:
        botes_ext = tmp / "botes_ext"
        botes_ext.mkdir(exist_ok=True)
        botes_root = extract_zip_to(botes_zip, botes_ext)
        log.info("BOTES extracted to %s", botes_root)

        botes_adapter = ADAPTERS["botes"]()
        botes_result = botes_adapter.load(botes_root, max_events=200000)
        log.info("BOTES parsed: total=%d loaded=%d skipped=%d errors=%d",
                 botes_result["total"], botes_result["loaded"],
                 botes_result["skipped"], len(botes_result["errors"]))

        if botes_result["events"]:
            ins, vids = insert_batch(botes_result["events"], "botes", session)
            grand_total += ins
            grand_verdicts += vids
            log.info("BOTES: Inserted %d events, %d verdicts", ins, vids)
    else:
        log.warning("BOTES download failed, skipping")

    # ════════════════════════════════════════════════════════════════
    # SOURCE 3: BOTSv1 — download ZIP
    # ════════════════════════════════════════════════════════════════
    log.info("=" * 60)
    log.info("SOURCE 3: BOTSv1 (Splunk)")
    log.info("=" * 60)

    botsv1_zip = tmp / "botsv1.zip"
    url = "https://github.com/splunk/botsv1/archive/refs/heads/master.zip"
    size = download_file(url, botsv1_zip, "botsv1")
    if size > 0:
        botsv1_ext = tmp / "botsv1_ext"
        botsv1_ext.mkdir(exist_ok=True)
        botsv1_root = extract_zip_to(botsv1_zip, botsv1_ext)
        log.info("BOTSv1 extracted to %s", botsv1_root)

        botsv1_adapter = ADAPTERS["botsv1"]()
        botsv1_result = botsv1_adapter.load(botsv1_root, max_events=200000)
        log.info("BOTSv1 parsed: total=%d loaded=%d skipped=%d errors=%d",
                 botsv1_result["total"], botsv1_result["loaded"],
                 botsv1_result["skipped"], len(botsv1_result["errors"]))

        if botsv1_result["events"]:
            ins, vids = insert_batch(botsv1_result["events"], "botsv1", session)
            grand_total += ins
            grand_verdicts += vids
            log.info("BOTSv1: Inserted %d events, %d verdicts", ins, vids)
    else:
        log.warning("BOTSv1 download failed, skipping")

    # ════════════════════════════════════════════════════════════════
    # FINAL STATS
    # ════════════════════════════════════════════════════════════════
    with engine.connect() as conn:
        total = conn.scalar(select(func.count(NormalizedEvent.id)))
        verdict_count = conn.scalar(select(func.count(Verdict.id)))

    log.info("=" * 60)
    log.info("BULK REAL-DATA IMPORT COMPLETE")
    log.info("Inserted this run: %d events", grand_total)
    log.info("Verdicts created: %d", grand_verdicts)
    log.info("Total events in DB: %d", total)
    log.info("Total verdicts in DB: %d", verdict_count)
    log.info("=" * 60)

    session.close()
    shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    main()
