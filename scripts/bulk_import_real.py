"""Bulk real-data import: OTRF Security-Datasets + BOTES + BOTSv1.

Downloads full repo ZIPs (no GitHub API rate limits), parses via adapters,
and loads into NormalizedEvent + Verdict tables.
Target: 100k+ real labeled events.
"""

import os, sys, json, tempfile, zipfile, shutil, logging, time, hashlib
from pathlib import Path
from datetime import UTC, datetime

os.chdir(Path(__file__).resolve().parent.parent)
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("bulk_import")

# ── Download helpers ──────────────────────────────────────────────

def download_zip(url: str, dest: Path, label: str) -> Path | None:
    """Download a ZIP file from GitHub. Returns path or None."""
    import urllib.request, urllib.error
    zip_path = dest / f"{label}.zip"
    log.info("[%s] Downloading %s", label, url)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BARAQ/1.0"})
        with urllib.request.urlopen(req, timeout=600) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            last_pct = 0
            with open(zip_path, "wb") as f:
                while True:
                    chunk = resp.read(131072)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total > 0:
                        pct = int((downloaded / total) * 100)
                        if pct >= last_pct + 10:
                            log.info("[%s] %d%% (%d MB)", label, pct, downloaded // (1024*1024))
                            last_pct = pct
        log.info("[%s] Downloaded %d MB", label, downloaded // (1024*1024))
        return zip_path
    except Exception as e:
        log.error("[%s] Download failed: %s", label, e)
        return None


def extract_zip(zip_path: Path, dest: Path) -> Path:
    """Extract ZIP and return the extracted directory."""
    log.info("Extracting %s ...", zip_path.name)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest)
    # Find the top-level directory (usually repo-branch/)
    dirs = [d for d in dest.iterdir() if d.is_dir()]
    if len(dirs) == 1:
        return dirs[0]
    return dest


# ── Dataset sources ───────────────────────────────────────────────

DATASETS = [
    {
        "name": "OTRF Security-Datasets",
        "label": "otrf",
        "urls": [
            "https://github.com/OTRF/Security-Datasets/archive/refs/heads/master.zip",
        ],
        "adapter": "security_datasets",
    },
    {
        "name": "BOTES (Boss of Elastic SOC)",
        "label": "botes",
        "urls": [
            "https://github.com/Seblhd/BOTES/archive/refs/heads/main.zip",
        ],
        "adapter": "botes",
    },
    {
        "name": "BOTSv1 (Splunk)",
        "label": "botsv1",
        "urls": [
            "https://github.com/splunk/botsv1/archive/refs/heads/master.zip",
        ],
        "adapter": "botsv1",
    },
]


# ── DB insert ─────────────────────────────────────────────────────

def insert_events(events: list, source_label: str, session) -> tuple[int, int]:
    """Insert normalized events into DB. Returns (inserted, verdicts_created)."""
    from backend.database.models import NormalizedEvent, Verdict
    from sqlalchemy import text as sa_text

    inserted = 0
    verdicts = 0
    batch_size = 500

    for i in range(0, len(events), batch_size):
        batch = events[i:i+batch_size]
        for ev in batch:
            ts_raw = ev.get("timestamp")
            if isinstance(ts_raw, str):
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    ts = datetime.now(UTC)
            elif isinstance(ts_raw, datetime):
                ts = ts_raw if ts_raw.tzinfo else ts_raw.replace(tzinfo=UTC)
            else:
                ts = datetime.now(UTC)

            event_id = ev.get("event_id", 0)
            channel = ev.get("channel", "")
            host = ev.get("host", "")
            user = ev.get("user", "")
            message = ev.get("message", "")
            source_ip = ev.get("source_ip", "")
            source_stream = ev.get("source", source_label)
            attack_chain = ev.get("attack_chain")
            stage = ev.get("stage")
            raw_facts = ev.get("raw", {})
            label_val = ev.get("label", 0)

            ne = NormalizedEvent(
                event_id=int(event_id) if event_id else 0,
                category=source_stream or "other",
                source=source_label,
                channel=channel,
                user=user,
                host=host,
                severity="high" if label_val else "info",
                message=message[:1024] if message else "",
                timestamp=ts,
                source_ip=source_ip or "",
                raw_json=json.dumps({
                    "event_id": event_id,
                    "channel": channel,
                    "source_ip": source_ip,
                    "attack_chain": attack_chain,
                    "stage": stage,
                    **(raw_facts if isinstance(raw_facts, dict) else {}),
                }, default=str)[:10000],
                org="",
            )
            session.add(ne)
            inserted += 1

            if label_val:
                fp_key = f"{ts.isoformat()}-{event_id}-{host}-{message[:128]}"
                fp = hashlib.sha256(fp_key.encode()).hexdigest()[:16]
                v = Verdict(
                    event_id=ne.id,
                    verdict="true_positive" if label_val == 1 else "benign",
                    confidence=0.95,
                    analyst="otrf_dataset_import",
                    note=f"OTRF label from {source_label}",
                )
                session.add(v)
                verdicts += 1

        session.commit()
        if inserted % 2000 == 0:
            log.info("  ... %d events inserted", inserted)

    return inserted, verdicts


# ── Main ──────────────────────────────────────────────────────────

def main():
    from backend.database.connection import SessionLocal, engine
    from backend.database.models import NormalizedEvent
    from backend.ml.dataset_adapters import ADAPTERS
    from sqlalchemy import select, func

    tmp_base = Path(tempfile.mkdtemp(prefix="baraq_bulk_"))

    total_inserted = 0
    total_verdicts = 0

    for ds in DATASETS:
        label = ds["label"]
        adapter = ADAPTERS[ds["adapter"]]

        # Try each URL
        zip_path = None
        for url in ds["urls"]:
            ds_dir = tmp_base / label
            ds_dir.mkdir(exist_ok=True)
            zip_path = download_zip(url, ds_dir, label)
            if zip_path:
                break

        if not zip_path:
            log.error("[%s] All downloads failed, skipping", label)
            continue

        # Extract
        extract_dir = tmp_base / f"{label}_extracted"
        extract_dir.mkdir(exist_ok=True)
        extracted = extract_zip(zip_path, extract_dir)

        # Parse via adapter
        log.info("[%s] Parsing via adapter: %s", label, ds["adapter"])
        t0 = time.time()
        result = adapter.load(extracted, max_events=200000)
        elapsed = time.time() - t0
        log.info("[%s] Parsed in %.1fs: total=%d loaded=%d skipped=%d errors=%d",
                 label, elapsed, result["total"], result["loaded"],
                 result["skipped"], len(result["errors"]))

        events = result["events"]
        if not events:
            log.warning("[%s] No events parsed, skipping DB insert", label)
            continue

        # Insert into DB
        log.info("[%s] Inserting %d events into DB...", label, len(events))
        session = SessionLocal()
        try:
            ins, vids = insert_events(events, label, session)
            total_inserted += ins
            total_verdicts += vids
            log.info("[%s] Inserted %d events, %d verdicts", label, ins, vids)
        finally:
            session.close()

    # Final stats
    with engine.connect() as conn:
        count = conn.scalar(select(func.count(NormalizedEvent.id)))

    log.info("=" * 60)
    log.info("BULK IMPORT COMPLETE")
    log.info("Total events inserted this run: %d", total_inserted)
    log.info("Total verdicts created: %d", total_verdicts)
    log.info("Total events in DB: %d", count)
    log.info("=" * 60)

    # Cleanup
    shutil.rmtree(tmp_base, ignore_errors=True)


if __name__ == "__main__":
    main()
