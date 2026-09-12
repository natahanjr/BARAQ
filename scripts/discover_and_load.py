"""Step 1: Discover how many real events are available from OTRF."""
import urllib.request, json, time, os, sys, tempfile, shutil
from pathlib import Path

os.chdir(Path(__file__).resolve().parent.parent)
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"

import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("discover")

# Step 1: List all JSON files in OTRF via Trees API
log.info("Listing OTRF files via GitHub Trees API...")
url = "https://api.github.com/repos/OTRF/Security-Datasets/git/trees/master?recursive=1"
req = urllib.request.Request(url, headers={"User-Agent": "BARAQ/1.0", "Accept": "application/vnd.github.v3+json"})
with urllib.request.urlopen(req, timeout=60) as resp:
    data = json.loads(resp.read())

tree = data.get("tree", [])
jsons = [t for t in tree if t.get("type") == "blob" and t["path"].endswith(".json") and t["path"].startswith("datasets/")]
log.info("Total JSON files: %d", len(jsons))

# Group by attack scenario
scenarios = {}
for t in jsons:
    parts = t["path"].split("/")
    # datasets/atomic/windows/credential_access/... or datasets/...
    if len(parts) >= 4:
        scenario = parts[3] if parts[1] == "atomic" else parts[1]
    else:
        scenario = "other"
    scenarios.setdefault(scenario, []).append(t)

log.info("Scenarios found:")
for s, files in sorted(scenarios.items(), key=lambda x: -len(x[1])):
    total_kb = sum(f.get("size", 0) for f in files) / 1024
    log.info("  %s: %d files (%.0f KB)", s, len(files), total_kb)

# Step 2: Download the largest non-atomic files first (they have more events)
non_atomic = [t for t in jsons if "/atomic/" not in t["path"]]
atomic = [t for t in jsons if "/atomic/" in t["path"]]

log.info("Non-atomic files: %d (%.1f MB)", len(non_atomic), sum(t.get("size",0) for t in non_atomic)/(1024*1024))
log.info("Atomic files: %d (%.1f MB)", len(atomic), sum(t.get("size",0) for t in atomic)/(1024*1024))

# Download top 50 largest files (should give us plenty of events)
non_atomic.sort(key=lambda x: x.get("size", 0), reverse=True)
to_download = non_atomic[:50]
log.info("Will download top 50 non-atomic files")

tmp = Path(tempfile.mkdtemp(prefix="otrf_dl_"))
downloaded_dir = tmp / "files"
downloaded_dir.mkdir(exist_ok=True)

success = 0
failed = 0
for i, item in enumerate(to_download):
    path = item["path"]
    raw_url = f"https://raw.githubusercontent.com/OTRF/Security-Datasets/master/{path}"
    local_path = downloaded_dir / Path(path).name
    try:
        req = urllib.request.Request(raw_url, headers={"User-Agent": "BARAQ/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
            local_path.write_bytes(data)
        success += 1
        if (i + 1) % 10 == 0:
            log.info("Downloaded %d/%d", i + 1, len(to_download))
    except Exception as e:
        failed += 1
        log.warning("Failed %s: %s", path, str(e)[:80])
        time.sleep(1)

log.info("Downloaded: %d, Failed: %d", success, failed)

# Step 3: Parse via adapter
log.info("Parsing downloaded files...")
from backend.ml.dataset_adapters import ADAPTERS
adapter = ADAPTERS["security_datasets"]
result = adapter.load(downloaded_dir, max_events=200000)
log.info("Parsed: total=%d loaded=%d skipped=%d errors=%d", result["total"], result["loaded"], result["skipped"], len(result["errors"]))

# Step 4: Also download top atomic files
atomic.sort(key=lambda x: x.get("size", 0), reverse=True)
to_download_atomic = atomic[:30]
atomic_dir = tmp / "atomic"
atomic_dir.mkdir(exist_ok=True)

log.info("Downloading top 30 atomic files...")
for i, item in enumerate(to_download_atomic):
    path = item["path"]
    raw_url = f"https://raw.githubusercontent.com/OTRF/Security-Datasets/master/{path}"
    local_path = atomic_dir / Path(path).name
    try:
        req = urllib.request.Request(raw_url, headers={"User-Agent": "BARAQ/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            local_path.write_bytes(resp.read())
    except:
        pass

atomic_result = adapter.load(atomic_dir, max_events=50000)
log.info("Atomic parsed: total=%d loaded=%d", atomic_result["total"], atomic_result["loaded"])

all_events = result["events"] + atomic_result["events"]
log.info("Total combined events: %d", len(all_events))

# Step 5: Insert into DB
log.info("Inserting into database...")
from backend.database.connection import SessionLocal, engine
from backend.database.models import NormalizedEvent, Verdict
from sqlalchemy import text, func
import hashlib
from datetime import UTC, datetime

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
        else:
            ts = datetime.now(UTC)

        ne = NormalizedEvent(
            event_id=int(ev.get("event_id", 0) or 0),
            category=ev.get("source", "other"),
            source="otrf",
            channel=ev.get("channel", ""),
            user=ev.get("user", ""),
            host=ev.get("host", ""),
            severity="high" if ev.get("label") else "info",
            message=str(ev.get("message", ""))[:1024],
            timestamp=ts,
            source_ip=ev.get("source_ip", ""),
            raw_json=json.dumps(ev.get("raw", {}), default=str)[:10000],
            org="",
        )
        session.add(ne)
        inserted += 1

        if ev.get("label"):
            v = Verdict(
                event_id=ne.id,
                verdict="true_positive",
                confidence=0.95,
                analyst="otrf_import",
                note="OTRF labeled dataset",
            )
            session.add(v)
            verdicts += 1

    session.commit()
    if inserted % 2000 == 0:
        log.info("  %d inserted...", inserted)

log.info("Inserted %d events, %d verdicts", inserted, verdicts)

# Final count
with engine.connect() as conn:
    total = conn.scalar(select(func.count(NormalizedEvent.id)))
    log.info("Total events in DB: %d", total)

session.close()
shutil.rmtree(tmp, ignore_errors=True)
log.info("DONE")
