"""Fleet-scale ingest load test for the BARAQ ingest channel.

Simulates ``--agents`` endpoint agents (each with its own X-Agent-Key)
posting realistic Windows telemetry batches to ``POST /api/ingest`` at a
sustained rate for ``--duration`` seconds, then reports throughput, latency
and detection lag.

The default profile mirrors the documented reference fleet: 1,000 agents
posting ~20 events every 15 s (~1,333 events/s sustained).

    venv\\Scripts\\python tools\\load_test_agents.py --server http://127.0.0.1:8010
    venv\\Scripts\\python tools\\load_test_agents.py --agents 1000 --duration 120 --attack-rate 0.005

The tool writes ``agent_configs/load_test_keys.json`` (the agent key map the
server must be started with via ``BARAQ_AGENT_KEYS``) and a JSON report
under ``reports/``.

Start the server under test with, e.g.:

    $env:BARAQ_DATABASE_URL="postgresql+psycopg://postgres@127.0.0.1:55432/baraq_load"
    $env:BARAQ_AGENT_KEYS=(Get-Content agent_configs\\load_test_keys.json -Raw)
    $env:BARAQ_INGEST_ASYNC_DETECT="1"
    venv\\Scripts\\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8010
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import random
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

KEYS_FILE = ROOT / "agent_configs" / "load_test_keys.json"
REPORT_DIR = ROOT / "reports"

# ---------------------------------------------------------------------------
# Record generators (benign Windows telemetry mix + attack bursts)
# ---------------------------------------------------------------------------

BENIGN_EVENT_IDS = [4624, 4624, 4688, 4688, 5156, 5156, 5156, 6005, 7036, 800, 100, 1]
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
PROCESSES = [
    "chrome.exe",
    "explorer.exe",
    "svchost.exe",
    "msedge.exe",
    "python.exe",
    "Teams.exe",
    "Spotify.exe",
    "winword.exe",
    "powershell.exe",
    "cmd.exe",
]


def _ts() -> str:
    return datetime.now(UTC).isoformat()


def _benign_record(i: int) -> dict:
    eid = BENIGN_EVENT_IDS[i % len(BENIGN_EVENT_IDS)]
    user = USERS[i % len(USERS)]
    if eid == 4688:
        return {
            "source": "eventlog",
            "channel": "Security",
            "event_id": 4688,
            "timestamp": _ts(),
            "user": user,
            "message": f"A new process has been created. New Process Name: {PROCESSES[i % len(PROCESSES)]}.",
            "raw": {
                "process_name": PROCESSES[i % len(PROCESSES)],
                "pid": 1000 + i % 30000,
            },
        }
    if eid == 5156:
        return {
            "source": "network",
            "pid": 1000 + i % 30000,
            "process": PROCESSES[i % len(PROCESSES)],
            "local_ip": "192.168.10.%d" % (10 + i % 200),
            "local_port": 50000 + i % 1000,
            "remote_ip": "203.0.113.%d" % (i % 240),
            "remote_port": 443,
            "state": "established",
            "is_listening": False,
            "bytes_sent": 0,
            "bytes_recv": 0,
            "duration_seconds": 1,
            "timestamp": _ts(),
        }
    return {
        "source": "eventlog",
        "channel": "Security",
        "event_id": eid,
        "timestamp": _ts(),
        "user": user,
        "message": f"Event {eid} from {user} on host telemetry (benign baseline).",
        "raw": {"i": i},
    }


def _attack_record(kind: str, i: int) -> dict:
    """A small set of attack events so the load test can measure detection lag."""
    if kind == "powershell":
        payload = "powershell.exe -NoP -NonI -W Hidden -EncodedCommand SQBFAFgAKAAiAGQAbwB3AG4AbABvAGEAZAAiACkA"
        return {
            "source": "powershell",
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "event_id": 4104,
            "timestamp": _ts(),
            "user": USERS[i % len(USERS)],
            "message": f"Creating Scriptblock text (1 of 1): {payload}",
            "raw": {
                "script_block": payload,
                "command_line": payload,
                "has_encoded": True,
                "has_download": True,
                "has_hidden": True,
            },
        }
    return {
        "source": "eventlog",
        "channel": "Security",
        "event_id": 4625,
        "timestamp": _ts(),
        "user": "administrator",
        "message": "An account failed to log on. Account Name: administrator. "
        "Source Network Address: 198.51.100.42. Logon Type: 3.",
        "raw": {
            "logon_type": 3,
            "source_ip": "198.51.100.42",
            "sub_status": "0xC000006A",
        },
    }


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


class IngestClient:
    def __init__(self, server: str, timeout: float = 30.0):
        self.server = server.rstrip("/")
        self.timeout = timeout

    def post_ingest(
        self, agent_key: str, records: list[dict], host: str
    ) -> tuple[float, dict]:
        body = json.dumps({"records": records, "host": host}).encode()
        req = urllib.request.Request(
            self.server + "/api/ingest",
            data=body,
            headers={"Content-Type": "application/json", "X-Agent-Key": agent_key},
            method="POST",
        )
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
            return time.perf_counter() - start, data
        except urllib.error.HTTPError as exc:
            return time.perf_counter() - start, {
                "error": exc.code,
                "detail": exc.read()[:200].decode(errors="replace"),
            }
        except Exception as exc:
            return time.perf_counter() - start, {"error": str(exc)}

    def get_json(self, path: str, headers: dict | None = None) -> dict:
        req = urllib.request.Request(self.server + path, headers=headers or {})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())


# ---------------------------------------------------------------------------
# Load driver
# ---------------------------------------------------------------------------


class LoadDriver:
    def __init__(
        self,
        client: IngestClient,
        keys: dict[str, str],
        batch_size: int,
        attack_rate: float,
        rng: random.Random,
    ):
        self.client = client
        self.keys = keys
        self.key_list = list(keys.items())
        self.batch_size = batch_size
        self.attack_rate = attack_rate
        self.rng = rng
        self.lock = threading.Lock()
        self.records_sent = 0
        self.events_saved = 0
        self.alerts_created = 0
        self.errors = 0
        self.latencies: list[float] = []
        self.attack_times: list[float] = []
        self.attack_records = 0
        self.start_time = time.perf_counter()
        self.end_time = float("inf")

    def _batch(
        self, agent_key: str, agent_id: str, counter: int
    ) -> tuple[str, list[dict]]:
        records = []
        for i in range(self.batch_size):
            r = self.rng.random()
            if r < self.attack_rate:
                records.append(
                    _attack_record(
                        "powershell" if counter % 2 else "brute", counter * 1000 + i
                    )
                )
            else:
                records.append(_benign_record(counter * 1000 + i))
        return agent_id, records

    def work(self, worker_id: int):
        counter = 0
        while time.perf_counter() < self.end_time:
            agent_key, agent_id = self.key_list[
                (worker_id * 7919 + counter) % len(self.key_list)
            ]
            aid, records = self._batch(agent_key, agent_id, counter)
            is_attack = any(
                rec.get("source") in ("powershell",) or rec.get("event_id") == 4625
                for rec in records
            )
            if is_attack:
                self.attack_records += sum(
                    1
                    for rec in records
                    if rec.get("event_id") in (4104, 4625)
                    or rec.get("source") == "powershell"
                )
            latency, result = self.client.post_ingest(
                agent_key, records, f"load-host-{aid[-4:]}"
            )
            with self.lock:
                self.latencies.append(latency)
                self.records_sent += len(records)
                if "error" in result:
                    self.errors += 1
                else:
                    self.events_saved += result.get("saved_events", 0)
                    self.alerts_created += result.get("alerts_created", 0)
                if is_attack:
                    self.attack_times.append(time.perf_counter() - self.start_time)
            counter += 1


def run_load(args) -> dict:
    keys = json.loads(KEYS_FILE.read_text(encoding="utf-8"))
    client = IngestClient(args.server)
    driver = LoadDriver(
        client, keys, args.batch_size, args.attack_rate, random.Random(args.seed)
    )

    # Warm-up: a single probe batch to verify auth + pipeline before the storm.
    probe_key = next(iter(keys))
    probe_host = keys[probe_key]
    _latency, result = client.post_ingest(probe_key, _benign_record(1) * 2, probe_host)
    if "error" in result:
        raise SystemExit(f"Probe ingest failed - is the server running? {result}")

    driver.start_time = time.perf_counter()
    driver.end_time = driver.start_time + args.duration
    workers = min(args.concurrency, len(keys))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(driver.work, w) for w in range(workers)]
        for future in futures:
            future.result()

    wall = time.perf_counter() - driver.start_time
    eps = driver.events_saved / wall
    lat = sorted(driver.latencies)
    pct = lambda p: lat[min(len(lat) - 1, int(p / 100 * len(lat)))] * 1000  # ms
    report = {
        "test": "baraq-fleet-load",
        "server": args.server,
        "agents": len(keys),
        "batch_size": args.batch_size,
        "duration_s": round(wall, 2),
        "workers": workers,
        "records_sent": driver.records_sent,
        "events_saved": driver.events_saved,
        "alerts_created_inline": driver.alerts_created,
        "attack_records_sent": driver.attack_records,
        "errors": driver.errors,
        "throughput_events_per_second": round(eps, 1),
        "records_per_second": round(driver.records_sent / wall, 1),
        "latency_ms": {
            "p50": round(pct(50), 1),
            "p95": round(pct(95), 1),
            "p99": round(pct(99), 1),
            "max": round(max(driver.latencies) * 1000, 1),
        },
        "started_at": datetime.now(UTC).isoformat(),
    }
    return report


def settle_and_report(client: IngestClient, report: dict, settle_s: float) -> dict:
    """Quiet phase: let the scheduler's incremental detection catch up and
    measure detection lag on the injected attack records."""
    admin_headers = {"X-API-Key": "baraq-dev-admin"}
    attack_window_start = time.perf_counter()
    first_alert_seen: float | None = None
    status = {}
    deadline = time.perf_counter() + settle_s
    alert_names = {"Suspicious PowerShell Activity", "Brute Force Attack"}
    seen: set[str] = set()
    while time.perf_counter() < deadline:
        try:
            alerts = client.get_json("/api/alerts?limit=200", admin_headers)
        except Exception:
            time.sleep(2)
            continue
        for item in alerts.get("items", []):
            if item.get("name") in alert_names and item.get("name") not in seen:
                seen.add(item["name"])
                if first_alert_seen is None:
                    first_alert_seen = time.perf_counter()
        try:
            status = client.get_json("/api/system/status", admin_headers)
        except Exception:
            pass
        if seen == alert_names:
            break
        time.sleep(3)

    summary = status.get("summary", {})
    report["alerts_after_settle"] = {
        "total_open": summary.get("active_alerts", 0),
        "expected_attack_rules": sorted(alert_names),
        "detected_rules": sorted(seen),
        "detection_lag_s": (
            round(first_alert_seen - attack_window_start, 1)
            if first_alert_seen
            else None
        ),
        "total_events_in_db": summary.get("total_events", 0),
    }
    return report


def gen_keys(count: int, seed: int) -> None:
    """Deterministic key map: short keys (Windows env-var size limit) mapped
    to numbered agent ids, e.g. ``l0001 -> a1``."""
    random.Random(seed)
    keys = {}
    for i in range(1, count + 1):
        keys[f"l{i:04d}"] = f"a{i}"
    KEYS_FILE.parent.mkdir(exist_ok=True)
    KEYS_FILE.write_text(json.dumps(keys, sort_keys=True), encoding="utf-8")
    print(f"wrote {count} agent keys -> {KEYS_FILE}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--server", default="http://127.0.0.1:8010")
    parser.add_argument("--agents", type=int, default=1000)
    parser.add_argument(
        "--duration", type=int, default=120, help="ingest phase seconds"
    )
    parser.add_argument(
        "--settle", type=int, default=90, help="detection-lag phase seconds"
    )
    parser.add_argument("--batch-size", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=128)
    parser.add_argument(
        "--attack-rate",
        type=float,
        default=0.004,
        help="fraction of attack records in the mix",
    )
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--gen-keys-only", action="store_true")
    args = parser.parse_args(argv)

    gen_keys(args.agents, args.seed)
    if args.gen_keys_only:
        return 0

    report = run_load(args)
    print(json.dumps({k: v for k, v in report.items() if k != "latency_ms"}, indent=2))
    print("latency_ms:", json.dumps(report["latency_ms"]))

    if args.settle > 0:
        client = IngestClient(args.server)
        report = settle_and_report(client, report, args.settle)
        print(json.dumps(report["alerts_after_settle"], indent=2))

    REPORT_DIR.mkdir(exist_ok=True)
    path = REPORT_DIR / f"load_test_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"report -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
