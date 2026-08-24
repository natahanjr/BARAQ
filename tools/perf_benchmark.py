# BARAQ performance benchmark harness.
#
# Spins up a dedicated backend instance on an isolated port with an isolated
# scratch PostgreSQL database (the production `sentinel` DB is never touched),
# loads the REAL Sigma rule set, then measures:
#   1. API latency   (login / status / alerts / events / dashboard / ingest)
#   2. Ingest throughput (events/sec through the full pipeline incl. Sigma)
#   3. In-process: Sigma engine eval timing + scheduler cycle timing + memory
#
# Usage:  venv\Scripts\python tools\perf_benchmark.py
from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PG_PORT = 55432
SCRATCH_DB = f"baraq_perf_{uuid.uuid4().hex[:8]}"
API_PORT = 8010
BASE = f"http://127.0.0.1:{API_PORT}"
ADMIN_KEY = "baraq-perf-admin"
AGENT_KEY = "baraq-agent-perf"
ADMIN_PASS = "perf-admin-pass-1"
SIGMA_DIR = ROOT / "sigma_rules"

HDRS = {"X-API-Key": ADMIN_KEY}
AGENT_HDRS = {"X-Agent-Key": AGENT_KEY, "Content-Type": "application/json"}


def percentiles(samples: list[float]) -> dict:
    s = sorted(samples)
    n = len(s)
    def pct(p: float) -> float:
        idx = min(n - 1, int(p * n))
        return s[idx]
    return {
        "min": round(s[0], 2),
        "p50": round(pct(0.50), 2),
        "p90": round(pct(0.90), 2),
        "p95": round(pct(0.95), 2),
        "p99": round(pct(0.99), 2),
        "max": round(s[-1], 2),
        "n": n,
        "mean": round(statistics.mean(s), 2),
    }


def create_scratch_db() -> None:
    import psycopg
    with psycopg.connect(host="127.0.0.1", port=PG_PORT, user="postgres", dbname="postgres", autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{SCRATCH_DB}"')
    print(f"[db] scratch database {SCRATCH_DB} created")


def drop_scratch_db() -> None:
    import psycopg
    try:
        with psycopg.connect(host="127.0.0.1", port=PG_PORT, user="postgres", dbname="postgres", autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{SCRATCH_DB}" WITH (FORCE)')
    except Exception as exc:  # noqa: BLE001
        print(f"[db] drop skipped: {exc}")


def server_env() -> dict:
    env = os.environ.copy()
    env.update({
        "BARAQ_DATABASE_URL": f"postgresql+psycopg://postgres@127.0.0.1:{PG_PORT}/{SCRATCH_DB}",
        "BARAQ_ADMIN_PASSWORD": ADMIN_PASS,
        "BARAQ_ADMIN_USERNAME": "admin",
        "BARAQ_API_KEYS": json.dumps({ADMIN_KEY: "admin", "baraq-perf-analyst": "analyst"}),
        "BARAQ_AGENT_KEYS": json.dumps({AGENT_KEY: "perf-host"}),
        "BARAQ_TOKEN_SECRET": "perf-token-secret-0001",
        "BARAQ_NO_SCHEDULER": "1",
        "BARAQ_TOAST_ENABLED": "0",
        "BARAQ_AI_API_URL": "",
        "BARAQ_ENFORCE_ADMIN_MFA": "0",
        "BARAQ_SKIP_SECRET_GEN": "1",
        "SIGMA_RULES_DIR": str(SIGMA_DIR),
        "PYTHONUNBUFFERED": "1",
    })
    return env


def start_server() -> subprocess.Popen:
    py = ROOT / "venv" / "Scripts" / "python.exe"
    proc = subprocess.Popen(
        [str(py), "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", str(API_PORT)],
        cwd=str(ROOT), env=server_env(),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return proc


def wait_ready(proc: subprocess.Popen, timeout: int = 120) -> None:
    import httpx
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"server exited early with code {proc.returncode}")
        try:
            r = httpx.get(f"{BASE}/api/system/status", headers=HDRS, timeout=2)
            if r.status_code == 200:
                return
        except Exception:  # noqa: BLE001
            pass
        time.sleep(1)
    raise RuntimeError("server did not become ready in time")


def timed_get(client, path: str, n: int = 60, **kw):
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        client.get(path, headers=HDRS, timeout=30, **kw)
        samples.append((time.perf_counter() - t0) * 1000)
    return samples


def event_records(count: int, seed: int = 42) -> list[dict]:
    """Realistic normalizer-shaped telemetry: benign mix + occasional attack."""
    import random
    rng = random.Random(seed)
    now = time.time()
    out: list[dict] = []
    exchangers = ("workstation-01", "workstation-02", "ws-eng-03", "laptop-04")
    users = ("alice", "bob", "erin", "carol", "dave")
    for i in range(count):
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now - i * 0.05)) + ".000000Z"
        host = exchangers[i % len(exchangers)]
        roll = rng.random()
        if roll < 0.55:
            eid, msg = 4624, "An account was successfully logged on."
            user = users[rng.randrange(len(users))]
            raw = {"logon_type": 2, "source_ip": f"10.0.{rng.randrange(5)}.{rng.randrange(2, 254)}"}
        elif roll < 0.70:
            eid, msg = 4688, "A new process has been created."
            user, raw = users[rng.randrange(len(users))], {
                "new_process": rng.choice(["chrome.exe", "explorer.exe", "winword.exe", "svchost.exe", "powershell.exe"]),
                "creator": "svchost.exe",
            }
        elif roll < 0.80:
            eid, msg = 3, "Network connection detected."
            user, raw = "SYSTEM", {
                "remote_ip": f"8.8.{rng.randrange(4)}.{rng.randrange(2, 254)}",
                "local_port": rng.randrange(49152, 65535), "remote_port": 443,
                "process": rng.choice(["chrome.exe", "msedge.exe"]),
            }
        elif roll < 0.88:
            eid, msg = 4625, "An account failed to log on."
            user, raw = "administrator", {"sub_status": "0xC000006D", "source_ip": f"10.0.9.{rng.randrange(2, 254)}"}
            out.append({"source": "eventlog", "channel": "Security", "event_id": eid,
                        "timestamp": ts, "user": user, "message": msg, "raw": raw, "host": host})
            continue
        else:
            eid, msg = 4104, "PowerShell ScriptBlock created."
            user, raw = users[rng.randrange(len(users))], {"script_block": "Get-Process | Where-Object {$_.Name -eq 'explorer'}"}
        out.append({"source": "eventlog", "channel": "Security" if eid in (4624, 4625) else "Microsoft-Windows-PowerShell/Operational" if eid == 4104 else "Microsoft-Windows-Sysmon/Operational",
                    "event_id": eid, "timestamp": ts, "user": user, "message": msg, "raw": raw, "host": host})
    return out


def api_latency(client, engine_client) -> dict:
    print("\n=== API LATENCY (dedicated instance, scratch DB, full Sigma set) ===")
    results: dict[str, dict] = {}

    login = []
    for _ in range(40):
        fresh = httpx.Client(base_url=BASE, verify=False, http2=False)
        t0 = time.perf_counter()
        r = fresh.post(f"{BASE}/api/auth/login", json={"username": "admin", "password": ADMIN_PASS}, timeout=30)
        login.append((time.perf_counter() - t0) * 1000)
        fresh.close()
        assert r.status_code == 200, r.text
    results["POST /api/auth/login"] = percentiles(login)

    for name, path in [
        ("GET /api/system/status", "/api/system/status"),
        ("GET /api/alerts", "/api/alerts?limit=50"),
        ("GET /api/events", "/api/events?limit=50"),
        ("GET /api/dashboard/summary", "/api/dashboard/summary"),
        ("GET /api/endpoints", "/api/endpoints"),
    ]:
        results[name] = percentiles(timed_get(client, path, n=60))

    # Ingest latency: single small batch (10 records)
    batch = event_records(10)
    ing = []
    for _ in range(20):
        t0 = time.perf_counter()
        r = client.post(f"{BASE}/api/ingest",
                        headers=AGENT_HDRS, json={"host": "perf-host", "records": batch}, timeout=60)
        ing.append((time.perf_counter() - t0) * 1000)
        assert r.status_code == 200, r.text[:300]
    results["POST /api/ingest (10 rec)"] = percentiles(ing)

    for name, table in results.items():
        print(f"  {name:<40} p50={table['p50']:>7}ms  p95={table['p95']:>7}ms  p99={table['p99']:>7}ms  max={table['max']:>7}ms  (n={table['n']})")
    return results


def ingest_throughput(client) -> dict:
    print("\n=== INGEST THROUGHPUT (full pipeline: normalize + 100 rules + Sigma 2512) ===")
    total_events = 0
    total_time = 0.0
    alerts = 0
    batch_size = 200
    batches = 30
    for b in range(batches):
        records = event_records(batch_size, seed=100 + b)
        t0 = time.perf_counter()
        r = client.post(f"{BASE}/api/ingest",
                        headers=AGENT_HDRS, json={"host": f"perf-host-{b % 4}", "records": records}, timeout=120)
        dt = time.perf_counter() - t0
        assert r.status_code == 200, r.text[:300]
        total_events += len(records)
        total_time += dt
        alerts += r.json().get("alerts_created", 0)
        if (b + 1) % 10 == 0:
            print(f"  batch {b+1}/{batches}: {len(records)} rec in {dt*1000:.0f} ms")
    eps = total_events / total_time
    apm = alerts / (total_time / 60)
    result = {
        "events": total_events,
        "elapsed_s": round(total_time, 2),
        "events_per_sec": round(eps, 1),
        "alerts_created": alerts,
        "alerts_per_min": round(apm, 2),
        "records_per_req": batch_size,
        "pipeline_ms_per_event": round((total_time * 1000) / total_events, 3),
    }
    print(f"  total={total_events} events in {result['elapsed_s']}s -> {result['events_per_sec']} events/sec | {result['alerts_created']} alerts ({result['alerts_per_min']}/min)")
    return result


def server_memory(proc: subprocess.Popen) -> dict:
    import psutil
    try:
        p = psutil.Process(proc.pid)
        p.memory_info()
        rss_peak = 0
        for _ in range(20):
            try:
                p.memory_info()
                rss = p.memory_info().rss / 1024 / 1024
                rss_peak = max(rss_peak, rss)
            except Exception:  # noqa: BLE001
                break
            time.sleep(0.5)
        return {"rss_peak_mb": round(rss_peak, 1), "cpu_percent": p.cpu_percent(interval=1)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def sigma_eval_timing() -> dict:
    """In-process Sigma engine timing against the scratch DB (real rule set)."""
    print("\n=== SIGMA ENGINE EVAL TIMING (in-process, real 2512-rule set) ===")
    os.environ.update(server_env())
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker

    from backend.database.connection import normalize_database_url
    from backend.database.models import Base, NormalizedEvent
    from backend.detection.sigma.engine import SigmaRuleEngine, load_rules_cached

    engine = create_engine(normalize_database_url(os.environ["BARAQ_DATABASE_URL"]))
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()

    t0 = time.perf_counter()
    rules = load_rules_cached(SIGMA_DIR)
    load_ms = (time.perf_counter() - t0) * 1000
    print(f"  rule parse+load : {load_ms:.0f} ms ({len(rules)} rules)")

    import random
    from datetime import datetime, timedelta, timezone
    rng = random.Random(7)
    now = datetime.now(timezone.utc)
    events = []
    for i in range(2000):
        eid = rng.choice([4624, 4625, 4688, 3, 4104, 7045, 4732, 1, 11, 13])
        events.append(NormalizedEvent(
            event_id=eid, category="cat", user="u", host="h", timestamp=now - timedelta(seconds=i),
            message="msg", risk_score=20, severity="low", source="eventlog", raw_json={},
        ))
    session.add_all(events)
    session.commit()

    sigma = SigmaRuleEngine(session, rules_dir=SIGMA_DIR)
    to = time.perf_counter()
    findings = sigma.evaluate(window_minutes=10)
    first_ms = (time.perf_counter() - to) * 1000
    print(f"  evaluate (2000 evts, cold): {first_ms:.1f} ms -> {len(findings)} findings")

    evals = []
    for _ in range(5):
        t0 = time.perf_counter()
        sigma.evaluate(window_minutes=10)
        evals.append((time.perf_counter() - t0) * 1000)
    p = percentiles(evals)
    print(f"  evaluate (warm, 2000 evts): p50={p['p50']}ms p95={p['p95']}ms (avg {p['mean']}ms)")

    session.close()
    engine.dispose()
    return {
        "rules_loaded": len(rules),
        "rule_load_ms": round(load_ms, 1),
        "eval_cold_ms": round(first_ms, 1),
        "eval_warm_p50_ms": p["p50"],
        "eval_warm_p95_ms": p["p95"],
        "eval_warm_mean_ms": p["mean"],
        "findings": len(findings),
    }


def scheduler_cycle_timing() -> dict:
    """In-process replication of scheduler._scheduler_loop body timings."""
    print("\n=== SCHEDULER CYCLE TIMING (in-process, scratch DB, real Sigma) ===")
    os.environ.update(server_env())
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker

    from backend.database.connection import normalize_database_url
    from backend.database.models import Base
    from backend.api.system import run_pipeline

    engine = create_engine(normalize_database_url(os.environ["BARAQ_DATABASE_URL"]))
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()

    records = event_records(150, seed=9)
    # warm: run once to populate tables
    run_pipeline(session, records)
    session.rollback()

    t0 = time.perf_counter()
    result = run_pipeline(session, event_records(150, seed=10))
    pipeline_ms = (time.perf_counter() - t0) * 1000
    session.rollback()

    from backend.analyzers import dashboard
    t0 = time.perf_counter()
    summary = dashboard.dashboard_summary(session)
    summary_ms = (time.perf_counter() - t0) * 1000
    session.rollback()

    cycles = []
    for _ in range(5):
        t0 = time.perf_counter()
        run_pipeline(session, event_records(150, seed=20 + _))
        session.rollback()
        cycles.append((time.perf_counter() - t0) * 1000)

    print(f"  pipeline cycle (150 rec, incl Sigma): {pipeline_ms:.0f} ms (p50 of {len(cycles)} runs: {statistics.median(cycles):.0f} ms)")
    print(f"  dashboard_summary                    : {summary_ms:.0f} ms")

    session.close()
    engine.dispose()
    return {
        "pipeline_150rec_ms": round(pipeline_ms, 1),
        "pipeline_150rec_p50_ms": round(statistics.median(cycles), 1),
        "dashboard_summary_ms": round(summary_ms, 1),
        "cycle_est_ms_per_150rec": round(pipeline_ms + summary_ms, 1),
    }


def run_all() -> dict:
    import httpx
    create_scratch_db()
    proc = None
    report: dict = {}
    try:
        proc = start_server()
        wait_ready(proc)
        client = httpx.Client(base_url=BASE, verify=False, http2=False)

        report["api_latency"] = api_latency(client, None)
        report["ingest"] = ingest_throughput(client)
        report["memory"] = server_memory(proc)
        client.close()
        print(f"\n  server memory: {report['memory']}")

        report["sigma"] = sigma_eval_timing()
        report["scheduler"] = scheduler_cycle_timing()
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except Exception:  # noqa: BLE001
                proc.kill()
        drop_scratch_db()

    out = ROOT / "reports" / "perf_benchmark.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n[report] written to {out}")
    return report


if __name__ == "__main__":
    run_all()