"""Development synthetic telemetry generator (Phase 1, clean-room).

Creates a throwaway ``baraq_scratch_<uuid>`` database on the local cluster,
pushes a synthetic ground-truth workload through the v2 pipeline
(normalize -> enrich -> ingest), verifies idempotent replay and the
boundary (no alerts/incidents/risk rows ever created), then drops the
database.

Rules (see docs/phase0/ENVIRONMENTS.md):
  * Refuses to run if the configured database is ``sentinel`` (production)
    or ``baraq_test`` (evaluation), or if ``BARAQ_ENV=production``.
  * The v2 pipeline is the only consumer of the scratch database.

Usage:
    python scripts/dev_seed_telemetry.py [--keep] [--records N] [--seed S]
"""
from __future__ import annotations

import argparse
import os
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADMIN_URL = os.environ.get(
    "BARAQ_TEST_ADMIN_URL",
    "postgresql+psycopg://postgres@127.0.0.1:55432/postgres",
)
#: Databases that are off-limits for development scratch runs.
FORBIDDEN = ("sentinel", "baraq_test", "postgres", "template0", "template1")


def _fresh_db_name() -> str:
    return f"baraq_scratch_{uuid.uuid4().hex[:8]}"


def _synthetic_records(rng: random.Random, now: datetime, count: int) -> list[dict]:
    """Ground-truth synthetic workload.

    ~60% benign background, ~30% the known-problem attack patterns from
    tests/regression/v1-known-problems/ (brute force bursts, rdp lateral
    duplication), ~10% malformed records to exercise the fail path.
    """
    hosts = ["ws-01", "ws-02", "ws-03", "srv-01", "srv-02", "dc-01"]
    users = ["alice", "bob", "carol", "dave", "eve", "svc_backup"]
    attack_ips = ["203.0.113.7", "203.0.113.8", "198.51.100.9", "192.0.2.55"]
    records: list[dict] = []
    for _ in range(count):
        roll = rng.random()
        ts = now - timedelta(seconds=rng.randint(0, 86_400))
        if roll < 0.10:
            records.append({"unexpected": True})  # malformed -> failed
            continue
        if roll < 0.40:  # brute-force burst: repeated 4625, same user, many IPs
            host, user = rng.choice(hosts), rng.choice(users)
            burst = rng.randint(3, 8)
            for _ in range(burst):
                records.append(
                    {
                        "event_id": 4625,
                        "computer": host,
                        "event_data": {
                            "target_user_name": user,
                            "ip_address": rng.choice(attack_ips),
                            "logon_type": 3,
                        },
                        "time_created": ts.isoformat(),
                    }
                )
            continue
        if roll < 0.50:  # rdp lateral duplication: repeated remote logons
            records.append(
                {
                    "event_id": 4624,
                    "computer": "dc-01",
                    "event_data": {
                        "target_user_name": rng.choice(users),
                        "ip_address": rng.choice(attack_ips),
                        "logon_type": 10,
                    },
                    "time_created": ts.isoformat(),
                }
            )
            continue
        if roll < 0.60:  # syslog-ish generic (linux)
            records.append(
                {
                    "timestamp": ts.isoformat(),
                    "host": rng.choice(["lnx-01", "lnx-02"]),
                    "user": rng.choice(users),
                    "source": "syslog",
                    "action": rng.choice(["ssh_login", "sudo", "cron_job"]),
                    "facts": {
                        "source_ip": rng.choice(attack_ips + ["10.0.0." + str(rng.randint(2, 99))]),
                        "service": "sshd",
                    },
                }
            )
            continue
        if roll < 0.70:  # web / proxy generic
            records.append(
                {
                    "timestamp": ts.isoformat(),
                    "host": rng.choice(["web-01", "web-02"]),
                    "user": "-",
                    "source": "web",
                    "action": "request",
                    "facts": {"source_ip": "10.0.0." + str(rng.randint(2, 99)), "method": "GET", "status": 200},
                }
            )
            continue
        # benign windows background: local logons + process creates
        records.append(
            {
                "event_id": rng.choice([4624, 4688]),
                "computer": rng.choice(hosts),
                "event_data": {
                    "target_user_name": rng.choice(users),
                    "ip_address": "127.0.0.1" if rng.random() < 0.5 else "10.0.0.5",
                    "process_name": rng.choice(["explorer.exe", "svchost.exe", "cmd.exe"]),
                },
                "time_created": ts.isoformat(),
            }
        )
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="keep the scratch DB after the run")
    parser.add_argument("--records", type=int, default=500, help="synthetic records to generate")
    parser.add_argument("--seed", type=int, default=7, help="deterministic PRNG seed")
    args = parser.parse_args()

    if os.environ.get("BARAQ_ENV") == "production":
        print("refusing: BARAQ_ENV=production", file=sys.stderr)
        return 2

    # --- pre-import guard: config is captured at import time ---------------
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    configured = os.environ.get("BARAQ_DATABASE_URL", "")
    if configured:
        current_url = make_url(configured)
        if current_url.database in FORBIDDEN:
            print(
                f"refusing: BARAQ_DATABASE_URL points at protected database "
                f"'{current_url.database}' - run without BARAQ_DATABASE_URL",
                file=sys.stderr,
            )
            return 2

    name = _fresh_db_name()
    admin = create_engine(ADMIN_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    scratch_url = str(make_url(ADMIN_URL).set(database=name))
    admin.dispose()

    # --- import backend AFTER the scratch URL is fixed ----------------------
    os.environ["BARAQ_DATABASE_URL"] = scratch_url
    os.environ["BARAQ_SKIP_SECRET_GEN"] = "1"
    os.environ.setdefault("BARAQ_ENV", "development")
    sys.path.insert(0, str(ROOT))

    from backend.database.connection import SessionLocal, init_db
    from backend.database.models import Alert, EntityRisk, Incident
    from backend.telemetry.ingestion.pipeline import ingest

    try:
        init_db()
        db = SessionLocal()
        try:
            rng = random.Random(args.seed)
            now = datetime.now(timezone.utc)
            records = _synthetic_records(rng, now, args.records)
            stats = ingest(db, records)
            replay = ingest(db, records)

            # boundary: v2 must never create v1 detection artefacts
            side = {
                "alerts": db.query(Alert).count(),
                "incidents": db.query(Incident).count(),
                "entity_risk": db.query(EntityRisk).count(),
            }
            assert side["alerts"] == side["incidents"] == side["entity_risk"] == 0, side

            print("=" * 60)
            print("Phase 1 dev telemetry run (scratch DB:", name + ")")
            print("=" * 60)
            print(f"records generated : {args.records}")
            print(f"first pass        : {stats}")
            print(f"replay (idempot.) : {replay}")
            print(f"boundary check    : {side} (all zero = clean)")
            print("PASS: normalize -> enrich -> ingest -> dedup -> boundary")
            return 0
        finally:
            db.close()
    except Exception as exc:  # noqa: BLE001 - report and still drop the DB
        print(f"FAILED: {exc}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1
    finally:
        if not args.keep:
            admin = create_engine(ADMIN_URL, isolation_level="AUTOCOMMIT")
            with admin.connect() as conn:
                conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
            admin.dispose()


if __name__ == "__main__":
    sys.exit(main())
