"""Automated red-team campaign replay against the live detection pipeline.

Replays realistic multi-stage attack traffic through the *actual* platform
path - ``backend.api.system.run_pipeline`` (normalize -> persist -> rules
engine -> alerting), the same entry point the agents use - inside an isolated
temp database, and reports per-scenario verdicts including detection method
(rule vs ML vs hybrid), detection latency and the MITRE mapping.

This is the repeatable asset behind ``documentation/red_team_validation.md``:
it turns the manual dashboard procedure into a one-shot, reproducible check
that the engine detects the documented kill chain. False negatives are
reported honestly with guidance, and the exit code reflects the outcome
(0 = every scenario detected).

Usage:
    python scripts/redteam_validate.py                # every scenario, fresh DB each
    python scripts/redteam_validate.py --chain        # one DB, realistic kill-chain timeline
    python scripts/redteam_validate.py --scenario brute_force --json-out report.json

The script is read-only: it never writes config or the production DB.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("SENTINEL_SKIP_SECRET_GEN", "1")
# Batch replay must not pop Windows toasts or enqueue alerts to external
# notification channels during a CI/automation run.
os.environ.setdefault("SENTINEL_TOAST_ENABLED", "0")
os.environ.setdefault(
    "SENTINEL_DATABASE_URL", f"sqlite:///{Path(tempfile.gettempdir()) / 'sentinel_redteam.db'}"
)

from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from backend.api.system import run_pipeline  # noqa: E402
from backend.database.models import Alert, Base  # noqa: E402

#: scenario -> (expected rule id, MITRE technique, human guidance).
SCENARIOS = {
    "brute_force": ("brute_force", "T1110", "brute-force failed-logon burst"),
    "suspicious_powershell": ("suspicious_powershell", "T1059.001", "encoded/hidden download-execute payload"),
    "privilege_escalation": ("privilege_escalation", "T1068", "admin account / privileged group mutation"),
    "persistence": ("persistence", "T1547", "scheduled-task persistence (run-at-logon)"),
    "port_scan": ("network_recon", "T1046", "multi-port service discovery"),
    "lateral_movement": ("lateral_movement", "T1021.002", "admin-share / session-based lateral movement"),
    "data_staging": ("data_staging", "T1074", "archive/binary staging before exfiltration"),
    "phishing_email": ("email_phishing", "T1566", "phishing email with lure attachment"),
    "dns_exfil": ("dns_http_exfil", "T1048", "DNS query exfiltration channel"),
    "http_exfil": ("exfiltration_volume", "T1048", "large HTTP upload transfer"),
    "ml_c2_beacon": ("c2_beacon", "T1071.001", "periodic C2 beacon cadence"),
    "log_clear": ("log_clearing", "T1074", "Windows event-log clearing"),
    "lolbin_usage": ("lolbin_execution", "T1204.002", "lolbin download/execute (certutil/mshta)"),
}

#: benign fixtures interleaved around each stage so the engine sees a busy host.
BENIGN_BUILDERS = (
    "benign_baseline",
    "benign_process",
    "sysmon_lsass_benign",
)


def _anchor_now(records: list[dict], newest_seconds: float = 2.0) -> list[dict]:
    """Shift timestamps so the newest record is ~2 s before ""now"".

    Keyed fixtures are stamped relative to build time; replaying minutes
    later would age them out of the rule windows, so every replay re-anchors
    the timeline to the moment it runs.
    """
    newest: datetime | None = None
    for rec in records:
        ts = rec.get("timestamp")
        if not isinstance(ts, str):
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            continue
        if newest is None or dt > newest:
            newest = dt
    if newest is None:
        return records
    offset = (datetime.now(timezone.utc) - newest).total_seconds() - newest_seconds
    if offset <= 0:
        return records
    shifted = []
    for rec in records:
        rec = dict(rec)
        if isinstance(rec.get("raw"), dict):
            rec["raw"] = dict(rec["raw"])
        ts = rec.get("timestamp")
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                rec["timestamp"] = (dt + timedelta(seconds=offset)).isoformat()
            except ValueError:
                pass
        shifted.append(rec)
    return shifted


def _shift_to(records: list[dict], target: datetime) -> list[dict]:
    """Move the whole timeline so the first record lands at ``target``."""
    records = _anchor_now(records)
    if not records:
        return records
    first = None
    for rec in records:
        ts = rec.get("timestamp")
        if isinstance(ts, str):
            try:
                first = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                break
            except ValueError:
                continue
    if first is None:
        return records
    delta = target - first
    shifted = []
    for rec in records:
        rec = dict(rec)
        ts = rec.get("timestamp")
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                rec["timestamp"] = (dt + delta).isoformat()
            except ValueError:
                pass
        shifted.append(rec)
    return shifted


def _shift_latest_to(records: list[dict], target: datetime) -> list[dict]:
    """Move the whole timeline so its *newest* record lands at ``target``.

    Stages span several minutes internally (rate-limit windows etc.), so
    pinning the latest record - not the first - keeps the whole stage inside
    the rule window without future-stamping anything.
    """
    records = _anchor_now(records)
    if not records:
        return records
    newest = None
    for rec in records:
        ts = rec.get("timestamp")
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                continue
            if newest is None or dt > newest:
                newest = dt
    if newest is None:
        return records
    delta = target - newest
    shifted = []
    for rec in records:
        rec = dict(rec)
        ts = rec.get("timestamp")
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                rec["timestamp"] = (dt + delta).isoformat()
            except ValueError:
                pass
        shifted.append(rec)
    return shifted


def _fresh_session():
    fd, path = tempfile.mkstemp(suffix=".db", prefix="sentinel_redteam_")
    os.close(fd)
    engine = create_engine("sqlite:///" + path)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _scenario_records(name: str) -> list[dict]:
    from tests import fixtures

    return list(getattr(fixtures, name)())


def _noise(count: int, seed: int = 20260806) -> list[dict]:
    from tests import fixtures

    source = [rec for name in BENIGN_BUILDERS for rec in getattr(fixtures, name)()]
    rng = random.Random(seed)
    return rng.sample(source, min(count, len(source)))


def _run_events(session, records: list[dict]) -> list[Alert]:
    """Push records through the production pipeline; return created alerts."""
    run_pipeline(session, records)
    return list(session.scalars(select(Alert).order_by(Alert.created_at)).all())


def _detection_time(alert: Alert | None, records: list[dict]) -> str:
    if alert is None or alert.created_at is None:
        return "n/a"
    newest = None
    for rec in records:
        ts = rec.get("timestamp")
        if not isinstance(ts, str):
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            continue
        if newest is None or dt > newest:
            newest = dt
    if newest is None:
        return "n/a"
    created = alert.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return f"{((created - newest).total_seconds()):+.1f}s"


def _replay_isolation(name: str, expected_rule: str, mitre: str, guidance: str) -> dict:
    """Stage in its own DB: scenario + interleaved benign noise, same window."""
    session = _fresh_session()
    attack = _scenario_records(name)
    noise = _noise(20)
    merged = _anchor_now(attack + noise)
    alerts = _run_events(session, merged)
    hit = [a for a in alerts if a.rule == expected_rule]
    primary = hit[0] if hit else (alerts[0] if alerts else None)
    result = {
        "scenario": name,
        "mitre": mitre,
        "expected_rule": expected_rule,
        "detected": bool(hit),
        "alert_rule": primary.rule if primary else "",
        "severity": primary.severity if primary else "",
        "risk_level": primary.risk_level if primary else "",
        "detection_method": primary.detection_method if primary else "",
        "detection_time_s": _detection_time(primary, merged),
        "total_alerts": len(alerts),
        "related_alerts": sorted({a.rule for a in alerts}),
        "false_negative_notes": "" if hit else guidance,
    }
    return result


def _replay_chain() -> list[dict]:
    """Full kill chain in one timeline.

    Stages are packed so the *newest* record of every stage sits within the
    last ~50 s and the oldest record of the earliest stage still lands inside
    the strictest rule lookback (``network_recon`` = 120 s); the engine's
    other rules use 10-minute windows, so the whole chain fits the same
    evaluation pass.
    """
    session = _fresh_session()
    now = datetime.now(timezone.utc)
    timeline: list[dict] = []
    for i, name in enumerate(SCENARIOS):
        newest_seconds = 15 + i * 3
        target = now - timedelta(seconds=newest_seconds)
        timeline.extend(_shift_latest_to(_scenario_records(name), target))
        timeline.extend(_shift_latest_to(_noise(12, seed=20260806 + i), target - timedelta(seconds=90)))
    timeline = _anchor_now(timeline)
    alerts = _run_events(session, timeline)
    by_rule: dict[str, list[Alert]] = {}
    for a in alerts:
        by_rule.setdefault(a.rule, []).append(a)
    results = []
    for name, (rule, _, _) in SCENARIOS.items():
        hits = by_rule.get(rule, [])
        primary = hits[0] if hits else None
        results.append({
            "scenario": name,
            "expected_rule": rule,
            "detected": bool(hits),
            "alert_rule": primary.rule if primary else "",
            "severity": primary.severity if primary else "",
            "detection_method": primary.detection_method if primary else "",
            "detection_time_s": _detection_time(primary, timeline),
        })
    session.close()
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", type=str, default="", help="replay a single scenario by fixture name")
    parser.add_argument("--chain", action="store_true", help="replay the full kill chain in one timeline")
    parser.add_argument("--json-out", type=str, default="", help="write the verdict table to a JSON file")
    args = parser.parse_args()

    if args.chain:
        results = _replay_chain()
        mode = "kill-chain timeline replay (one database)"
    elif args.scenario:
        name = args.scenario
        if name not in SCENARIOS:
            raise SystemExit(f"unknown scenario {name!r}; pick from: {', '.join(SCENARIOS)}")
        rule, mitre, note = SCENARIOS[name]
        results = [_replay_isolation(name, rule, mitre, note)]
        mode = f"isolated replay: {name}"
    else:
        results = [_replay_isolation(name, rule, mitre, note) for name, (rule, mitre, note) in SCENARIOS.items()]
        mode = "isolated per-scenario replay (fresh DB per scenario)"

    print(f"Red-team validation asset - mode: {mode}")
    print(f"{'scenario':22s} {'expected rule':18s} {'verdict':6s} {'severity':9s} {'method':10s} {'latency':9s}")
    misses = 0
    for r in results:
        hit = r["detected"]
        misses += 0 if hit else 1
        print(
            f"{r['scenario']:22s} {r['expected_rule']:18s} {'OK' if hit else 'MISS':6s} "
            f"{r['severity']:9s} {r['detection_method']:10s} {r.get('detection_time_s', 'n/a'):9s}"
        )
        if not hit and r.get("false_negative_notes"):
            print(f"    missed: {r['false_negative_notes']}")
    if args.json_out:
        with Path(args.json_out).open("w", encoding="utf-8") as fh:
            json.dump({"mode": mode, "results": results}, fh, indent=2)
    print(f"result: {'ALL DETECTED' if misses == 0 else f'{misses} scenario(s) missed'} (exit {misses})")
    return misses


if __name__ == "__main__":
    raise SystemExit(main())