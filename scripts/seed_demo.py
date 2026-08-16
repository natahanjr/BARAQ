"""Seed the BARAQ platform with a realistic multi-tenant SOC demo dataset.

Populates events (14 days of benign baseline + curated ATT&CK attack
timelines over the last 48 h), runs the full detection pipeline so alerts,
entity risk and automation playbooks all fire naturally, then creates a few
incidents, saved searches and dashboards - so every page of the web UI has
something to show out of the box.

Usage:
    python scripts/seed_demo.py                        # default demo data
    python scripts/seed_demo.py --wipe                 # reset demo tables first
    python scripts/seed_demo.py --org tenant-alpha     # seed a specific tenant
    python scripts/seed_demo.py --scenarios brute_force,phishing --days 7

Env overrides (same as the server): BARAQ_DATABASE_URL, BARAQ_HOST, ...
Detection uses the same cursor the scheduler uses, so this is safe to run
against a live instance.
"""
from __future__ import annotations

import argparse
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("BARAQ_SKIP_SECRET_GEN", "1")
os.environ.setdefault("BARAQ_TOAST_ENABLED", "0")

from sqlalchemy import delete  # noqa: E402

from backend.api.system import run_detection, run_pipeline  # noqa: E402
from backend.database.connection import SessionLocal  # noqa: E402
from backend.database.models import (  # noqa: E402
    Alert,
    AutomationPlaybook,
    Dashboard,
    DnsQuery,
    EmailMessage,
    EntityRisk,
    EntityRiskEvent,
    HttpRequest,
    Incident,
    IncidentAlertLink,
    IncidentComment,
    NetworkConnection,
    NormalizedEvent,
    PlaybookRun,
    ProcessRecord,
    SavedSearch,
)
from backend.detection.cursor import set_cursor  # noqa: E402

from fixtures import (  # noqa: E402
    benign_baseline,
    benign_process,
    brute_force,
    data_staging,
    dcsync,
    disable_defender,
    dns_exfil,
    http_exfil,
    kerberoast,
    lateral_movement,
    log_clear,
    lolbin_usage,
    ml_c2_beacon,
    pass_the_hash,
    persistence,
    phishing_email,
    port_scan,
    privilege_escalation,
    ransomware_impact,
    recovery_inhibit,
    suspicious_powershell,
    sysmon_lsass_benign,
    webhook_c2,
)

HOSTS = [f"DESKTOP-0{i}" for i in range(1, 5)] + [f"SRV-WEB-0{i}" for i in range(1, 3)]
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy"]

#: name -> (fixture builder, hours ago, host, user). Every cluster lands on a
#: distinct host so correlation chains and the entity graph look believable.
ATTACK_SCENARIOS = [
    ("brute_force", brute_force, 2, "DESKTOP-01", "bob"),
    ("suspicious_powershell", suspicious_powershell, 3, "DESKTOP-02", "carol"),
    ("privilege_escalation", privilege_escalation, 4, "DESKTOP-03", "erin"),
    ("persistence", persistence, 5, "DESKTOP-01", "dave"),
    ("port_scan", port_scan, 6, "DESKTOP-04", "grace"),
    ("lateral_movement", lateral_movement, 7, "DESKTOP-02", "frank"),
    ("data_staging", data_staging, 8, "DESKTOP-05", "heidi"),
    ("phishing_email", phishing_email, 9, "DESKTOP-03", "ivan"),
    ("dns_exfil", dns_exfil, 10, "SRV-WEB-01", "judy"),
    ("http_exfil", http_exfil, 11, "SRV-WEB-02", "alice"),
    ("log_clear", log_clear, 12, "DESKTOP-04", "grace"),
    ("lolbin", lolbin_usage, 13, "DESKTOP-06", "bob"),
    ("kerberoast", kerberoast, 26, "SRV-DC-01", "erin"),
    ("dcsync", dcsync, 28, "SRV-DC-01", "dave"),
    ("pass_the_hash", pass_the_hash, 32, "DESKTOP-05", "carol"),
    ("disable_defender", disable_defender, 42, "DESKTOP-06", "heidi"),
    ("ransomware", ransomware_impact, 44, "DESKTOP-03", "frank"),
    ("recovery_inhibit", recovery_inhibit, 45, "DESKTOP-03", "frank"),
    ("webhook_c2", webhook_c2, 46, "SRV-WEB-02", "judy"),
    ("c2_beacon", ml_c2_beacon, 48, "SRV-WEB-01", "ivan"),
]

SAVED_SEARCHES = [
    ("Failed Logons by User", "Failed authentication events bucketed by account.", "event_id=4625 | top 10 user | sort -count", "-7d"),
    ("Critical Open Alerts", "Highest-severity alerts still open.", "index=alerts severity=critical status=open | table name, rule, host, risk_level, risk_score | sort -risk_score", "-7d"),
    ("Failed Logon Trend", "Daily failed-logon volume for trend analysis.", "event_id=4625 | timechart span=1d count", "-30d"),
    ("Top Alerted Hosts", "Hosts with the most alerts.", "index=alerts | top 10 host", "-7d"),
    ("Open Alert Count", "Running total of open alerts.", "index=alerts status=open | stats count", "-7d"),
    ("PowerShell Downloads", "PowerShell script blocks that download content.", 'index=events source=powershell "DownloadString" | top 5 user', "-7d"),
]


def _reanchor(records: list[dict], hours_ago: float) -> list[dict]:
    """Shift a fixture timeline so its newest record is ``hours_ago`` old."""
    newest = None
    for rec in records:
        ts = rec.get("timestamp")
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if newest is None or dt > newest:
                    newest = dt
            except ValueError:
                continue
    if newest is None:
        return records
    target = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    offset = (target - newest).total_seconds()
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


def _scatter_ages(records: list[dict], max_hours: float) -> list[dict]:
    """Spread records over the past ``max_hours`` (for the benign baseline)."""
    now = datetime.now(timezone.utc)
    scattered = []
    for rec in records:
        rec = dict(rec)
        ts = rec.get("timestamp")
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                rec["timestamp"] = (now - timedelta(hours=random.uniform(0.05, max_hours))).isoformat()
            except ValueError:
                pass
        scattered.append(rec)
    return scattered


def _assign_entity(records: list[dict], host: str, user: str) -> list[dict]:
    out = []
    for rec in records:
        rec = dict(rec)
        rec["host"] = host
        if rec.get("user"):
            rec["user"] = user
        out.append(rec)
    return out


def _seed_playbooks(db) -> None:
    playbooks = [
        AutomationPlaybook(
            name="Block brute-force source",
            description="Automatically block the source IP when brute force is detected.",
            enabled=True,
            triggers={"rules": ["brute_force"]},
            actions=[{"action": "block_ip"}, {"action": "escalate"}],
        ),
        AutomationPlaybook(
            name="Isolate lateral movement host",
            description="Isolate hosts that pivoted and open an incident.",
            enabled=True,
            triggers={"rules": ["lateral_movement", "rdp_lateral", "pass_the_hash"], "severity": ["high", "critical"]},
            actions=[{"action": "isolate"}, {"action": "create_incident"}],
        ),
        AutomationPlaybook(
            name="Open incident on impact",
            description="Any impact-tactic alert opens an incident automatically.",
            enabled=True,
            triggers={"severity": ["critical"], "tactics": ["Impact"]},
            actions=[{"action": "notify"}, {"action": "create_incident"}],
        ),
    ]
    for pb in playbooks:
        if not db.query(AutomationPlaybook).filter(AutomationPlaybook.name == pb.name).first():
            db.add(pb)
    db.commit()
    print(f"  seeded {len(playbooks)} automation playbooks")


def _seed_saved_searches_and_dashboards(db) -> None:
    saved_ids = {}
    for name, desc, query, earliest in SAVED_SEARCHES:
        existing = db.query(SavedSearch).filter(SavedSearch.name == name).first()
        row = existing or SavedSearch(name=name)
        row.description = desc
        row.query = query
        row.earliest = earliest
        row.owner = "seeder"
        db.add(row)
        db.flush()
        saved_ids[name] = row.id
    db.commit()

    dashboards = [
        Dashboard(
            name="SOC Overview",
            description="The daily posture board: critical alerts, top hosts, logon trends.",
            panels=[
                {"id": "p1", "title": "Critical Open Alerts", "saved_search_id": saved_ids["Critical Open Alerts"], "viz": "table", "limit": 10, "cols": 2},
                {"id": "p2", "title": "Top Alerted Hosts", "saved_search_id": saved_ids["Top Alerted Hosts"], "viz": "top", "field": "host", "limit": 8, "cols": 2},
                {"id": "p3", "title": "Failed Logon Trend", "saved_search_id": saved_ids["Failed Logon Trend"], "viz": "area", "limit": 30, "cols": 2},
                {"id": "p4", "title": "Open Alerts", "saved_search_id": saved_ids["Open Alert Count"], "viz": "count", "cols": 1},
            ],
        ),
        Dashboard(
            name="Authentication Health",
            description="Everything about logons: who fails, who succeeds, how often.",
            panels=[
                {"id": "p5", "title": "Failed Logons by User", "saved_search_id": saved_ids["Failed Logons by User"], "viz": "top", "field": "user", "limit": 10, "cols": 2},
                {"id": "p6", "title": "Failed Logon Trend", "saved_search_id": saved_ids["Failed Logon Trend"], "viz": "area", "limit": 30, "cols": 2},
            ],
        ),
    ]
    for dash in dashboards:
        if not db.query(Dashboard).filter(Dashboard.name == dash.name).first():
            db.add(dash)
    db.commit()
    print(f"  seeded {len(dashboards)} dashboards, {len(SAVED_SEARCHES)} saved searches")


def _seed_incidents(db, org: str, limit: int = 3) -> None:
    alerts = (
        db.query(Alert)
        .filter(Alert.status == "open", Alert.org == org, Alert.demo.is_(True))
        .order_by(Alert.risk_score.desc())
        .all()
    )
    top = alerts[: max(1, limit)]
    created = 0
    for alert in top:
        title = f"{alert.name} - {alert.host or 'unknown host'}"
        existing = db.query(Incident).filter(Incident.title == title).first()
        if existing:
            continue
        incident = Incident(
            title=title,
            description=f"Demo incident opened from the seeded '{alert.rule}' alert "
                        f"({alert.mitre_id or 'unknown technique'}).",
            severity=alert.severity,
            owner="analyst",
            host=alert.host,
            org="",
            demo=True,
            mitre_id=alert.mitre_id,
            mitre_name=alert.mitre_name,
            risk_score=alert.risk_score,
            risk_level=alert.risk_level,
            opened_at=datetime.now(timezone.utc),
        )
        db.add(incident)
        db.flush()
        db.add(IncidentAlertLink(incident_id=incident.id, alert_id=alert.id))
        db.add(IncidentComment(
            incident_id=incident.id,
            author="seeder",
            body="Incident created by demo seeder",
            kind="status",
        ))
        created += 1
    db.commit()
    print(f"  created {created} incidents from top-risk alerts")


def _wipe(db) -> None:
    for model in (
        PlaybookRun,
        IncidentAlertLink,
        IncidentComment,
        Incident,
        Alert,
        EntityRiskEvent,
        EntityRisk,
        EmailMessage,
        HttpRequest,
        DnsQuery,
        NetworkConnection,
        ProcessRecord,
        NormalizedEvent,
        SavedSearch,
        Dashboard,
        AutomationPlaybook,
    ):
        db.execute(delete(model))
    set_cursor(db, 0)
    db.commit()
    print("  wiped demo tables + detection cursor")


def seed(org: str, scenarios: list[str], days: int, incidents: int, wipe: bool) -> dict:
    # Apply schema migrations (demo / correlation_id / escalation-state
    # columns) so the seeder works on databases created before those columns.
    from backend.database.connection import init_db

    init_db()
    with SessionLocal() as db:
        if wipe:
            _wipe(db)

        print("Seeding playbooks / saved searches / dashboards ...")
        _seed_playbooks(db)
        _seed_saved_searches_and_dashboards(db)

        print("Building event timeline ...")
        baseline = benign_baseline(n=120) + benign_process() + sysmon_lsass_benign()
        all_records = _scatter_ages(baseline, max_hours=days * 24)

        matched = 0
        for name, builder, hours_ago, host, user in ATTACK_SCENARIOS:
            if scenarios and name not in scenarios:
                continue
            matched += 1
            records = _assign_entity(builder(), host, user)
            all_records.extend(_reanchor(records, hours_ago))

        print(f"Persisting {len(all_records)} records ({matched} attack timelines, org={org!r}) ...")
        run_pipeline(db, all_records, org=org, detect=False, demo=True)

        print("Running detection pipeline (this can take a minute) ...")
        window = 60 * 49  # cover the oldest attack cluster (48 h) + margin
        findings, created = run_detection(db, org=org, window_minutes=window, demo=True)
        print(f"  {len(findings)} findings, {len(created)} alerts created")

        # Escalate demo entities (level-gated, idempotent) inside the demo
        # partition - the production scheduler never escalates demo entities,
        # so this is the only place the demo consoles get their notables.
        db.info["baraq_demo"] = True
        try:
            from backend.risk.entity_risk import EntityRiskManager

            notables = EntityRiskManager(db).escalate(org=org)
            if notables:
                print(f"  escalated {len(notables)} demo entity notable(s)")
        finally:
            db.info.pop("baraq_demo", None)

        if incidents:
            _seed_incidents(db, org, limit=incidents)

        counts = {
            "events": db.query(NormalizedEvent).filter(NormalizedEvent.org == org).count(),
            "alerts": db.query(Alert).filter(Alert.org == org).count(),
            "entities": db.query(EntityRisk).filter(EntityRisk.org == org).count(),
            "incidents": db.query(Incident).filter(Incident.org == org).count(),
            "playbook_runs": db.query(PlaybookRun).count(),
            "saved_searches": db.query(SavedSearch).count(),
            "dashboards": db.query(Dashboard).count(),
        }
        return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed BARAQ with a demo SOC dataset")
    parser.add_argument("--org", default="", help="tenant to seed (default: global)")
    parser.add_argument(
        "--scenarios",
        default="",
        help="comma-separated scenario subset (default: all, see ATTACK_SCENARIOS)",
    )
    parser.add_argument("--days", type=int, default=14, help="benign baseline span in days")
    parser.add_argument("--incidents", type=int, default=3, help="incidents to create (0 = none)")
    parser.add_argument("--wipe", action="store_true", help="wipe demo tables before seeding")
    args = parser.parse_args()

    scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    print("=" * 70)
    print("BARAQ demo data seeder")
    print("=" * 70)
    counts = seed(args.org, scenarios, args.days, args.incidents, args.wipe)
    print("Done. Summary:")
    for key, value in counts.items():
        print(f"  {key:<16} {value}")


if __name__ == "__main__":
    main()