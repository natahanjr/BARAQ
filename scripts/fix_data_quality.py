"""Fix data quality: re-extract fields from raw_json and create verdicts."""
import os, sys, json
from pathlib import Path
os.chdir(Path(__file__).resolve().parent.parent)
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"

from backend.database.connection import engine, SessionLocal
from backend.database.models import NormalizedEvent, Verdict
from sqlalchemy import select, func, text

session = SessionLocal()
batch_size = 5000
total = session.scalar(select(func.count(NormalizedEvent.id)))
print(f"Total events: {total}")

# Fix categories and extract real user/host from raw_json
updated = 0
verdicts_created = 0

events = session.execute(
    select(NormalizedEvent.id, NormalizedEvent.raw_json, NormalizedEvent.source, NormalizedEvent.message)
    .where(NormalizedEvent.source.in_(["otrf_atomic", "otrf_compound"]))
).fetchall()

print(f"Processing {len(events)} OTRF events...")

# Attack keywords for labeling
ATTACK_KEYWORDS = [
    "mimikatz", "psexec", "sekurlsa", "dcsync", "kerberos::golden",
    "invoke-expression", "invoke-shellcode", "downloadstring", "invoke-mimikatz",
    "powershell -enc", "certutil -decode", "bitsadmin /transfer", "mshta http",
    "reg add", "schtasks /create", "net user.*add", "net localgroup.*add",
    "credential dump", "lsass", "pass the hash", "lateral movement",
    "golden ticket", "silver ticket", "overpass the hash", "hashdump",
    "procdump", "lsass.exe", "comsvcs.dll", "tasklist /svc",
    "wmic process call create", "schtasks", "at.exe",
]

for row in events:
    eid, raw_json_str, source, message = row
    try:
        raw = json.loads(raw_json_str) if raw_json_str else {}
    except:
        raw = {}

    # Extract better user
    user = raw.get("user", "") or raw.get("target_user", "") or raw.get("username", "")
    if not user or user == "postgres":
        # Try from message
        import re
        m = re.search(r"TargetUserName:\s*(\S+)", message or "")
        if m:
            user = m.group(1)
        elif raw.get("SubjectUserName"):
            user = raw["SubjectUserName"]

    # Extract better host
    host = raw.get("host", "") or raw.get("hostname", "")
    if not host or host == "wec.internal.cloudapp.net":
        m = re.search(r"ComputerName:\s*(\S+)", message or "")
        if m:
            host = m.group(1)

    # Determine category from source path or raw fields
    category = "other"
    if source == "otrf_atomic":
        # Try to extract attack scenario from raw
        attack_chain = raw.get("attack_chain", "") or raw.get("stage", "")
        if attack_chain:
            category = attack_chain
        elif "process" in str(raw.get("channel", "")).lower():
            category = "process"
        elif "network" in str(raw.get("channel", "")).lower() or raw.get("remote_ip"):
            category = "network"
        elif "auth" in str(raw.get("channel", "")).lower() or raw.get("logon_type"):
            category = "authentication"
        elif raw.get("query"):
            category = "dns"
        elif raw.get("url"):
            category = "http"
        elif raw.get("target_object") or raw.get("registry"):
            category = "registry"
        elif raw.get("script_len", 0) > 0 or "powershell" in str(raw.get("channel", "")).lower():
            category = "powershell"

    # Determine severity and label
    severity = "info"
    is_attack = False
    combined = f"{message} {json.dumps(raw, default=str)}".lower()

    for kw in ATTACK_KEYWORDS:
        if re.search(kw, combined):
            is_attack = True
            severity = "high"
            break

    # Check raw features for attack indicators
    if not is_attack:
        if raw.get("has_encoded"):
            is_attack = True
            severity = "medium"
        elif raw.get("has_hidden"):
            is_attack = True
            severity = "medium"
        elif raw.get("has_download") and raw.get("has_remote"):
            is_attack = True
            severity = "high"
        elif raw.get("has_remote"):
            severity = "medium"
        elif raw.get("has_download"):
            severity = "medium"

    # Update event
    ne = session.get(NormalizedEvent, eid)
    if ne:
        if user and ne.user in ("", "postgres"):
            ne.user = user
        if host and ne.host in ("", "wec.internal.cloudapp.net"):
            ne.host = host
        if category != "other":
            ne.category = category
        if severity != "info" and ne.severity == "info":
            ne.severity = severity
        updated += 1

        # Create verdict for attack events
        if is_attack:
            v = Verdict(
                event_id=eid,
                verdict="true_positive",
                confidence=0.85,
                analyst="otrf_heuristic",
                note="OTRF pattern match",
            )
            session.add(v)
            verdicts_created += 1

    if updated % 5000 == 0 and updated > 0:
        session.commit()
        print(f"  Processed {updated}/{len(events)}...")

session.commit()
print(f"Updated {updated} events, created {verdicts_created} verdicts")

# Final stats
with engine.connect() as conn:
    print("\nFINAL DATABASE STATUS:")
    print(f"  Events: {conn.scalar(select(func.count(NormalizedEvent.id)))}")
    print(f"  Verdicts: {conn.scalar(select(func.count(Verdict.id)))}")
    print("\n  By severity:")
    for r in conn.execute(select(NormalizedEvent.severity, func.count(NormalizedEvent.id)).group_by(NormalizedEvent.severity).order_by(func.count(NormalizedEvent.id).desc())):
        print(f"    {r[0]}: {r[1]}")
    print("\n  By category:")
    for r in conn.execute(select(NormalizedEvent.category, func.count(NormalizedEvent.id)).group_by(NormalizedEvent.category).order_by(func.count(NormalizedEvent.id).desc()).limit(15)):
        print(f"    {r[0]}: {r[1]}")

session.close()
