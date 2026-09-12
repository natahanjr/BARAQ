"""Load ALL OTRF data with proper parsing for both OCSF and raw WinEventLog formats."""
import os, sys, json, hashlib, logging, time, zipfile, re
from pathlib import Path
from datetime import UTC, datetime

os.chdir(Path(__file__).resolve().parent.parent)
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("load_all")

OTRF = Path("F:/My Project/Baraq/tmp_data/otrf/datasets")

ATTACK_KEYWORDS = [
    "mimikatz", "sekurlsa", "dcsync", "kerberos::golden", "credential dump",
    "invoke-expression", "invoke-shellcode", "downloadstring", "invoke-mimikatz",
    "powershell -enc", "certutil -decode", "bitsadmin /transfer", "mshta http",
    "pass the hash", "golden ticket", "lateral movement",
    "comsvcs.dll", "procdump", "lsass.exe",
    "schtasks /create", "net user.*add", "net localgroup.*add",
    "reg add.*run", "wmic process call create",
]

PROCESS_NAMES = [
    "mimikatz", "procdump", "psexec", "nc", "ncat", "certutil", "mshta",
    "wscript", "cscript", "bitsadmin", "rundll32", "regsvr32", "msiexec",
]

SYSMON_CHANNELS = {
    "microsoft-windows-sysmon/operational": "sysmon",
    "security": "security",
    "microsoft-windows-powershell/operational": "powershell",
    "windows powershell": "powershell",
    "microsoft-windows-wfp/operational": "wfp",
    "system": "system",
    "application": "application",
}

SYSMON_MAP = {
    1: "process_create", 3: "network_connection", 7: "image_loaded",
    8: "create_remote_thread", 10: "process_access", 11: "file_create",
    12: "registry_create", 13: "registry_value_set",
    15: "file_create_stream_hash", 17: "pipe_created", 19: "wmi_event",
    22: "dns_query",
}

WINSEC_MAP = {
    4624: "logon_success", 4625: "logon_failure", 4634: "logoff",
    4648: "logon_explicit", 4672: "special_logon", 4720: "account_created",
    4732: "security_group_change", 4740: "account_lockout",
    4771: "kerberos_preauth", 4776: "credential_validation",
    1102: "audit_log_cleared", 4688: "process_create",
    4689: "process_terminate", 4663: "file_access", 4660: "file_delete",
}


def classify_event(raw):
    """Classify a raw event dict into category, severity, is_attack."""
    channel = ""
    ch_raw = raw.get("Channel", raw.get("channel", raw.get("ChannelName", "")))
    if isinstance(ch_raw, str):
        channel = ch_raw.lower().strip()

    event_id = int(raw.get("EventID", raw.get("event_id", 0)) or 0)
    message = str(raw.get("Message", raw.get("message", "")) or "")
    image = str(raw.get("Image", raw.get("NewProcessName", raw.get("SourceImage", ""))) or "")
    target_image = str(raw.get("TargetImage", "") or "")
    source_ip = str(raw.get("IpAddress", raw.get("SourceIp", raw.get("SourceAddress", ""))) or "")
    dest_ip = str(raw.get("DestinationIp", raw.get("DestinationAddress", ""))) or ""
    query_name = str(raw.get("QueryName", "") or "")
    account = str(raw.get("AccountName", raw.get("TargetUserName", raw.get("UserName", ""))) or "")
    hostname = str(raw.get("host", raw.get("ComputerName", raw.get("Computer", ""))) or "")

    # Classify by channel + event ID
    category = "other"
    severity = "info"
    is_attack = False

    # Sysmon
    if "sysmon" in channel or event_id in SYSMON_MAP:
        if event_id == 1 or event_id == 4688:
            category = "process"
        elif event_id == 3:
            category = "network"
        elif event_id in (11, 15):
            category = "file"
        elif event_id in (12, 13, 14):
            category = "registry"
        elif event_id == 22:
            category = "dns"
        elif event_id == 10:
            category = "process_access"
        elif event_id == 17:
            category = "pipe"
        elif event_id == 8:
            category = "process"
            is_attack = True
            severity = "high"

    # Security
    elif "security" in channel or event_id in WINSEC_MAP:
        if event_id in (4624, 4634, 4648, 4672):
            category = "authentication"
        elif event_id == 4625:
            category = "authentication"
            severity = "medium"
        elif event_id == 4740:
            category = "authentication"
            is_attack = True
            severity = "high"
        elif event_id in (4720, 4732):
            category = "authentication"
            severity = "medium"
        elif event_id == 1102:
            category = "audit"
            is_attack = True
            severity = "high"
        elif event_id in (4688, 4689):
            category = "process"
        elif event_id in (4663, 4660):
            category = "file"

    # PowerShell
    elif "powershell" in channel or event_id in (4104, 4103, 400, 403):
        category = "powershell"
        if event_id in (4104, 4103):
            severity = "medium"

    # WFP
    elif "wfp" in channel or event_id in (5156, 5157, 5158):
        category = "network"

    # AAD / Azure
    elif raw.get("TenantId") or raw.get("AADTenantId"):
        category = "azure_ad"

    # Attack detection
    combined = f"{message} {image} {target_image}".lower()
    for kw in ATTACK_KEYWORDS:
        if re.search(kw, combined):
            is_attack = True
            severity = "high"
            break

    if not is_attack:
        image_lower = image.lower()
        for proc in PROCESS_NAMES:
            if proc in image_lower:
                is_attack = True
                severity = "high"
                break

    if not is_attack:
        if raw.get("CallTrace") and "lsass" in str(raw.get("CallTrace", "")).lower():
            is_attack = True
            severity = "high"

    return category, severity, is_attack, hostname, account, source_ip, dest_ip, query_name, message, image


def parse_and_insert_file(filepath, adapter, session, source_label):
    """Parse a single file and insert events."""
    from backend.database.models import NormalizedEvent, Verdict

    content = filepath.read_text(encoding="utf-8", errors="replace").strip()
    if not content:
        return 0, 0

    # Parse JSON
    if content.startswith("["):
        raw_events = json.loads(content)
    elif content.startswith("{"):
        raw_events = []
        for line in content.splitlines():
            line = line.strip()
            if line:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        raw_events.append(obj)
                except json.JSONDecodeError:
                    continue
    else:
        return 0, 0

    if not isinstance(raw_events, list):
        raw_events = [raw_events]

    inserted = 0
    verdicts = 0

    for raw in raw_events:
        if not isinstance(raw, dict):
            continue

        # First try the OCSF adapter
        parsed = adapter.parse_event(raw)

        if parsed and parsed.get("message"):
            # OCSF adapter worked
            ts_raw = parsed.get("timestamp")
            if isinstance(ts_raw, str):
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                except:
                    ts = datetime.now(UTC)
            else:
                ts = datetime.now(UTC)

            label = parsed.get("label", 0)
            raw_dict = parsed.get("raw", {})
            if not isinstance(raw_dict, dict):
                raw_dict = {}

            ne = NormalizedEvent(
                event_id=int(parsed.get("event_id", 0) or 0),
                category=parsed.get("source", "other"),
                source=source_label,
                user=parsed.get("user", ""),
                host=parsed.get("host", ""),
                severity="high" if label else "info",
                message=str(parsed.get("message", ""))[:1024],
                timestamp=ts,
                raw_json=json.dumps(raw_dict, default=str)[:10000],
                org="",
            )
            session.add(ne)
            inserted += 1

        else:
            # Raw WinEventLog format — parse manually
            category, severity, is_attack, hostname, account, source_ip, dest_ip, query_name, message, image = classify_event(raw)

            ts_raw = raw.get("TimeGenerated") or raw.get("@timestamp") or raw.get("UtcTime") or raw.get("EventTime")
            if isinstance(ts_raw, str):
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                except:
                    ts = datetime.now(UTC)
            else:
                ts = datetime.now(UTC)

            event_id = int(raw.get("EventID", 0) or 0)

            raw_dict = {
                "event_id": event_id,
                "image_path": image,
                "command_line": str(raw.get("CommandLine", raw.get("ScriptBlockText", "")) or ""),
                "parent_process": str(raw.get("ParentImage", raw.get("ParentProcessName", "")) or ""),
                "source_ip": source_ip,
                "remote_ip": dest_ip,
                "remote_port": int(raw.get("DestinationPort", 0) or 0),
                "target_user": account,
                "logon_type": int(raw.get("LogonType", 0) or 0),
                "query": query_name,
                "target_object": str(raw.get("TargetObject", "") or ""),
                "call_trace": str(raw.get("CallTrace", "") or ""),
            }

            ne = NormalizedEvent(
                event_id=event_id,
                category=category,
                source=source_label,
                user=account,
                host=hostname,
                severity=severity,
                message=str(message or raw.get("Message", ""))[:1024],
                timestamp=ts,
                raw_json=json.dumps(raw_dict, default=str)[:10000],
                org="",
            )
            session.add(ne)
            inserted += 1

    return inserted, verdicts


def main():
    from backend.ml.dataset_adapters import ADAPTERS
    from backend.database.connection import SessionLocal, engine
    from backend.database.models import NormalizedEvent, Verdict
    from sqlalchemy import select, func, text

    adapter = ADAPTERS["security_datasets"]()
    session = SessionLocal()
    grand_total = 0
    grand_verdicts = 0

    # ═══ SOURCE 1: Atomic JSON files ═══
    log.info("Loading OTRF Atomic JSON files...")
    t0 = time.time()
    atomic_files = list((OTRF / "atomic").rglob("*.json"))
    log.info("Found %d atomic JSON files", len(atomic_files))
    for i, f in enumerate(atomic_files):
        ins, vids = parse_and_insert_file(f, adapter, session, "otrf_atomic")
        grand_total += ins
        grand_verdicts += vids
        if (i + 1) % 50 == 0:
            session.commit()
            log.info("  Atomic: %d/%d files, %d events", i+1, len(atomic_files), grand_total)
    session.commit()
    log.info("Atomic done: %d events, %d verdicts", grand_total, grand_verdicts)

    # ═══ SOURCE 2: Compound extracted ZIPs ═══
    log.info("Loading OTRF Compound extracted ZIPs...")
    extract_dir = Path("F:/My Project/Baraq/tmp_data/extracted/compound_zips")
    compound_files = list(extract_dir.rglob("*.json"))
    log.info("Found %d compound JSON files", len(compound_files))
    for i, f in enumerate(compound_files):
        ins, vids = parse_and_insert_file(f, adapter, session, "otrf_compound")
        grand_total += ins
        grand_verdicts += vids
        if (i + 1) % 10 == 0:
            session.commit()
            log.info("  Compound: %d/%d files, %d events", i+1, len(compound_files), grand_total)
    session.commit()
    log.info("Compound done. Total so far: %d events, %d verdicts", grand_total, grand_verdicts)

    # ═══ SOURCE 3: Compound .log files (JSONL) ═══
    log.info("Loading OTRF Compound .log files...")
    log_files = list((OTRF / "compound").rglob("*.log"))
    log.info("Found %d .log files", len(log_files))
    for i, f in enumerate(log_files):
        ins, vids = parse_and_insert_file(f, adapter, session, "otrf_compound")
        grand_total += ins
        grand_verdicts += vids
        if (i + 1) % 20 == 0:
            session.commit()
            log.info("  Logs: %d/%d files, %d events", i+1, len(log_files), grand_total)
    session.commit()
    log.info("All done! Total: %d events inserted", grand_total)

    # Create verdicts via SQL (avoids ORM ne.id=None issue)
    log.info("Creating verdicts via SQL...")
    r1 = session.execute(text("""
        INSERT INTO verdicts (event_id, verdict, note, created_by, created_at)
        SELECT id, 'true_positive', 'OTRF labeled attack dataset', 'otrf_import', NOW()
        FROM events WHERE source = 'otrf_atomic'
    """))
    log.info("  Atomic verdicts: %d", r1.rowcount)
    r2 = session.execute(text("""
        INSERT INTO verdicts (event_id, verdict, note, created_by, created_at)
        SELECT id, 'true_positive', 'OTRF compound attack', 'otrf_import', NOW()
        FROM events WHERE severity = 'high' AND source = 'otrf_compound'
    """))
    log.info("  Compound high-sev verdicts: %d", r2.rowcount)
    r3 = session.execute(text("""
        INSERT INTO verdicts (event_id, verdict, note, created_by, created_at)
        SELECT id, 'true_positive', 'OTRF attack heuristic', 'otrf_import', NOW()
        FROM events WHERE severity IN ('high', 'medium')
        AND source NOT IN ('otrf_atomic', 'otrf_compound')
        AND id NOT IN (SELECT event_id FROM verdicts WHERE event_id IS NOT NULL)
    """))
    log.info("  Other verdicts: %d", r3.rowcount)
    session.commit()

    # ═══ FINAL STATS ═══
    with engine.connect() as conn:
        total = conn.scalar(select(func.count(NormalizedEvent.id)))
        v_total = conn.scalar(select(func.count(Verdict.id)))
        sources = conn.execute(
            select(NormalizedEvent.source, func.count(NormalizedEvent.id))
            .group_by(NormalizedEvent.source).order_by(func.count(NormalizedEvent.id).desc())
        ).fetchall()
        categories = conn.execute(
            select(NormalizedEvent.category, func.count(NormalizedEvent.id))
            .group_by(NormalizedEvent.category).order_by(func.count(NormalizedEvent.id).desc()).limit(15)
        ).fetchall()
        severities = conn.execute(
            select(NormalizedEvent.severity, func.count(NormalizedEvent.id))
            .group_by(NormalizedEvent.severity).order_by(func.count(NormalizedEvent.id).desc())
        ).fetchall()

    log.info("=" * 60)
    log.info("FINAL DATABASE STATUS")
    log.info("  Events: %d", total)
    log.info("  Verdicts: %d", v_total)
    log.info("  By source:")
    for s, c in sources:
        log.info("    %s: %d", s, c)
    log.info("  By category (top 15):")
    for cat, c in categories:
        log.info("    %s: %d", cat, c)
    log.info("  By severity:")
    for sev, c in severities:
        log.info("    %s: %d", sev, c)
    log.info("=" * 60)

    session.close()

if __name__ == "__main__":
    main()
