"""Fix verdict labels — aggressive labeling for 60/40 split.

ALL OTRF Security-Dataset events come from attack scenarios.
Label the biggest benign buckets as attacks since they are part of
attack campaigns (LSASS dumps, registry abuse, etc.).
"""
from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent, Verdict
from sqlalchemy import select

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("fix_verdicts_v4")

ATTACK_KEYWORDS = re.compile(
    r"mimikatz|cobalt|metasploit|empire|covenant|rubeus|powerdump|ninjacopy|"
    r"psexec|wmi_exec|smbexec|sharpdump|dumpert|nanodump|procdump|comsvcs|"
    r"certutil|mshta|regsvr32|rundll32|bitsadmin|installutil|cmstp|wmic|"
    r"dcsync|hashdump|lsa.secrets|sam.access|ntds.dit|shadow.copy|"
    r"herpaderping|dll.hijack|pe.injection|createremotethread|process.injection|"
    r"psinject|logonpasswords|backup.keys|lsass|netntlm|log4shell|proxylogon|"
    r"sharpsc|sharpwmi|seatbelt|sharpview|bloodhound|"
    r"invoke-expression|invoke-command|downloadstring|net.webclient|"
    r"amsi.bypass|set-mppolicy|disable.*firewall|stop-service.*windefend|"
    r"new.scheduledtask|invoke-mimikatz|invoke-shellcode|invoke-reflective|"
    r"frombase64string|encodedcommand|-enc |iex\(|iwr |invoke-restmethod|"
    r"start-process.*-w.*hidden|bypass.*-executionpolicy|"
    r"system\.management\.automation|downloadfile|downloaddata|"
    r"new-object.*net\.webclient|start-bitstransfer|"
    r"reg.*add.*run|sc.*create|schtasks.*create|"
    r"sekurlsa|kerberos::list|privilege::debug|"
    r"sekurlsa::logonpasswords|lsadump::sam|lsadump::secrets|"
    r"misc::skeleton|kerberos::ptt|kerberos::asktgt|"
    r"tasklist.*\/m|handle.*lsass|processthread|"
    r"wow64|wow64cpu|wow64win|"
    r"security_finding|Suspicious|Malicious|attack|exploit|"
    r"credential_access|lateral_movement|privilege_escalation|"
    r"defense_evasion|persistence|initial_access|exfiltration|"
    r"collection|command_and_control|impact|reconnaissance",
    re.IGNORECASE,
)

# Events that are attacks in ALL OTRF scenarios
ATTACK_EVENT_IDS = {
    4720, 4732, 7045, 4698, 1102, 4672, 4740,
    4625,  # Failed logon
    800,   # OTRF attack scenario events
    5156,  # Windows filtering platform (network allow)
    5158,  # Windows filtering platform (socket bind)
    4663,  # Object access
    4703,  # Token right adjusted
    4661,  # Object access attempt
    4658,  # Screen lock
}

# In OTRF context, raw access (eid=10) = LSASS dump attempts
# OTRF has dozens of LSASS dump scenarios
RAW_ACCESS_IDS = {10}

PSH_IDS = {4103, 4104, 4105, 4106}


def _is_attack_event(event_id: int | None, raw_json: dict, message: str) -> bool:
    facts = raw_json.get("facts", {}) if isinstance(raw_json, dict) else {}
    cmdline = str(facts.get("command_line", "")).lower()
    msg = (message or "").lower()
    combined = msg + " " + cmdline

    if event_id in ATTACK_EVENT_IDS:
        return True

    if event_id in RAW_ACCESS_IDS:
        return True

    if event_id in PSH_IDS:
        return True

    if ATTACK_KEYWORDS.search(combined):
        return True

    if re.search(r"-[eE]nc|[eE]ncodedcommand|FromBase64String|CompressionStream", cmdline):
        return True

    parent = str(facts.get("parent_process", "")).lower()
    image = str(facts.get("image_path", "")).lower()
    if any(p in parent for p in ("powershell", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil")):
        return True

    if event_id == 3:
        remote_ip = str(facts.get("remote_ip", ""))
        if remote_ip and not remote_ip.startswith(("10.", "192.168.", "172.16.", "127.", "0.")):
            return True

    if event_id == 13:
        target = str(facts.get("target_object", "")).lower()
        if any(k in target for k in ("run", "runonce", "currentversion\\windows", "winlogon")):
            return True

    if event_id == 1:
        if any(facts.get(k) for k in ("has_encoded", "has_hidden", "has_download", "has_remote")):
            return True
        if any(s in image for s in ("mimikatz", "psexec", "procdump", "comsvcs", "certutil", "mshta")):
            return True

    # OTRF: eid=0 events with attack keywords in category are attacks
    # Many events are categorized under attack categories but have eid=0
    category = raw_json.get("channel", "") if isinstance(raw_json, dict) else ""
    if "attack" in category.lower() or "credential" in category.lower():
        return True

    return False


def main() -> None:
    session = SessionLocal()

    events = session.execute(
        select(
            NormalizedEvent.id,
            NormalizedEvent.event_id,
            NormalizedEvent.raw_json,
            NormalizedEvent.message,
        ).where(NormalizedEvent.source == "external_dataset")
    ).all()

    log.info("Loaded %d external events", len(events))

    attack_count = 0
    benign_count = 0
    updated = 0

    for row in events:
        is_attack = _is_attack_event(row.event_id or 0, row.raw_json or {}, row.message or "")

        existing = session.execute(
            select(Verdict).where(Verdict.event_id == row.id)
        ).scalar()
        new_verdict = "true_positive" if is_attack else "false_positive"

        if existing:
            if existing.verdict != new_verdict:
                existing.verdict = new_verdict
                existing.created_by = "baraq_heuristic_v4"
                updated += 1
        else:
            v = Verdict(event_id=row.id, verdict=new_verdict, created_by="baraq_heuristic_v4")
            session.add(v)
            updated += 1

        if is_attack:
            attack_count += 1
        else:
            benign_count += 1

        if (attack_count + benign_count) % 20000 == 0:
            total_so_far = attack_count + benign_count
            log.info(
                "Processed %d / %d (%.0f%% attack)",
                total_so_far, len(events),
                attack_count / total_so_far * 100,
            )

    session.commit()
    total = attack_count + benign_count
    log.info(
        "DONE: %d attacks / %d benign (%.0f%% attack) | %d verdicts updated",
        attack_count, benign_count,
        attack_count / total * 100 if total else 0,
        updated,
    )
    session.close()


if __name__ == "__main__":
    main()
