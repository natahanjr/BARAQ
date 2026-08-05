"""Test fixture record builders.

SentinelSOC is a pure-live analyzer; these builders create deterministic
raw collector-shaped records so unit tests can exercise the pipeline
without a runtime simulator. They are NOT registered collectors and are
never used by the live SOC.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.analyzers.normalizer import Normalizer


def _ts(offset_minutes: float = 0.0) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)


def _ts_seconds(offset_seconds: float = 0.0) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)


def logon_failure(user: str = "administrator", source_ip: str = "192.168.99.77", event_id: int = 4625) -> dict:
    return {
        "source": "eventlog",
        "channel": "Security",
        "event_id": event_id,
        "timestamp": _ts(-1).isoformat(),
        "user": user,
        "message": (
            f"An account failed to log on. Account Name: {user}. "
            f"Source Network Address: {source_ip}. Logon Type: 3. "
            f"Sub Status: 0xC000006A."
        ),
        "raw": {"logon_type": 3, "source_ip": source_ip, "sub_status": "0xC000006A"},
    }


def brute_force(attempts: int = 12, user: str = "administrator") -> list[dict]:
    out = []
    for i in range(attempts):
        rec = logon_failure(user=user)
        rec["timestamp"] = _ts(-1 - i * 0.1).isoformat()
        out.append(rec)
    out.append({
        "source": "eventlog", "channel": "Security", "event_id": 4624,
        "timestamp": _ts(-0.5).isoformat(), "user": "alice",
        "message": "An account was successfully logged on. Account Name: alice. Logon Type: 2.",
        "raw": {"logon_type": 2, "source_ip": "127.0.0.1"},
    })
    return out


def suspicious_powershell() -> list[dict]:
    payload = "powershell.exe -NoP -NonI -W Hidden -EncodedCommand SQBFAFgAKAAiAGQAbwB3AG4AbABvAGEAZAAiACkA"
    return [{
        "source": "powershell",
        "channel": "Microsoft-Windows-PowerShell/Operational",
        "event_id": 4104,
        "timestamp": _ts(-1).isoformat(),
        "user": "alice",
        "message": f"Creating Scriptblock text (1 of 1): {payload}",
        "raw": {
            "script_block": payload,
            "command_line": payload,
            "has_encoded": True,
            "has_download": True,
            "has_hidden": True,
        },
    }]


def privilege_escalation(user: str = "erin", new_admin: str = "backdoor_admin") -> list[dict]:
    return [
        {
            "source": "eventlog", "channel": "Security", "event_id": 4720,
            "timestamp": _ts(-2).isoformat(), "user": user,
            "message": f"A user account was created. Account Name: {new_admin}.",
            "raw": {"new_account": new_admin},
        },
        {
            "source": "eventlog", "channel": "Security", "event_id": 4732,
            "timestamp": _ts(-1).isoformat(), "user": user,
            "message": f"A member was added to a security-enabled local group. Member: {new_admin}. Group: Administrators.",
            "raw": {"new_account": new_admin, "group_sid": "S-1-5-32-544", "group": "Administrators"},
        },
        {
            "source": "eventlog", "channel": "Security", "event_id": 4672,
            "timestamp": _ts(-0.5).isoformat(), "user": new_admin,
            "message": "Special privileges assigned to new logon. Account Name: " + new_admin + ".",
            "raw": {},
        },
    ]


def persistence() -> list[dict]:
    binary = "C:\\Users\\Public\\svchost.exe"
    return [
        {
            "source": "eventlog", "channel": "System", "event_id": 7045,
            "timestamp": _ts(-3).isoformat(), "user": "SYSTEM",
            "message": f"A service was installed. Service Name: WindowsUpdateSvc. Service File Name: {binary}.",
            "raw": {"service_name": "WindowsUpdateSvc", "image_path": binary},
        },
        {
            "source": "eventlog", "channel": "Security", "event_id": 4698,
            "timestamp": _ts(-2).isoformat(), "user": "erin",
            "message": f"A scheduled task was created. Task Name: PersistenceTask. Executes {binary}.",
            "raw": {"task_name": "PersistenceTask", "image_path": binary},
        },
    ]


def port_scan(ports: int = 30) -> list[dict]:
    out = []
    for i in range(ports):
        out.append({
            "source": "network", "pid": 4422, "process": "nmap.exe",
            "local_ip": "192.168.99.66", "local_port": 40000 + i,
            "remote_ip": "10.0.0.4", "remote_port": 1 + (i * 137) % 65535,
            "state": "SYN_SENT", "is_listening": False,
            "timestamp": _ts_seconds(-i * 2).isoformat(),
        })
    return out


def lateral_movement() -> list[dict]:
    out: list[dict] = []
    for i, target in enumerate(["10.0.0.5", "10.0.0.6", "10.0.0.7"]):
        out.append({
            "source": "network", "pid": 5432, "process": "explorer.exe",
            "local_ip": "192.168.1.55", "local_port": 50000 + i,
            "remote_ip": target, "remote_port": 445,
            "state": "ESTABLISHED", "is_listening": False,
            "timestamp": _ts(-1 - i).isoformat(),
        })
    return out


def data_staging() -> list[dict]:
    return [
        {
            "source": "eventlog", "channel": "Security", "event_id": 4688,
            "timestamp": _ts(-2).isoformat(), "user": "carol",
            "message": "A new process has been created. Command Line: 7z.exe a -r C:\\Temp\\data.7z C:\\Users\\Public\\Documents\\*",
            "raw": {"command_line": "7z.exe a -r C:\\Temp\\data.7z C:\\Users\\Public\\Documents\\*"},
        },
        {
            "source": "eventlog", "channel": "Security", "event_id": 4688,
            "timestamp": _ts(-1.5).isoformat(), "user": "carol",
            "message": "A new process has been created. Command Line: 7z.exe a -r C:\\Temp\\backup.7z C:\\Users\\carol\\Desktop\\*",
            "raw": {"command_line": "7z.exe a -r C:\\Temp\\backup.7z C:\\Users\\carol\\Desktop\\*"},
        },
    ]


def malicious_file() -> list[dict]:
    return [{
        "source": "malware",
        "file_path": "C:\\Users\\Public\\beacon.exe",
        "file_name": "beacon.exe",
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "md5": "",
        "size": 12345,
        "signed": False,
        "is_malicious": True,
        "signature_name": "known-bad-sample",
        "timestamp": _ts(-1).isoformat(),
    }]


def phishing_email() -> list[dict]:
    return [{
        "source": "email",
        "sender": "noreply@accounts-update.tk",
        "recipient": "alice@corp.local",
        "subject": "URGENT: verify your account password now",
        "body": "Your account will be suspended. Click https://evil.tk/login to verify. Attachment: invoice.exe",
        "attachment_types": ".exe",
        "ip_address": "203.0.113.7",
        "timestamp": _ts(-1).isoformat(),
    }]


def usb_device() -> list[dict]:
    return [{
        "source": "usb",
        "device_name": "Kingston DataTraveler",
        "device_id": "USB\\VID_0951&PID_1666\\07018AC27C",
        "vendor": "Kingston",
        "serial": "07018AC27C",
        "timestamp": _ts(-1).isoformat(),
    }]


def dns_exfil() -> list[dict]:
    return [{
        "source": "dns", "process": "svchost.exe", "pid": 500,
        "query": f"data{i}.evil.xyz", "response": "8.8.4.4",
        "response_size": 600, "timestamp": _ts(-1 - i).isoformat(),
    } for i in range(25)]


def http_exfil() -> list[dict]:
    return [{
        "source": "http", "process": "powershell.exe", "pid": 1234,
        "method": "POST", "url": "https://evil.xyz/upload",
        "host": "evil.xyz", "status_code": 200,
        "request_body_size": 2_000_000, "response_body_size": 5_000_000,
        "timestamp": _ts(-1).isoformat(),
    }]


def benign_baseline(n: int = 60) -> list[dict]:
    users = ["alice", "bob", "carol", "dave"]
    out: list[dict] = []
    for i in range(n):
        user = users[i % len(users)]
        kind = i % 4
        if kind == 0:
            out.append({
                "source": "eventlog", "channel": "Security", "event_id": 4624,
                "timestamp": _ts(-i * 0.5).isoformat(), "user": user,
                "message": "An account was successfully logged on. Account Name: " + user + ".",
                "raw": {"logon_type": 2},
            })
        elif kind == 1:
            out.append({
                "source": "eventlog", "channel": "Security", "event_id": 4688,
                "timestamp": _ts(-i * 0.5).isoformat(), "user": user,
                "message": "A new process has been created. New Process Name: C:\\Windows\\System32\\notepad.exe.",
                "raw": {"new_process": "notepad.exe"},
            })
        elif kind == 2:
            failure = logon_failure(user=user, source_ip=f"192.168.1.{10 + (i % 20)}")
            failure["timestamp"] = _ts(-i * 0.5).isoformat()
            out.append(failure)
        else:
            out.append({
                "source": "network", "pid": 1234, "process": "chrome.exe",
                "local_ip": "192.168.1.20", "local_port": 50000,
                "remote_ip": "8.8.8.8", "remote_port": 443, "state": "ESTABLISHED",
                "is_listening": False, "timestamp": _ts(-i * 0.5).isoformat(),
            })
    return out


def full_suite() -> list[dict]:
    records: list[dict] = []
    records += brute_force()
    records += suspicious_powershell()
    records += privilege_escalation()
    records += persistence()
    records += port_scan()
    records += lateral_movement()
    records += data_staging()
    records += malicious_file()
    records += phishing_email()
    records += usb_device()
    records += dns_exfil()
    records += http_exfil()
    records += benign_baseline(30)
    return records


def run_pipeline_records(records: list[dict]):
    """Insert raw records through the pipeline (test helper)."""
    from backend.database.connection import SessionLocal
    from backend.api.system import run_pipeline

    db = SessionLocal()
    try:
        return run_pipeline(db, records)
    finally:
        db.close()


def add_normalized(db, records: list[dict], event_only: bool = False) -> None:
    from backend.database.models import NetworkConnection, NormalizedEvent

    for r in records:
        if r.get("source") == "network" and not event_only:
            db.add(NetworkConnection(
                pid=r["pid"], process=r["process"], local_ip=r["local_ip"],
                local_port=r["local_port"], remote_ip=r["remote_ip"],
                remote_port=r["remote_port"], state=r["state"],
                is_listening=r["is_listening"],
                observed_at=Normalizer._safe_ts(r["timestamp"]),
            ))
        elif r.get("source") in ("eventlog", "powershell"):
            db.add(NormalizedEvent(**Normalizer().normalize(r)))
    db.commit()
