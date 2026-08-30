"""Test all 11 weakness fixes — backend + API."""

import sys

sys.path.insert(0, ".")
from fastapi.testclient import TestClient

from backend.auth import create_token
from backend.database.connection import SessionLocal
from backend.database.models import User
from backend.main import app

db = SessionLocal()
user = db.query(User).filter_by(username="admin").first()
db.close()

token = create_token(user.id, "admin", "admin")
client = TestClient(app)
headers = {"Authorization": f"Bearer {token}"}

print("=== Test 1: /api/network default ===")
r = client.get("/api/network?limit=3", headers=headers)
data = r.json()
print(f'status={r.status_code} total={data.get("total")}')
items = data.get("items", [])
if items:
    c = items[0]
    print(
        f'  first: local={c["local_ip"]}:{c["local_port"]} -> {c["remote_ip"]}:{c["remote_port"]}'
    )
    print(
        f'    state={c["state"]} sent={c["bytes_sent"]} recv={c["bytes_recv"]} dur={c["duration_seconds"]}s org="{c.get("org","")}"'
    )

print()
print("=== Test 2: /api/network?direction=outbound ===")
r = client.get("/api/network?limit=5&direction=outbound", headers=headers)
out = r.json()
print(f'status={r.status_code} total={out.get("total")}')
for c in out.get("items", [])[:3]:
    print(f'  -> {c["local_ip"]} -> {c["remote_ip"]}:{c["remote_port"]}')

print()
print("=== Test 3: /api/network?since=2026-08-29T00:00:00 ===")
r = client.get("/api/network?limit=5&since=2026-08-29T00:00:00", headers=headers)
print(f'status={r.status_code} total={r.json().get("total")}')

print()
print("=== Test 4: /api/network/geo?ip=142.250.187.14 (Google) ===")
r = client.get("/api/network/geo?ip=142.250.187.14", headers=headers)
print(f"status={r.status_code} body={r.json()}")

print()
print("=== Test 5: /api/network/geo?ip=192.168.1.6 (internal) ===")
r = client.get("/api/network/geo?ip=192.168.1.6", headers=headers)
print(f"status={r.status_code} body={r.json()}")

print()
print("=== Test 6: /api/alerts/suppressions/list ===")
r = client.get("/api/alerts/suppressions/list", headers=headers)
print(f"status={r.status_code}")
body = r.json() if r.status_code == 200 else r.text[:200]
print(f"  body={body}")

print()
print("=== Test 7: verify UDP connections present ===")
r = client.get("/api/network?limit=2000", headers=headers)
items = r.json().get("items", [])
udp = [c for c in items if not c["state"] or c["state"] == "NONE"]
print(f"  total={len(items)} udp/no-state={len(udp)}")

print()
print("=== Test 8: verify org field populated for external IPs ===")
external = [c for c in items if c.get("org")]
print(f"  external with org={len(external)}/{len(items)}")
if external:
    sample = external[0]
    print(
        f'  sample: {sample["remote_ip"]} -> org="{sample["org"]}" sent={sample["bytes_sent"]} recv={sample["bytes_recv"]}'
    )

print()
print("=== Test 9: verify bytes distributed (per-connection) ===")
# Group by PID and sum
from collections import defaultdict

by_pid = defaultdict(lambda: {"count": 0, "sent": 0, "recv": 0})
for c in items:
    by_pid[c["pid"]]["count"] += 1
    by_pid[c["pid"]]["sent"] += c["bytes_sent"]
    by_pid[c["pid"]]["recv"] += c["bytes_recv"]
# Show a PID with multiple connections — bytes should be split evenly
multi = [(pid, d) for pid, d in by_pid.items() if d["count"] > 1 and d["sent"] > 0]
if multi:
    pid, d = multi[0]
    conns = [c for c in items if c["pid"] == pid and c["bytes_sent"] > 0]
    if conns:
        avg_sent = d["sent"] / d["count"]
        per = conns[0]["bytes_sent"]
        print(
            f'  pid={pid} conns={d["count"]} total_sent={d["sent"]} avg={int(avg_sent)} sample_conn_sent={per} match={abs(per - avg_sent) < avg_sent*0.2}'
        )

print()
print("=== Test 10: duration — was it PID age or socket age? ===")
# If duration is small (<60s) for an active connection, it means first_seen is working
active = [
    c for c in items if c["state"] == "ESTABLISHED" and c["duration_seconds"] < 60
]
long = [c for c in items if c["duration_seconds"] > 60]
print(f"  active_under_60s={len(active)} over_60s={len(long)}")
if active:
    c = active[0]
    print(
        f'  short example: {c["local_ip"]}->{c["remote_ip"]} dur={c["duration_seconds"]}s'
    )
if long:
    c = long[0]
    print(
        f'  long example: {c["local_ip"]}->{c["remote_ip"]} dur={c["duration_seconds"]}s'
    )

print()
print("=== ALL TESTS COMPLETE ===")
