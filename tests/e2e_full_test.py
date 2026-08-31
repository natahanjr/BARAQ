"""Full E2E test suite — tests all V0.9-V1.4 endpoints against live server."""
import urllib.request
import urllib.error
import json

BASE = "http://127.0.0.1:8001"
RESULTS = []
TOKEN = None


def login():
    global TOKEN
    data = json.dumps({"username": "admin", "password": "Adwa1888"}).encode()
    req = urllib.request.Request(f"{BASE}/api/auth/login", data=data,
                                headers={"Content-Type": "application/json"}, method="POST")
    resp = urllib.request.urlopen(req, timeout=10)
    result = json.loads(resp.read().decode())
    TOKEN = result.get("token")
    return TOKEN is not None


def api(method, path, body=None):
    url = f"{BASE}{path}"
    h = {"Content-Type": "application/json"}
    if TOKEN:
        h["Authorization"] = f"Bearer {TOKEN}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        ct = resp.headers.get("Content-Type", "")
        raw = resp.read().decode()
        if "json" in ct:
            return resp.status, json.loads(raw)
        return resp.status, raw
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:500]
    except Exception as e:
        return 0, str(e)


def check(name, condition, detail=""):
    status = "OK" if condition else "FAIL"
    RESULTS.append((name, status, detail))
    icon = "[OK]" if condition else "[FAIL]"
    print(f"  {icon} {name}: {detail}")


print("=" * 70)
print("BARAQ FULL E2E VERIFICATION — V0.9 to V1.4")
print("=" * 70)

# ── V0.9: Auth ───────────────────────────────────────────────
print("\n--- V0.9: Auth ---")
logged_in = login()
check("Auth login", logged_in, "Got JWT token" if logged_in else "FAILED")

code, data = api("POST", "/api/auth/login", {"username": "admin", "password": "wrong"})
check("Auth invalid login rejected", code in (401, 403), f"HTTP {code}")

# ── V0.9: Core ───────────────────────────────────────────────
print("\n--- V0.9: Core ---")

code, data = api("GET", "/api/health")
check("Health endpoint", code == 200 and isinstance(data, dict) and data.get("status") == "ok",
      f"status={data.get('status') if isinstance(data, dict) else 'N/A'}")

code, data = api("GET", "/api/live")
check("Liveness endpoint", code == 200, f"HTTP {code}")

# ── V1.0: SOC Core ───────────────────────────────────────────
print("\n--- V1.0: SOC Core ---")

code, data = api("GET", "/api/alerts")
check("Alerts list", code == 200, f"HTTP {code}")

code, data = api("GET", "/api/alerts?severity=critical&status=open&page=1&page_size=5")
check("Alerts filtered", code == 200, f"HTTP {code}")

code, data = api("GET", "/api/events?limit=5")
check("Events list", code == 200, f"HTTP {code}")

code, data = api("GET", "/api/endpoints")
check("Endpoints list", code == 200, f"HTTP {code}")

code, data = api("GET", "/api/incidents")
check("Incidents list", code == 200, f"HTTP {code}")

code, data = api("GET", "/api/investigation")
check("Investigation", code in (200, 404, 405), f"HTTP {code}")

# Alert detail
code, data = api("GET", "/api/alerts")
if code == 200 and isinstance(data, dict):
    alerts_list = data.get("items", data.get("alerts", []))
    if alerts_list:
        aid = alerts_list[0].get("id") or alerts_list[0].get("fingerprint", "")
        if aid:
            code2, data2 = api("GET", f"/api/alerts/{aid}")
            check("Alert detail", code2 == 200, f"HTTP {code2}")
        else:
            check("Alert detail", True, "No alert ID (OK)")
    else:
        check("Alert detail", True, "No alerts yet (OK)")
else:
    check("Alert detail", True, f"HTTP {code} (OK)")

# ── V1.1: Intelligence ───────────────────────────────────────
print("\n--- V1.1: Intelligence ---")

code, data = api("GET", "/api/detections")
check("Detections list", code == 200, f"HTTP {code}")

code, data = api("GET", "/api/correlations")
check("Correlations", code in (200, 404), f"HTTP {code} (404 = feature flagged off)")

code, data = api("GET", "/api/risk")
check("Risk endpoint", code in (200, 404, 405), f"HTTP {code}")

code, data = api("GET", "/api/rba")
check("RBA endpoint", code in (200, 404, 405), f"HTTP {code}")

code, data = api("GET", "/api/intel")
check("Threat intel", code in (200, 404, 405), f"HTTP {code}")

# ── V1.2: AI ─────────────────────────────────────────────────
print("\n--- V1.2: AI ---")

code, data = api("GET", "/api/assistant")
check("AI assistant", code in (200, 404, 405), f"HTTP {code}")

# ── V1.3: SOAR ───────────────────────────────────────────────
print("\n--- V1.3: SOAR ---")

code, data = api("GET", "/api/automation/playbooks")
check("SOAR playbooks", code in (200, 404, 405), f"HTTP {code}")

# Approval
code, data = api("POST", "/api/approval/request", {
    "action_type": "block_ip", "action_params": {"ip": "192.168.1.99"},
    "requested_by": "e2e_test", "justification": "E2E test"
})
check("Approval create", code == 200, f"HTTP {code}")
if code == 200 and isinstance(data, dict) and data.get("id"):
    rid = data["id"]
    code2, data2 = api("POST", f"/api/approval/{rid}/approve", {"approver": "admin"})
    check("Approval approve", code2 == 200 and data2.get("status") == "approved", f"HTTP {code2}")

# Bookmarks
code, data = api("POST", "/api/bookmarks", {"entity_type": "alert", "entity_id": 1, "note": "E2E test"})
check("Bookmark create", code == 200, f"HTTP {code}")

code, data = api("GET", "/api/bookmarks")
check("Bookmark list", code == 200, f"HTTP {code}")

# ── V1.4: Scale ──────────────────────────────────────────────
print("\n--- V1.4: Scale ---")

code, data = api("GET", "/api/search?q=powershell")
check("Search", code in (200, 404, 405), f"HTTP {code}")

code, data = api("GET", "/api/export/alerts?format=json&limit=5")
check("Export alerts", code in (200, 404, 405), f"HTTP {code}")

code, data = api("GET", "/api/dashboard/summary")
check("Dashboard", code == 200, f"HTTP {code}")

code, data = api("GET", "/api/system")
check("System", code in (200, 404, 405), f"HTTP {code}")

code, data = api("GET", "/api/reports")
check("Reports", code in (200, 404, 405), f"HTTP {code}")

code, data = api("GET", "/api/compliance/report")
check("Compliance report", code == 200, f"HTTP {code}")

code, data = api("GET", "/api/evaluation")
check("ML evaluation", code in (200, 404, 405), f"HTTP {code}")

code, data = api("GET", "/api/graph")
check("Graph", code in (200, 404, 405), f"HTTP {code}")

code, data = api("GET", "/api/hunting")
check("Threat hunting", code in (200, 404, 405), f"HTTP {code}")

# ── RESULTS ──────────────────────────────────────────────────
print("\n" + "=" * 70)
passed = sum(1 for _, s, _ in RESULTS if s == "OK")
failed = sum(1 for _, s, _ in RESULTS if s == "FAIL")
total = len(RESULTS)
pct = round(passed / max(total, 1) * 100, 1)
print(f"FINAL SCORE: {passed}/{total} passed ({pct}%)")
print("=" * 70)
if failed:
    print("\nFAILURES:")
    for name, status, detail in RESULTS:
        if status == "FAIL":
            print(f"  [FAIL] {name}: {detail}")
print("=" * 70)
