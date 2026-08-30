"""Trigger ML training via the API."""
import json
import sys
import time
import urllib.request


def api_call(method: str, path: str, data: dict | None = None, api_key: str = "") -> dict:
    url = f"http://127.0.0.1:8001{path}"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())


# Try the dev admin API key
API_KEY = "baraq-dev-admin"

# Trigger training
print("Triggering ML training (async, forced)...")
result = api_call("POST", "/api/system/ml/train?async_mode=true&force=true", api_key=API_KEY)
print(f"Response: {json.dumps(result, indent=2)}")

# Poll status
for i in range(30):
    time.sleep(5)
    status = api_call("GET", "/api/system/ml/status", api_key=API_KEY)
    training = status.get("training", False)
    version = status.get("version")
    samples = status.get("samples")
    trained_at = status.get("trained_at")
    print(f"  [{i*5}s] training={training} version={version} samples={samples} trained_at={trained_at}")
    if not training and version:
        print("\nTraining complete!")
        break

# Final status
print("\n=== Final ML Status ===")
print(f"Version: {status.get('version')}")
print(f"Trained at: {status.get('trained_at')}")
print(f"Samples: {status.get('samples')}")
print(f"Events at train: {status.get('events_at_train')}")
print(f"Scored events: {status.get('scored_events')}")
print(f"Streams: {json.dumps(status.get('streams', {}), indent=2)}")
print(f"Thresholds: {json.dumps(status.get('thresholds', {}), indent=2)}")
