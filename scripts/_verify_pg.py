"""Temporary Postgres verification - run backend flows against migrated PG."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["SENTINEL_DATABASE_URL"] = "postgresql+psycopg://postgres@127.0.0.1:55432/sentinel"
os.environ["SENTINEL_NO_SCHEDULER"] = "1"
os.environ["SENTINEL_SCHEDULER_ENABLED"] = "0"
os.environ["SENTINEL_TOAST_ENABLED"] = "0"

from fastapi.testclient import TestClient  # noqa: E402
from backend.database.connection import engine, normalize_database_url  # noqa: E402
from backend.main import app  # noqa: E402

print("engine URL:", normalize_database_url(os.environ["SENTINEL_DATABASE_URL"]))
print("dialect:", engine.dialect.name)

with TestClient(app) as c:
    # login (bootstrap admin was migrated from SQLite)
    login = c.post("/api/auth/login", json={"username": "admin", "password": "sentineladmin"})
    print("login:", login.status_code, login.json().get("user", {}).get("username"))
    token = login.json().get("token")
    h = {"Authorization": f"Bearer {token}"}
    as_ = c.get("/api/auth/users", headers=h)
    print("users:", as_.status_code, [u["username"] for u in as_.json().get("items", [])])
    s = c.get("/api/dashboard/summary")
    print("summary:", s.status_code, "score=", s.json().get("security_score"),
          "events=", s.json().get("total_events"))
    e = c.get("/api/events", params={"limit": 3})
    print("events:", e.status_code, "rows=", e.json().get("total"))
    inv = c.get("/api/alerts", params={"page_size": 3})
    print("alerts:", inv.status_code, "open=", inv.json().get("total"))
    # exercise the analytics/aggregates that were SQLite-sensitive
    tl = c.get("/api/dashboard/timeline", params={"hours": 24})
    print("timeline:", tl.status_code, "buckets=", len(tl.json()))
    sd = c.get("/api/dashboard/severity-distribution")
    print("severity-dist:", sd.status_code)
    # agent ingest path (the fleet-scale reason for Postgres)
    ingest = c.post(
        "/api/ingest",
        headers={"X-Agent-Key": "sentinel-agent-dev"},
        json={"records": [{"event_id": 901, "source": "process", "name": "whoami.exe",
                           "pid": 1, "timestamp": "2026-08-05T20:00:00Z"}],
              "host": "pg-test-host"},
    )
    print("ingest:", ingest.status_code, ingest.json().get("saved_events"), "events saved")
    ep = c.get("/api/endpoints").json()["items"]
    print("endpoints:", [e["agent_id"] for e in ep])