"""User and Entity Behavior Analytics (UEBA) — baseline profiling per user."""
import logging
import math
from collections import defaultdict
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger("baraq.ueba")


class UserBaseline(BaseModel):
    username: str
    login_hours: list[int] = []
    typical_hosts: list[str] = []
    typical_processes: list[str] = []
    typical_ips: list[str] = []
    event_count_30d: int = 0
    avg_daily_events: float = 0.0
    unique_days_active: int = 0
    risk_score: float = 0.0


class UEBAEngine:
    def __init__(self):
        self._baselines: dict[str, UserBaseline] = {}

    def build_baseline(self, username: str, events: list[dict]) -> UserBaseline:
        hours = defaultdict(int)
        hosts = defaultdict(int)
        processes = defaultdict(int)
        ips = defaultdict(int)
        days = set()
        for e in events:
            ts = e.get("timestamp", "")
            if ts and len(ts) >= 13:
                try:
                    h = int(ts[11:13])
                    hours[h] += 1
                except (ValueError, IndexError):
                    pass
            host = e.get("host", "")
            if host:
                hosts[host] += 1
            proc = e.get("process_name", "")
            if proc:
                processes[proc] += 1
            ip = e.get("src_ip", "")
            if ip:
                ips[ip] += 1
            day = ts[:10] if ts else ""
            if day:
                days.add(day)
        total = len(events)
        baseline = UserBaseline(
            username=username,
            login_hours=sorted(hours.keys()),
            typical_hosts=sorted(hosts.keys(), key=hosts.get, reverse=True)[:5],
            typical_processes=sorted(processes.keys(), key=processes.get, reverse=True)[:10],
            typical_ips=sorted(ips.keys(), key=ips.get, reverse=True)[:5],
            event_count_30d=total,
            avg_daily_events=round(total / max(len(days), 1), 1),
            unique_days_active=len(days),
        )
        self._baselines[username] = baseline
        return baseline

    def detect_anomalies(self, username: str, current_events: list[dict]) -> list[dict]:
        baseline = self._baselines.get(username)
        if not baseline:
            return []
        anomalies = []
        current_hours = set()
        current_hosts = set()
        current_ips = set()
        for e in current_events:
            ts = e.get("timestamp", "")
            if ts and len(ts) >= 13:
                try:
                    current_hours.add(int(ts[11:13]))
                except (ValueError, IndexError):
                    pass
            host = e.get("host", "")
            if host:
                current_hosts.add(host)
            ip = e.get("src_ip", "")
            if ip:
                current_ips.add(ip)
        unusual_hours = current_hours - set(baseline.login_hours)
        if unusual_hours:
            anomalies.append({"type": "unusual_hours", "hours": sorted(unusual_hours), "severity": "medium"})
        new_hosts = current_hosts - set(baseline.typical_hosts)
        if new_hosts:
            anomalies.append({"type": "new_host", "hosts": sorted(new_hosts), "severity": "high"})
        new_ips = current_ips - set(baseline.typical_ips)
        if new_ips:
            anomalies.append({"type": "new_ip", "ips": sorted(new_ips), "severity": "medium"})
        if len(current_events) > baseline.avg_daily_events * 3:
            anomalies.append({"type": "event_volume_spike", "current": len(current_events), "baseline_avg": baseline.avg_daily_events, "severity": "high"})
        return anomalies

    def get_baseline(self, username: str) -> Optional[UserBaseline]:
        return self._baselines.get(username)
