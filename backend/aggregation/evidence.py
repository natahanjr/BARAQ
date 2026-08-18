"""Phase 4 evidence + observables (spec 4.23, 4.24).

Evidence is preserved from every member alert as field/value/reason rows -
never reduced to "Multiple alerts detected". Observables are aggregated
as unique sets per category (hosts, users, source_ips, destination_ips,
processes, file_paths, domains), and the original alert-level observables
are never lost (they stay on the member alerts and their evidence rows).
"""
from __future__ import annotations

from typing import Protocol

from backend.aggregation.contract import OBSERVABLE_KEYS
from backend.alerting.models import AlertRecord


class EvidenceItem(Protocol):
    field: str
    value: object
    reason: str


def evidence_rows(alert: AlertRecord) -> list[dict]:
    """Evidence rows for one member alert (spec 4.23)."""
    rows: list[dict] = []
    for item in alert.evidence or []:
        if isinstance(item, dict):
            rows.append(
                {
                    "field": str(item.get("field", "")),
                    "value": str(item.get("value", "")),
                    "reason": str(item.get("reason", "")) or f"Alert {alert.alert_id}",
                }
            )
    if not rows:
        rows.append(
            {
                "field": "alert",
                "value": alert.title,
                "reason": f"Alert {alert.alert_id}",
            }
        )
    return rows


def _scan_observables(alert: AlertRecord, buckets: dict[str, set]) -> None:
    """Fold the alert's raw observables strings into typed buckets.

    Observables carry a ``category:value`` prefix (e.g. ``host:ml-host``,
    ``ip:185.0.0.1``, ``process:powershell.exe``). Unknown prefixes are
    preserved under a ``raw`` bucket so nothing is lost.
    """
    category_map = {
        "host": "hosts",
        "user": "users",
        "ip": "source_ips",
        "src": "source_ips",
        "source": "source_ips",
        "dest": "destination_ips",
        "dst": "destination_ips",
        "process": "processes",
        "file": "file_paths",
        "path": "file_paths",
        "domain": "domains",
    }
    for obs in alert.observables or []:
        if not isinstance(obs, str):
            continue
        if ":" in obs:
            category, _, value = obs.partition(":")
            target = category_map.get(category.strip().lower())
            if target is not None:
                buckets[target].add(value.strip())
                continue
        buckets.setdefault("raw", set()).add(obs)


def aggregate_observables(alerts: list[AlertRecord]) -> dict:
    """Unique observables per category (spec 4.24), field-derived + raw."""
    buckets: dict[str, set] = {key: set() for key in OBSERVABLE_KEYS}
    for alert in alerts:
        if alert.host_name or alert.host_id:
            buckets["hosts"].add(alert.host_name or alert.host_id)
        if alert.username or alert.user_id:
            buckets["users"].add(alert.username or alert.user_id)
        if alert.source_ip:
            buckets["source_ips"].add(alert.source_ip)
        if alert.destination_ip:
            buckets["destination_ips"].add(alert.destination_ip)
        _scan_observables(alert, buckets)
    result: dict = {}
    for key in OBSERVABLE_KEYS:
        result[key] = sorted(buckets[key])
    if "raw" in buckets:
        result["raw"] = sorted(buckets["raw"])
    return result


def merge_observables(existing: dict | None, new: dict | None) -> dict:
    """Idempotent union of two observables dicts."""
    merged: dict[str, set] = {}
    for source in (existing or {}, new or {}):
        for key, values in source.items():
            merged.setdefault(key, set()).update(values if isinstance(values, list) else [])
    return {key: sorted(values) for key, values in merged.items()}