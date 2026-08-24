"""Normalization: telemetry event -> research dataset record.

Converts a BARAQ ``NormalizedEvent`` into the compact research
representation used by the dataset collector. Only fields that actually
apply to the event are populated - no synthetic values. Linked alert /
incident / analyst labels are resolved in bulk (per collection batch),
never per event.
"""

from __future__ import annotations

from datetime import datetime

from backend.database.models import NormalizedEvent

from .fingerprint import fingerprint_row

#: CSV column order - stable schema v1.
CSV_FIELDS = [
    "dataset_event_id",
    "timestamp",
    "event_type",
    "event_source",
    "host_id",
    "host_name",
    "user",
    "process_name",
    "parent_process",
    "command_line",
    "file_path",
    "source_ip",
    "destination_ip",
    "destination_port",
    "protocol",
    "authentication_result",
    "severity",
    "rule_id",
    "mitre_technique",
    "anomaly_score",
    "entity_risk",
    "alert_id",
    "incident_id",
    "analyst_label",
    "collector_version",
]

#: Event-id -> research event-type bucket (drives stats + CSV event_type).
_TYPE_BY_EVENT_ID = {
    4688: "Process",
    4689: "Process",
    4104: "PowerShell",
    4103: "PowerShell",
    4624: "Authentication",
    4625: "Authentication",
    4622: "Authentication",
    4720: "Authentication",
    4732: "Authentication",
    4672: "Authentication",
    4771: "Authentication",
    4776: "Authentication",
    5156: "Network",
    5157: "Network",
    5158: "Network",
    5140: "Network",
    5145: "Network",
    4663: "File/System",
    4656: "File/System",
    4660: "File/System",
    4657: "File/System",
    7045: "File/System",
    4698: "File/System",
    1102: "Other",
    6005: "Other",
    7036: "Other",
}

_CATEGORY_TYPE = {
    "Process": "Process",
    "Network": "Network",
    "Login": "Authentication",
    "Authentication": "Authentication",
    "File": "File/System",
    "PowerShell": "PowerShell",
    "Script": "PowerShell",
}

#: Facts keys carried into the research payload (compact, no full raw copy).
_PAYLOAD_FACTS = (
    "new_process",
    "NewProcessName",
    "ParentProcessName",
    "CommandLine",
    "Image",
    "source_ip",
    "SourceIp",
    "DestinationIp",
    "DestinationPort",
    "Protocol",
    "TargetFilename",
    "ObjectName",
    "logon_type",
    "account_name",
    "has_encoded",
    "has_download",
    "has_remote",
    "has_hidden",
    "cmdline_len",
)

#: verdict -> analyst label mapping.
_LABEL_BY_VERDICT = {
    "true_positive": "malicious",
    "false_positive": "benign",
    "expected_behavior": "suspicious",
}

_SECRET_CMD_MARKERS = ("password", "passwd", "pwd=", "token", "api_key", "secret", "credential")


def event_type(ev: NormalizedEvent) -> str:
    """Research event-type bucket for an event."""
    mapped = _TYPE_BY_EVENT_ID.get(ev.event_id or 0)
    if mapped:
        return mapped
    return _CATEGORY_TYPE.get(ev.category or "", "Other")


def _facts(ev: NormalizedEvent) -> dict:
    if not ev.raw_json:
        return {}
    raw = ev.raw_json
    facts = raw.get("facts") if isinstance(raw, dict) else {}
    return facts if isinstance(facts, dict) else {}


def _fact(ev: NormalizedEvent, *keys: str) -> str:
    facts = _facts(ev)
    for key in keys:
        for k in facts:
            if k.lower() == key.lower() and facts[k] not in (None, ""):
                return str(facts[k])
    return ""


def _auth_result(ev: NormalizedEvent) -> str:
    """Best-effort authentication outcome for login events."""
    if ev.event_id == 4625:
        return "failure"
    if ev.event_id == 4624:
        return "success"
    status = _fact(ev, "Status", "SubStatus", "LogonResult").strip().lower()
    if not status:
        return ""
    if status in ("0xc000006a", "0xc0000234", "0xc0000072", "failure", "fail"):
        return "failure"
    if status in ("0x0", "success", "successes"):
        return "success"
    return status


def to_dataset_row(
    ev: NormalizedEvent,
    labels: dict,
    risk_map: dict,
    anonymizer,
    include_labels: bool,
    collector_version: str,
    ts_override: datetime | None = None,
) -> tuple[str, dict]:
    """Return (fingerprint, flat research row) for one event."""
    ts = ts_override or ev.timestamp
    cmdline = _fact(ev, "CommandLine", "command_line")
    user = ev.user or ""
    host = ev.host or ""
    host_id = _fact(ev, "computer") or host

    row: dict = {
        "dataset_event_id": ev.id,
        "timestamp": ts.isoformat() if ts else "",
        "event_type": event_type(ev),
        "event_source": ev.source or "",
        "host_id": anonymizer.field("host", host_id),
        "host_name": anonymizer.field("host", host),
        "user": anonymizer.field("user", user),
        "process_name": anonymizer.field("process", _fact(ev, "new_process", "NewProcessName", "Image")),
        "parent_process": anonymizer.field("process", _fact(ev, "ParentProcessName", "parent_process", "parent_image", "parent_name")),
        "command_line": anonymizer.command_line(cmdline),
        "file_path": anonymizer.file_path(_fact(ev, "TargetFilename", "ObjectName", "TargetObject")),
        "source_ip": anonymizer.ips(_fact(ev, "source_ip", "SourceIp", "IpAddress")),
        "destination_ip": anonymizer.ips(_fact(ev, "DestinationIp", "TargetServerName")),
        "destination_port": _fact(ev, "DestinationPort"),
        "protocol": _fact(ev, "Protocol"),
        "authentication_result": _auth_result(ev),
        "severity": ev.severity or ev.risk or "",
        "rule_id": "",
        "mitre_technique": "",
        "anomaly_score": round(float(ev.ml_score), 4) if ev.ml_score is not None else "",
        "entity_risk": "",
        "alert_id": "",
        "incident_id": "",
        "analyst_label": "",
        "collector_version": collector_version,
    }

    if include_labels:
        meta = labels.get(ev.id)
        if meta:
            row["rule_id"] = meta.get("rule", "")
            row["mitre_technique"] = meta.get("mitre", "")
            row["alert_id"] = meta.get("alert_id") or ""
            row["incident_id"] = meta.get("incident_id") or ""
            label = meta.get("label")
            row["analyst_label"] = _LABEL_BY_VERDICT.get(label, label or "")

        ent_risk = risk_map.get(user) or risk_map.get(host)
        if ent_risk is not None:
            row["entity_risk"] = round(float(ent_risk), 2)

    payload = {
        "event_id": ev.event_id,
        "category": ev.category,
        "message": anonymizer.text((ev.message or "")[:500]),
        "is_anomaly": bool(ev.is_anomaly),
        "data_integrity": ev.data_integrity,
        "facts": {
            k: str(v)[:500]
            for k, v in _facts(ev).items()
            if k in _PAYLOAD_FACTS and v not in (None, "")
        },
    }
    # the stored payload carries both the flat CSV fields and the extras,
    # so exports and stats read from one place
    payload = {**row, **payload}

    fingerprint = fingerprint_row(ts, row)
    return fingerprint, {**row, "_payload": payload}