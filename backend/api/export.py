"""Universal data export API — CSV and JSON for all collected data."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import (
    Alert,
    DatasetEvent,
    DnsQuery,
    EmailMessage,
    Endpoint,
    EntityRisk,
    FileScan,
    HttpRequest,
    Incident,
    NetworkConnection,
    NormalizedEvent,
    ProcessRecord,
    ThreatIntelRecord,
    UsbDevice,
    VulnFinding,
)
from backend.security import require_auth

router = APIRouter(prefix="/api/export", tags=["export"], dependencies=[Depends(require_auth)])

# ── Registry of exportable data types ──────────────────────────────────────

EXPORTABLE: dict[str, dict] = {}


def _reg(name: str, model, label: str, columns: list[str], header: list[str] | None = None):
    EXPORTABLE[name] = {
        "model": model,
        "label": label,
        "columns": columns,
        "header": header or columns,
    }


_reg(
    "events",
    NormalizedEvent,
    "Events",
    ["id", "event_id", "category", "source", "user", "host", "severity", "risk", "message", "timestamp", "ml_score", "risk_score", "is_anomaly"],
)
_reg(
    "alerts",
    Alert,
    "Alerts",
    ["id", "name", "severity", "status", "confidence", "score", "mitre_id", "mitre_tactic", "host", "evidence", "recommendation", "created_at", "risk_score", "risk_level"],
)
_reg(
    "network",
    NetworkConnection,
    "Network Connections",
    ["id", "pid", "process", "local_ip", "local_port", "remote_ip", "remote_port", "state", "is_listening", "bytes_sent", "bytes_recv", "duration_seconds", "observed_at", "org"],
)
_reg(
    "processes",
    ProcessRecord,
    "Processes",
    ["id", "pid", "ppid", "name", "path", "command_line", "parent_name", "user", "is_new", "observed_at", "org"],
)
_reg(
    "dns",
    DnsQuery,
    "DNS Queries",
    ["id", "process", "pid", "query", "response", "response_size", "observed_at", "org"],
)
_reg(
    "http",
    HttpRequest,
    "HTTP Requests",
    ["id", "process", "pid", "method", "url", "host", "status_code", "request_body_size", "response_body_size", "observed_at", "org"],
)
_reg(
    "emails",
    EmailMessage,
    "Email Messages",
    ["id", "sender", "recipient", "subject", "body", "attachment_types", "ip_address", "received_at", "org"],
)
_reg(
    "usb",
    UsbDevice,
    "USB Devices",
    ["id", "device_name", "device_id", "vendor", "serial", "inserted_at", "org"],
)
_reg(
    "file_scans",
    FileScan,
    "File Scans",
    ["id", "file_path", "file_name", "sha256", "md5", "size", "signed", "is_malicious", "signature_name", "scanned_at", "org"],
)
_reg(
    "vulns",
    VulnFinding,
    "Vulnerability Findings",
    ["id", "host", "product", "version", "cve_id", "cvss", "severity", "description", "remediation", "found_at", "org"],
)
_reg(
    "endpoints",
    Endpoint,
    "Endpoints",
    ["id", "agent_id", "host", "org", "last_seen", "records_total", "events_total", "alerts_total", "agent_version", "os_info", "health_status"],
)
_reg(
    "incidents",
    Incident,
    "Incidents",
    ["id", "title", "description", "severity", "status", "owner", "mitre_id", "host", "org", "risk_score", "confidence", "created_at"],
)
_reg(
    "threat_intel",
    ThreatIntelRecord,
    "Threat Intelligence",
    ["id", "indicator", "kind", "category", "label", "confidence", "sources", "last_checked", "org"],
)
_reg(
    "entity_risk",
    EntityRisk,
    "Entity Risk",
    ["id", "entity_kind", "entity_name", "score", "risk_level", "alerts_count", "last_updated"],
)
_reg(
    "dataset_events",
    DatasetEvent,
    "Dataset Events",
    ["id", "event_fingerprint", "source_event_id", "event_type", "payload_normalized", "created_at"],
)


@router.get("/types")
def list_export_types():
    """List all available data types for export."""
    return {
        "types": [
            {"key": k, "label": v["label"], "columns": v["columns"]}
            for k, v in EXPORTABLE.items()
        ]
    }


@router.get("/{data_type}")
def export_data(
    data_type: str,
    format: str = Query("csv", regex="^(csv|json)$"),
    limit: int = Query(10000, ge=1, le=100000),
    offset: int = Query(0, ge=0),
    since: str | None = Query(None, description="ISO timestamp filter"),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    search: str | None = Query(None, description="Search in message/evidence/name"),
    db: Session = Depends(get_db),
):
    """Export collected data as CSV or JSON."""
    if data_type not in EXPORTABLE:
        raise HTTPException(404, f"Unknown data type: {data_type}. Available: {', '.join(EXPORTABLE.keys())}")

    spec = EXPORTABLE[data_type]
    model = spec["model"]
    columns = spec["columns"]
    header = spec["header"]
    label = spec["label"]

    # Build query
    stmt = select(model)

    # Apply filters based on available columns
    if since and hasattr(model, "timestamp"):
        stmt = stmt.where(model.timestamp >= since)
    elif since and hasattr(model, "observed_at"):
        stmt = stmt.where(model.observed_at >= since)
    elif since and hasattr(model, "created_at"):
        stmt = stmt.where(model.created_at >= since)
    elif since and hasattr(model, "received_at"):
        stmt = stmt.where(model.received_at >= since)
    elif since and hasattr(model, "scanned_at"):
        stmt = stmt.where(model.scanned_at >= since)
    elif since and hasattr(model, "inserted_at"):
        stmt = stmt.where(model.inserted_at >= since)
    elif since and hasattr(model, "found_at"):
        stmt = stmt.where(model.found_at >= since)
    elif since and hasattr(model, "last_seen"):
        stmt = stmt.where(model.last_seen >= since)
    elif since and hasattr(model, "last_checked"):
        stmt = stmt.where(model.last_checked >= since)
    elif since and hasattr(model, "last_updated"):
        stmt = stmt.where(model.last_updated >= since)

    if severity and hasattr(model, "severity"):
        stmt = stmt.where(model.severity == severity)
    if status and hasattr(model, "status"):
        stmt = stmt.where(model.status == status)

    # Text search
    if search:
        search_lower = f"%{search.lower()}%"
        if hasattr(model, "message"):
            stmt = stmt.where(func.lower(model.message).like(search_lower))
        elif hasattr(model, "evidence"):
            stmt = stmt.where(func.lower(model.evidence).like(search_lower))
        elif hasattr(model, "name"):
            stmt = stmt.where(func.lower(model.name).like(search_lower))
        elif hasattr(model, "query"):
            stmt = stmt.where(func.lower(model.query).like(search_lower))
        elif hasattr(model, "url"):
            stmt = stmt.where(func.lower(model.url).like(search_lower))
        elif hasattr(model, "indicator"):
            stmt = stmt.where(func.lower(model.indicator).like(search_lower))

    # Count total
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = db.scalar(count_stmt) or 0

    # Apply pagination
    stmt = stmt.order_by(getattr(model, "id", model.id) if hasattr(model, "id") else model.id)
    stmt = stmt.offset(offset).limit(limit)

    rows = db.execute(stmt).scalars().all()

    # Serialize rows
    def serialize(row):
        data = {}
        for col in columns:
            val = getattr(row, col, None)
            if isinstance(val, datetime):
                val = val.isoformat()
            elif isinstance(val, bool):
                val = val
            elif val is None:
                val = ""
            else:
                val = str(val)
            data[col] = val
        return data

    serialized = [serialize(r) for r in rows]

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"baraq_{data_type}_{ts}"

    if format == "json":
        content = json.dumps(
            {
                "export_type": data_type,
                "label": label,
                "total": total,
                "returned": len(serialized),
                "offset": offset,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "data": serialized,
            },
            indent=2,
            default=str,
        )
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}.json"'},
        )

    # CSV format
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(serialized)

    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'},
    )
