"""SQLAlchemy ORM models for the SentinelSOC local database (SQLite)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class NormalizedEvent(Base):
    """A normalised security event, the atomic unit of the pipeline.

    Raw Windows events from every collector are converted into this shape:
    Event ID / Category / User / Risk / Timestamp / Host / Message / Raw.
    """

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[int] = mapped_column(Integer, index=True, default=0)
    category: Mapped[str] = mapped_column(String(64), index=True, default="Other")
    source: Mapped[str] = mapped_column(String(32), index=True, default="unknown")
    user: Mapped[str] = mapped_column(String(128), index=True, default="-")
    host: Mapped[str] = mapped_column(String(128), default="-")
    risk: Mapped[str] = mapped_column(String(16), index=True, default="Low")
    severity: Mapped[str] = mapped_column(String(16), index=True, default="info")
    message: Mapped[str] = mapped_column(Text, default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    raw_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "category": self.category,
            "source": self.source,
            "user": self.user,
            "host": self.host,
            "risk": self.risk,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "message": self.message,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "raw": self.raw_json,
            "is_anomaly": self.is_anomaly,
            "ml_score": self.ml_score,
        }


class Alert(Base):
    """A detection alert enriched with MITRE ATT&CK mapping."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True, default="medium")
    status: Mapped[str] = mapped_column(String(16), index=True, default="open")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    mitre_id: Mapped[str] = mapped_column(String(16), index=True, default="T0000")
    mitre_name: Mapped[str] = mapped_column(String(128), default="")
    mitre_tactic: Mapped[str] = mapped_column(String(64), default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    rule: Mapped[str] = mapped_column(String(64), index=True, default="")
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    detection_method: Mapped[str] = mapped_column(String(16), index=True, default="rule")
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)
    risk_level: Mapped[str] = mapped_column(String(16), index=True, default="MEDIUM")
    events: Mapped[list["AlertEventLink"]] = relationship(
        "AlertEventLink", back_populates="alert", cascade="all, delete-orphan"
    )
    notes: Mapped[list["AnalystNote"]] = relationship(
        "AnalystNote", back_populates="alert", cascade="all, delete-orphan"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    def to_dict(self, include_events: bool = False) -> dict:
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "confidence": self.confidence,
            "score": self.score,
            "detection_method": self.detection_method,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "mitre_id": self.mitre_id,
            "mitre_name": self.mitre_name,
            "mitre_tactic": self.mitre_tactic,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "rule": self.rule,
            "event_count": self.event_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_events:
            data["events"] = [
                link.event.to_dict() for link in sorted(self.events, key=lambda l: l.event_id)
            ]
            data["notes"] = [
                {"id": n.id, "note": n.note, "created_at": n.created_at.isoformat()}
                for n in sorted(self.notes, key=lambda n: n.created_at)
            ]
        return data


class AlertEventLink(Base):
    """Many-to-many link between alerts and the evidence events."""

    __tablename__ = "alert_events"
    __table_args__ = (UniqueConstraint("alert_id", "event_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    event_id: Mapped[int] = mapped_column(
        ForeignKey("events.id", ondelete="CASCADE"), index=True
    )
    alert: Mapped[Alert] = relationship(back_populates="events")
    event: Mapped[NormalizedEvent] = relationship()


class ProcessRecord(Base):
    """Snapshot of a running process observed by the process collector."""

    __tablename__ = "processes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pid: Mapped[int] = mapped_column(Integer, index=True)
    ppid: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(256), index=True)
    path: Mapped[str] = mapped_column(Text, default="")
    command_line: Mapped[str] = mapped_column(Text, default="")
    parent_name: Mapped[str] = mapped_column(String(256), default="")
    user: Mapped[str] = mapped_column(String(128), default="")
    is_new: Mapped[bool] = mapped_column(Boolean, default=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "path": self.path,
            "command_line": self.command_line,
            "parent_name": self.parent_name,
            "user": self.user,
            "is_new": self.is_new,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
        }


class NetworkConnection(Base):
    """An observed TCP connection or listening socket."""

    __tablename__ = "network_connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pid: Mapped[int] = mapped_column(Integer, default=0)
    process: Mapped[str] = mapped_column(String(256), default="")
    local_ip: Mapped[str] = mapped_column(String(64), default="")
    local_port: Mapped[int] = mapped_column(Integer, default=0)
    remote_ip: Mapped[str] = mapped_column(String(64), index=True, default="")
    remote_port: Mapped[int] = mapped_column(Integer, default=0)
    state: Mapped[str] = mapped_column(String(32), default="")
    is_listening: Mapped[bool] = mapped_column(Boolean, default=False)
    bytes_sent: Mapped[int] = mapped_column(Integer, default=0)
    bytes_recv: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "process": self.process,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "state": self.state,
            "is_listening": self.is_listening,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "duration_seconds": self.duration_seconds,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
        }


class DnsQuery(Base):
    """A DNS query observed by the DNS monitor (Sysmon Event 22 / snoop).

    No live packet capture by default; the collector reads the Sysmon DNS
    channel (Event 22) and/or a configured query snapshot file so the
    detection rules can reason over real resolver activity.
    """

    __tablename__ = "dns_queries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    process: Mapped[str] = mapped_column(String(256), default="")
    pid: Mapped[int] = mapped_column(Integer, default=0)
    query: Mapped[str] = mapped_column(String(512), index=True)
    response: Mapped[str] = mapped_column(String(512), default="")
    response_size: Mapped[int] = mapped_column(Integer, default=0)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "process": self.process,
            "pid": self.pid,
            "query": self.query,
            "response": self.response,
            "response_size": self.response_size,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
        }


class HttpRequest(Base):
    """Metadata for an HTTP/S request observed by the HTTP monitor.

    Mirrors what a local HTTP monitor (MITM proxy, Windows filter driver or
    Sysmon-assisted logging) can expose without deep packet inspection.
    """

    __tablename__ = "http_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    process: Mapped[str] = mapped_column(String(256), default="")
    pid: Mapped[int] = mapped_column(Integer, default=0)
    method: Mapped[str] = mapped_column(String(16), default="GET")
    url: Mapped[str] = mapped_column(String(1024), index=True)
    host: Mapped[str] = mapped_column(String(256), default="")
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    request_body_size: Mapped[int] = mapped_column(Integer, default=0)
    response_body_size: Mapped[int] = mapped_column(Integer, default=0)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "process": self.process,
            "pid": self.pid,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "status_code": self.status_code,
            "request_body_size": self.request_body_size,
            "response_body_size": self.response_body_size,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
        }


class EmailMessage(Base):
    """An email message (metadata) ingested for phishing analysis.

    The email collector ingests real message metadata from a configured source
    (e.g. an EMF/.msg export directory or a local mail spool). No live inbox
    scraping is performed; detection runs over whichever messages are present.
    """

    __tablename__ = "emails"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender: Mapped[str] = mapped_column(String(256), default="")
    recipient: Mapped[str] = mapped_column(String(256), default="")
    subject: Mapped[str] = mapped_column(String(512), default="")
    body: Mapped[str] = mapped_column(Text, default="")
    attachment_types: Mapped[str] = mapped_column(String(512), default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "sender": self.sender,
            "recipient": self.recipient,
            "subject": self.subject,
            "attachment_types": self.attachment_types,
            "ip_address": self.ip_address,
            "received_at": self.received_at.isoformat() if self.received_at else None,
        }


class UsbDevice(Base):
    """A removable/USB device insertion observed by the USB monitor.

    Mirrors Windows Security/Kernel-PnP events 6416 and 6420 (new external
    device recognised) captured via the event-log collector.
    """

    __tablename__ = "usb_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_name: Mapped[str] = mapped_column(String(256), default="")
    device_id: Mapped[str] = mapped_column(String(256), default="")
    vendor: Mapped[str] = mapped_column(String(128), default="")
    serial: Mapped[str] = mapped_column(String(128), default="")
    inserted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "device_name": self.device_name,
            "device_id": self.device_id,
            "vendor": self.vendor,
            "serial": self.serial,
            "inserted_at": self.inserted_at.isoformat() if self.inserted_at else None,
        }


class FileScan(Base):
    """A file scanned by the malware/file-hash analyzer."""

    __tablename__ = "file_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_path: Mapped[str] = mapped_column(String(1024), index=True)
    file_name: Mapped[str] = mapped_column(String(256), default="")
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    md5: Mapped[str] = mapped_column(String(32), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    signed: Mapped[bool] = mapped_column(Boolean, default=False)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    signature_name: Mapped[str] = mapped_column(String(128), default="")
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "file_path": self.file_path,
            "file_name": self.file_name,
            "sha256": self.sha256,
            "md5": self.md5,
            "size": self.size,
            "signed": self.signed,
            "is_malicious": self.is_malicious,
            "signature_name": self.signature_name,
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
        }


class DashboardSnapshot(Base):
    """Periodic roll-up of the platform KPIs used for trend charts."""

    __tablename__ = "dashboard_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    security_score: Mapped[float] = mapped_column(Float, default=100.0)
    total_events: Mapped[int] = mapped_column(Integer, default=0)
    active_alerts: Mapped[int] = mapped_column(Integer, default=0)
    critical_threats: Mapped[int] = mapped_column(Integer, default=0)
    events_last_hour: Mapped[int] = mapped_column(Integer, default=0)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "security_score": self.security_score,
            "total_events": self.total_events,
            "active_alerts": self.active_alerts,
            "critical_threats": self.critical_threats,
            "events_last_hour": self.events_last_hour,
        }


class ReportRecord(Base):
    """Metadata for a generated report file."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_type: Mapped[str] = mapped_column(String(32))  # executive | technical
    format: Mapped[str] = mapped_column(String(16))       # pdf | html | json | csv
    title: Mapped[str] = mapped_column(String(256))
    file_path: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "report_type": self.report_type,
            "format": self.format,
            "title": self.title,
            "file_path": self.file_path,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AnalystNote(Base):
    """Analyst annotation attached to an alert during investigation."""

    __tablename__ = "analyst_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"))
    note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    alert: Mapped[Alert] = relationship(back_populates="notes")


class AssistantMessage(Base):
    """Chat history for the AI security assistant."""

    __tablename__ = "assistant_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    role: Mapped[str] = mapped_column(String(16))  # user | assistant
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "role": self.role,
            "content": self.content,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AlertAction(Base):
    """A response action taken on an alert (automated containment/triage)."""

    __tablename__ = "alert_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    action: Mapped[str] = mapped_column(String(32))  # block_ip | kill_process | quarantine | escalate | ack
    target: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued | success | failed
    detail: Mapped[str] = mapped_column(Text, default="")
    triggered_by: Mapped[str] = mapped_column(String(64), default="auto")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "action": self.action,
            "target": self.target,
            "status": self.status,
            "detail": self.detail,
            "triggered_by": self.triggered_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class EvaluationRun(Base):
    """One evaluation-framework run: metrics for a scenario (or the suite)."""

    __tablename__ = "evaluation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scenario: Mapped[str] = mapped_column(String(64), index=True)
    total_samples: Mapped[int] = mapped_column(Integer, default=0)
    attack_samples: Mapped[int] = mapped_column(Integer, default=0)
    baseline_samples: Mapped[int] = mapped_column(Integer, default=0)
    true_positives: Mapped[int] = mapped_column(Integer, default=0)
    false_positives: Mapped[int] = mapped_column(Integer, default=0)
    true_negatives: Mapped[int] = mapped_column(Integer, default=0)
    false_negatives: Mapped[int] = mapped_column(Integer, default=0)
    accuracy: Mapped[float] = mapped_column(Float, default=0.0)
    precision: Mapped[float] = mapped_column(Float, default=0.0)
    recall: Mapped[float] = mapped_column(Float, default=0.0)
    f1_score: Mapped[float] = mapped_column(Float, default=0.0)
    false_positive_rate: Mapped[float] = mapped_column(Float, default=0.0)
    detection_time_ms: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scenario": self.scenario,
            "total_samples": self.total_samples,
            "attack_samples": self.attack_samples,
            "baseline_samples": self.baseline_samples,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "detection_time_ms": round(self.detection_time_ms, 2),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def json_dumps(data) -> str:
    return json.dumps(data, default=str)
