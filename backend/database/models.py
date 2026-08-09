"""SQLAlchemy ORM models for the SentinelSOC local database (SQLite/PostgreSQL)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON, TypeDecorator


class JSONColumnType(TypeDecorator):
    """JSON column that compiles to ``jsonb`` on PostgreSQL and ``json``
    elsewhere.

    Plain ``json`` has no equality operator in PostgreSQL, so GROUP BY /
    distinct on JSON columns requires ``jsonb``. SQLite keeps the generic
    ``JSON`` type. Being a ``TypeDecorator`` the choice follows the engine
    dialect at compile time, not the process-level DATABASE_URL, so mixed
    SQLite/Postgres engines (tests, migrations) always render correctly.
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import JSONB

            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


class EncryptedColumn(TypeDecorator):
    """AES-256-GCM field-level encryption applied transparently on write/read.

    Encrypts on ``bind`` (any non-empty string) and decrypts on ``result``.
    Legacy plaintext values are returned unchanged, so pre-hardening rows and
    development databases keep working. Queries that filter/group on these
    columns are NOT supported (encryption prevents index lookups) — the
    caller must filter in Python on loaded rows (which all rules already do).
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, (dict, list)):
            value = json.dumps(value, default=str)
        from backend.crypto import encrypt_text

        return encrypt_text(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        from backend.crypto import decrypt_text

        return decrypt_text(value)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def canonical_timestamp(ts: datetime | None) -> str:
    """Normalise a timestamp to a deterministic UTC string (no microseconds).

    SQLite drops tzinfo and may truncate microseconds on round-trip, so the
    same instant must hash identically at write time and read time.
    """
    if ts is None:
        return ""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).replace(microsecond=0).isoformat()


class Base(DeclarativeBase):
    pass


class User(Base):
    """An operator/analyst account. Passwords are stored as salted PBKDF2
    hashes; role is either ``admin`` or ``analyst``.

    Two-factor authentication (TOTP, see ``backend/totp.py``): ``totp_secret``
    holds the base32 shared secret (encrypted at rest) and ``totp_enabled``
    gates the second step on login. Operators provision 2FA via
    ``/api/auth/mfa/*``.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(16), default="analyst")  # admin | analyst
    #: Tenant scoping: "" (system/central), an organization id, or "all" for
    #: admins who must oversee every tenant. Analysts are pinned to their org.
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret: Mapped[str] = mapped_column(EncryptedColumn(), default="")  # User
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "org": self.org,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "totp_enabled": self.totp_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }


class AuditLog(Base):
    """Immutable trail of who did what, when. Wired into login, alert actions,
    command dispatch, report generation and user management.

    Tamper-evidence: every entry carries ``prev_hash`` (SHA-256 of the
    canonical form of the previous entry) and ``hash`` (SHA-256 of this
    entry's canonical form chained to ``prev_hash``). Altering any historical
    row breaks the chain and is detectable (see ``backend/audit.verify_chain``).
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(64), index=True)  # username / api key / system
    action: Mapped[str] = mapped_column(String(64), index=True)  # login, alert.status, command.queue, ...
    entity_type: Mapped[str] = mapped_column(String(32), default="")
    entity_id: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(EncryptedColumn(), default="")  # AuditLog
    ip: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    #: SHA-256 of the previous audit entry's canonical form ("0"*64 for genesis).
    prev_hash: Mapped[str] = mapped_column(String(64), default="0" * 64)
    #: SHA-256 chain hash of this entry.
    hash: Mapped[str] = mapped_column(String(64), default="0" * 64)

    def canonical(self) -> str:
        """Deterministic string hashed to build the chain."""
        ts = canonical_timestamp(self.created_at)
        return "|".join(
            [
                self.prev_hash or "",
                self.actor or "",
                self.action or "",
                self.entity_type or "",
                self.entity_id or "",
                self.detail or "",
                self.ip or "",
                ts,
            ]
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "actor": self.actor,
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "detail": self.detail,
            "ip": self.ip,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "hash": self.hash,
            "prev_hash": self.prev_hash,
        }


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
    #: Tenant scoping: telemetry from remote agents is tagged with the
    #: organization the agent key belongs to; "" is the local/system host.
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    risk: Mapped[str] = mapped_column(String(16), index=True, default="Low")
    severity: Mapped[str] = mapped_column(String(16), index=True, default="info")
    message: Mapped[str] = mapped_column(EncryptedColumn(), default="")  # NormalizedEvent
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    raw_json: Mapped[dict | None] = mapped_column(JSONColumnType, nullable=True)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)

    verdict: Mapped["Verdict | None"] = relationship(
        "Verdict", back_populates="event", uselist=False, passive_deletes=True
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "category": self.category,
            "source": self.source,
            "user": self.user,
            "host": self.host,
            "org": self.org,
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
    evidence: Mapped[str] = mapped_column(EncryptedColumn(), default="")  # Alert
    rule: Mapped[str] = mapped_column(String(64), index=True, default="")
    host: Mapped[str] = mapped_column(String(128), index=True, default="")
    #: Tenant scoping: inherits the org of the evidence events ("" = system).
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    trigger_count: Mapped[int] = mapped_column(Integer, default=1)
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
            "host": self.host,
            "org": self.org,
            "event_count": self.event_count,
            "trigger_count": self.trigger_count,
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


class Endpoint(Base):
    """A monitored host feeding telemetry via the ingest agent."""

    __tablename__ = "endpoints"

    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    host: Mapped[str] = mapped_column(String(128), index=True, default="")
    #: Tenant scoping: the organization owning this agent ("" = system fleet).
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    records_total: Mapped[int] = mapped_column(Integer, default=0)
    events_total: Mapped[int] = mapped_column(Integer, default=0)
    alerts_total: Mapped[int] = mapped_column(Integer, default=0)
    output_format_version: Mapped[str] = mapped_column(String(16), default="1.0")

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "host": self.host,
            "org": self.org,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "records_total": self.records_total,
            "events_total": self.events_total,
            "alerts_total": self.alerts_total,
        }


class ProcessRecord(Base):
    """Snapshot of a running process observed by the process collector."""

    __tablename__ = "processes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pid: Mapped[int] = mapped_column(Integer, index=True)
    ppid: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(256), index=True)
    path: Mapped[str] = mapped_column(Text, default="")
    command_line: Mapped[str] = mapped_column(EncryptedColumn(), default="")  # ProcessRecord
    parent_name: Mapped[str] = mapped_column(String(256), default="")
    user: Mapped[str] = mapped_column(String(128), default="")
    is_new: Mapped[bool] = mapped_column(Boolean, default=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)

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
            "org": self.org,
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
    org: Mapped[str] = mapped_column(String(64), default="", index=True)

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
            "org": self.org,
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
    org: Mapped[str] = mapped_column(String(64), default="", index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "process": self.process,
            "pid": self.pid,
            "query": self.query,
            "response": self.response,
            "response_size": self.response_size,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "org": self.org,
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
    org: Mapped[str] = mapped_column(String(64), default="", index=True)

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
            "org": self.org,
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
    body: Mapped[str] = mapped_column(EncryptedColumn(), default="")  # EmailMessage
    attachment_types: Mapped[str] = mapped_column(String(512), default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "sender": self.sender,
            "recipient": self.recipient,
            "subject": self.subject,
            "attachment_types": self.attachment_types,
            "ip_address": self.ip_address,
            "received_at": self.received_at.isoformat() if self.received_at else None,
            "org": self.org,
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
    org: Mapped[str] = mapped_column(String(64), default="", index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "device_name": self.device_name,
            "device_id": self.device_id,
            "vendor": self.vendor,
            "serial": self.serial,
            "inserted_at": self.inserted_at.isoformat() if self.inserted_at else None,
            "org": self.org,
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
    org: Mapped[str] = mapped_column(String(64), default="", index=True)

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
            "org": self.org,
        }


class VulnFinding(Base):
    """A matched known-vulnerable product (CVE hit) on a monitored host.

    Produced by the vulnerability scanner (``source: vuln`` records) and
    aggregated into alerts by the vulnerability detection rule.
    """

    __tablename__ = "vuln_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host: Mapped[str] = mapped_column(String(128), index=True, default="")
    product: Mapped[str] = mapped_column(String(256), index=True)
    version: Mapped[str] = mapped_column(String(64), default="")
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    found_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "host": self.host,
            "product": self.product,
            "version": self.version,
            "cve_id": self.cve_id,
            "cvss": self.cvss,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "found_at": self.found_at.isoformat() if self.found_at else None,
            "org": self.org,
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
    content: Mapped[str] = mapped_column(EncryptedColumn())  # AssistantMessage
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


class AgentCommand(Base):
    """A remote command queued for an agent by the SOC controller.

    The server stores the command (block_ip / kill_process / quarantine /
    escalate) and the agent picks it up on its next poll cycle via
    ``GET /api/commands/pending``, executes it locally and reports the
    outcome back with ``POST /api/commands/{id}/result``.
    """

    __tablename__ = "agent_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(32))  # block_ip | kill_process | quarantine | escalate
    target: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[str] = mapped_column(String(16), index=True, default="pending")  # pending | success | failed
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "action": self.action,
            "target": self.target,
            "status": self.status,
            "detail": self.detail,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
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


class Verdict(Base):
    """Analyst ground-truth on a scored event (the feedback loop).

    One verdict per event; posting again overwrites. Verdicts become the
    authoritative labels for supervised retraining - an analyst-confirmed
    attack is always labelled positive and a false-positive always negative,
    overriding the heuristic labeler.
    """

    __tablename__ = "verdicts"
    __table_args__ = (UniqueConstraint("event_id", name="uq_verdict_event"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("events.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    verdict: Mapped[str] = mapped_column(String(32))  # true_positive | false_positive
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    event: Mapped["NormalizedEvent"] = relationship("NormalizedEvent", back_populates="verdict")
    __table_args__ = (UniqueConstraint("event_id", name="uq_verdict_event"),)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "verdict": self.verdict,
            "note": self.note,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def json_dumps(data) -> str:
    return json.dumps(data, default=str)


class Incident(Base):
    """A security incident: one or more related alerts tracked as a case.

    Analysts group alerts into incidents, assign ownership, track response
    status and build a timeline of investigation notes.
    """

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(256), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True, default="high")
    status: Mapped[str] = mapped_column(String(16), index=True, default="open")
    owner: Mapped[str] = mapped_column(String(128), default="")
    mitre_id: Mapped[str] = mapped_column(String(16), default="T0000")
    mitre_name: Mapped[str] = mapped_column(String(128), default="")
    host: Mapped[str] = mapped_column(String(128), index=True, default="")
    #: Tenant scoping: the org of the alerts that make up the case.
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), index=True, default="MEDIUM")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    opened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    alerts: Mapped[list["IncidentAlertLink"]] = relationship(
        "IncidentAlertLink",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentAlertLink.alert_id",
    )
    comments: Mapped[list["IncidentComment"]] = relationship(
        "IncidentComment",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentComment.created_at",
    )

    def to_dict(self, include_links: bool = False) -> dict:
        data = {
            "id": self.id,
            "ref": f"INC-{self.id:04d}",
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "owner": self.owner,
            "mitre_id": self.mitre_id,
            "mitre_name": self.mitre_name,
            "host": self.host,
            "org": self.org,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "alert_count": len(self.alerts),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "opened_at": self.opened_at.isoformat() if self.opened_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
        }
        if include_links:
            data["alerts"] = [
                {"alert_id": l.alert_id, "name": l.alert.name, "severity": l.alert.severity}
                for l in self.alerts
            ]
            data["comments"] = [c.to_dict() for c in self.comments]
        return data


class IncidentAlertLink(Base):
    """Link an incident to the alerts that make up the case."""

    __tablename__ = "incident_alerts"
    __table_args__ = (UniqueConstraint("incident_id", "alert_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    incident: Mapped[Incident] = relationship(back_populates="alerts")
    alert: Mapped[Alert] = relationship()

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "alert_id": self.alert_id,
            "alert_name": self.alert.name if self.alert else "",
            "alert_severity": self.alert.severity if self.alert else "",
        }


class IncidentComment(Base):
    """An analyst note/update appended to an incident timeline."""

    __tablename__ = "incident_comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    author: Mapped[str] = mapped_column(String(128), default="analyst")
    body: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(16), default="comment")  # comment | action | status
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="comments")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "author": self.author,
            "body": self.body,
            "kind": self.kind,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ThreatIntelRecord(Base):
    """Cached threat-intel verdict for a single indicator (IP / domain / hash)."""

    __tablename__ = "threat_intel_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(16), default="ip")  # ip | domain | hash
    category: Mapped[str] = mapped_column(String(16), index=True, default="unknown")  # abusive | malicious | suspicious | benign | unknown
    label: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    sources: Mapped[list] = mapped_column(JSONColumnType, default=list)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "indicator": self.indicator,
            "kind": self.kind,
            "category": self.category,
            "label": self.label,
            "confidence": self.confidence,
            "sources": self.sources or [],
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
        }


class EntityNode(Base):
    """An entity in the intelligence graph (user / device / process / IP /
    domain / file hash / technique / threat actor).

    Persisted by the configured graph provider (Postgres by default, Neo4j
    adapter optional). ``kind`` + ``name`` is the natural key; analytic
    counters (event_count, alert_count, risk_score) are refreshed by the
    extractor on each pipeline pass.
    """

    __tablename__ = "entity_nodes"
    __table_args__ = (UniqueConstraint("kind", "name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(24), index=True)  # user | device | process | ip | domain | file | technique | threat_actor
    name: Mapped[str] = mapped_column(String(512), index=True)
    display_name: Mapped[str] = mapped_column(String(512), default="")
    label: Mapped[str] = mapped_column(String(256), default="")
    risk_level: Mapped[str] = mapped_column(String(16), index=True, default="LOW")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    alerts_count: Mapped[int] = mapped_column(Integer, default=0)
    events_count: Mapped[int] = mapped_column(Integer, default=0)
    properties: Mapped[dict] = mapped_column(JSONColumnType, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    provider: Mapped[str] = mapped_column(String(16), default="postgres")

    def to_dict(self, include_props: bool = True) -> dict:
        data = {
            "kind": self.kind,
            "name": self.name,
            "display_name": self.display_name or self.name,
            "label": self.label,
            "risk_level": self.risk_level,
            "risk_score": round(self.risk_score, 2),
            "alerts_count": self.alerts_count,
            "events_count": self.events_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "id": self.id,
        }
        if include_props:
            data["properties"] = self.properties or {}
        return data


class EntityEdge(Base):
    """A directional relationship between two graph entities.

    Edges carry a verb label (e.g. ``user -> logon_on -> host``) plus a
    freshness/weight so the graph can rank "hot" connections. The Postgres
    provider merges on ``(src_kind, src_name, rel, dst_kind, dst_name)``.
    """

    __tablename__ = "entity_edges"
    __table_args__ = (UniqueConstraint("src_kind", "src_name", "rel", "dst_kind", "dst_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    src_kind: Mapped[str] = mapped_column(String(24), index=True)
    src_name: Mapped[str] = mapped_column(String(512), index=True)
    rel: Mapped[str] = mapped_column(String(32), index=True)
    dst_kind: Mapped[str] = mapped_column(String(24), index=True)
    dst_name: Mapped[str] = mapped_column(String(512), index=True)
    weight: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    properties: Mapped[dict] = mapped_column(JSONColumnType, default=dict)
    provider: Mapped[str] = mapped_column(String(16), default="postgres")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": {"kind": self.src_kind, "name": self.src_name},
            "rel": self.rel,
            "target": {"kind": self.dst_kind, "name": self.dst_name},
            "weight": self.weight,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "properties": self.properties or {},
        }
