"""additive columns migration - replaces in-place DDL at startup.

Revision ID: 002
Revises: 0001_baseline
Create Date: 2026-09-06

Covers all columns from the _ADDITIVE_MIGRATIONS dict in connection.py.
Uses ADD COLUMN IF NOT EXISTS so it's safe to run multiple times.
"""

from alembic import op
import sqlalchemy as sa

revision = "002_additive_columns"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def _add_column_safe(table: str, column: str, coltype: sa.types.TypeEngine) -> None:
    """Add a column only if it does not exist (idempotent)."""
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing = [c["name"] for c in insp.get_columns(table)]
    if column not in existing:
        op.add_column(table, sa.Column(column, coltype))


def upgrade() -> None:
    # v2_events
    _add_column_safe("v2_events", "event_id", sa.String(64))
    _add_column_safe("v2_events", "event_type", sa.String(32))
    _add_column_safe("v2_events", "destination", sa.String(128))
    _add_column_safe("v2_events", "process", sa.JSON())
    _add_column_safe("v2_events", "network", sa.JSON())
    _add_column_safe("v2_events", "outcome", sa.String(16))
    _add_column_safe("v2_events", "schema_version", sa.String(8))

    # events
    _add_column_safe("events", "risk_score", sa.Float())
    _add_column_safe("events", "is_anomaly", sa.Boolean())
    _add_column_safe("events", "ml_score", sa.Float())
    _add_column_safe("events", "org", sa.String(64))
    _add_column_safe("events", "data_integrity", sa.String(16))
    _add_column_safe("events", "demo", sa.Boolean())

    # alerts
    _add_column_safe("alerts", "detection_method", sa.String(16))
    _add_column_safe("alerts", "risk_score", sa.Float())
    _add_column_safe("alerts", "risk_level", sa.String(16))
    _add_column_safe("alerts", "trigger_count", sa.Integer())
    _add_column_safe("alerts", "host", sa.String(128))
    _add_column_safe("alerts", "org", sa.String(64))
    _add_column_safe("alerts", "ticket_links", sa.JSON())
    _add_column_safe("alerts", "demo", sa.Boolean())
    _add_column_safe("alerts", "correlation_id", sa.String(64))
    _add_column_safe("alerts", "risk_json", sa.Text())
    _add_column_safe("alerts", "intel_json", sa.Text())

    # entity_risk
    _add_column_safe("entity_risk", "demo", sa.Boolean())
    _add_column_safe("entity_risk", "last_escalated_level", sa.String(16))
    _add_column_safe("entity_risk", "last_escalated_score", sa.Float())
    _add_column_safe("entity_risk", "last_escalated_at", sa.DateTime(timezone=True))

    # entity_risk_events
    _add_column_safe("entity_risk_events", "demo", sa.Boolean())

    # incidents
    _add_column_safe("incidents", "org", sa.String(64))
    _add_column_safe("incidents", "demo", sa.Boolean())
    _add_column_safe("incidents", "confidence", sa.Float())
    _add_column_safe("incidents", "correlation_key", sa.String(96))
    _add_column_safe("incidents", "chain_json", sa.Text())
    _add_column_safe("incidents", "chain_confidence", sa.Float())
    _add_column_safe("incidents", "chain_risk", sa.Integer())
    _add_column_safe("incidents", "responded_at", sa.DateTime(timezone=True))

    # network_connections
    _add_column_safe("network_connections", "bytes_sent", sa.BigInteger())
    _add_column_safe("network_connections", "bytes_recv", sa.BigInteger())
    _add_column_safe("network_connections", "duration_seconds", sa.Float())
    _add_column_safe("network_connections", "org", sa.String(64))
    _add_column_safe("network_connections", "demo", sa.Boolean())

    # processes
    _add_column_safe("processes", "org", sa.String(64))
    _add_column_safe("processes", "demo", sa.Boolean())
    _add_column_safe("processes", "guid", sa.String(64))
    _add_column_safe("processes", "parent_guid", sa.String(64))

    # dns_queries
    _add_column_safe("dns_queries", "org", sa.String(64))
    _add_column_safe("dns_queries", "demo", sa.Boolean())

    # http_requests
    _add_column_safe("http_requests", "org", sa.String(64))
    _add_column_safe("http_requests", "demo", sa.Boolean())

    # emails
    _add_column_safe("emails", "org", sa.String(64))
    _add_column_safe("emails", "demo", sa.Boolean())

    # usb_devices
    _add_column_safe("usb_devices", "org", sa.String(64))
    _add_column_safe("usb_devices", "demo", sa.Boolean())

    # file_scans
    _add_column_safe("file_scans", "org", sa.String(64))
    _add_column_safe("file_scans", "demo", sa.Boolean())

    # vuln_findings
    _add_column_safe("vuln_findings", "org", sa.String(64))
    _add_column_safe("vuln_findings", "demo", sa.Boolean())

    # audit_log
    _add_column_safe("audit_log", "prev_hash", sa.String(64))
    _add_column_safe("audit_log", "hash", sa.String(64))

    # users
    _add_column_safe("users", "totp_secret", sa.Text())
    _add_column_safe("users", "totp_enabled", sa.Boolean())
    _add_column_safe("users", "last_login_at", sa.DateTime(timezone=True))
    _add_column_safe("users", "org", sa.String(64))
    _add_column_safe("users", "registration_status", sa.String(16))
    _add_column_safe("users", "must_change_password", sa.Boolean())
    _add_column_safe("users", "password_changed_at", sa.DateTime(timezone=True))

    # endpoints
    _add_column_safe("endpoints", "org", sa.String(64))
    _add_column_safe("endpoints", "agent_version", sa.String(32))
    _add_column_safe("endpoints", "os_info", sa.String(128))
    _add_column_safe("endpoints", "tags", sa.String(256))
    _add_column_safe("endpoints", "health_status", sa.String(16))
    _add_column_safe("endpoints", "update_status", sa.String(16))
    _add_column_safe("endpoints", "errors_total", sa.Integer())


def downgrade() -> None:
    pass
