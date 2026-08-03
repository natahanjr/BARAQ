"""SentinelSOC SQLite database schema (reference copy).

The authoritative schema is defined by SQLAlchemy models in
backend/database/models.py and created automatically at startup
(init_db). This file documents the physical layout.
"""

-- ============================================================
-- SENTINELSOC - SQLITE DATABASE SCHEMA (v1.0.0)
-- ============================================================

-- Normalized security events (canonical pipeline output)
CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    INTEGER NOT NULL DEFAULT 0,
    category    VARCHAR(64)  NOT NULL DEFAULT 'Other',
    source      VARCHAR(32)  NOT NULL DEFAULT 'unknown',
    user        VARCHAR(128) NOT NULL DEFAULT '-',
    host        VARCHAR(128) NOT NULL DEFAULT '-',
    risk        VARCHAR(16)  NOT NULL DEFAULT 'Low',
    severity    VARCHAR(16)  NOT NULL DEFAULT 'info',
    message     TEXT         NOT NULL DEFAULT '',
    timestamp   DATETIME,
    raw_json    JSON,
    is_anomaly  BOOLEAN      NOT NULL DEFAULT 0,
    ml_score    FLOAT
);
CREATE INDEX ix_events_event_id ON events (event_id);
CREATE INDEX ix_events_category ON events (category);
CREATE INDEX ix_events_source   ON events (source);
CREATE INDEX ix_events_user     ON events (user);
CREATE INDEX ix_events_risk     ON events (risk);
CREATE INDEX ix_events_severity ON events (severity);
CREATE INDEX ix_events_timestamp ON events (timestamp);
CREATE INDEX ix_events_is_anomaly ON events (is_anomaly);
CREATE INDEX idx_events_ts      ON events (timestamp);

-- Detection alerts with MITRE ATT&CK enrichment
CREATE TABLE alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            VARCHAR(128),
    description     TEXT,
    severity        VARCHAR(16) DEFAULT 'medium',
    status          VARCHAR(16) DEFAULT 'open',
    confidence      FLOAT,
    score           FLOAT,
    mitre_id        VARCHAR(16),
    mitre_name      VARCHAR(128),
    mitre_tactic    VARCHAR(64),
    recommendation  TEXT,
    evidence        TEXT,
    rule            VARCHAR(64),
    event_count     INTEGER,
    created_at      DATETIME,
    updated_at      DATETIME
);
CREATE INDEX ix_alerts_name ON alerts (name);
CREATE INDEX ix_alerts_severity ON alerts (severity);
CREATE INDEX ix_alerts_status ON alerts (status);
CREATE INDEX ix_alerts_mitre_id ON alerts (mitre_id);
CREATE INDEX ix_alerts_rule ON alerts (rule);
CREATE INDEX ix_alerts_created_at ON alerts (created_at);
CREATE INDEX idx_alerts_status ON alerts (status);

-- Alert <-> evidence event links
CREATE TABLE alert_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    UNIQUE (alert_id, event_id)
);
CREATE INDEX ix_alert_events_alert_id ON alert_events (alert_id);
CREATE INDEX ix_alert_events_event_id ON alert_events (event_id);

-- Process observation snapshots
CREATE TABLE processes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    pid          INTEGER,
    ppid         INTEGER DEFAULT 0,
    name         VARCHAR(256),
    path         TEXT,
    command_line TEXT,
    parent_name  VARCHAR(256) DEFAULT '',
    user         VARCHAR(128) DEFAULT '',
    is_new       BOOLEAN DEFAULT 0,
    observed_at  DATETIME
);
CREATE INDEX ix_processes_pid ON processes (pid);
CREATE INDEX ix_processes_name ON processes (name);
CREATE INDEX ix_processes_observed_at ON processes (observed_at);

-- Network connection observations
CREATE TABLE network_connections (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    pid          INTEGER DEFAULT 0,
    process      VARCHAR(256) DEFAULT '',
    local_ip     VARCHAR(64) DEFAULT '',
    local_port   INTEGER DEFAULT 0,
    remote_ip    VARCHAR(64) DEFAULT '',
    remote_port  INTEGER DEFAULT 0,
    state        VARCHAR(32) DEFAULT '',
    is_listening BOOLEAN DEFAULT 0,
    observed_at  DATETIME
);
CREATE INDEX ix_network_connections_remote_ip ON network_connections (remote_ip);
CREATE INDEX ix_network_connections_observed_at ON network_connections (observed_at);

-- KPI roll-ups for the dashboard trend charts
CREATE TABLE dashboard_snapshots (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        DATETIME,
    security_score   FLOAT,
    total_events     INTEGER,
    active_alerts    INTEGER,
    critical_threats INTEGER,
    events_last_hour INTEGER
);
CREATE INDEX ix_dashboard_snapshots_timestamp ON dashboard_snapshots (timestamp);

-- Generated report metadata
CREATE TABLE reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    report_type VARCHAR(32),
    format      VARCHAR(16),
    title       VARCHAR(256),
    file_path   TEXT,
    created_at  DATETIME
);

-- Analyst annotations on alerts
CREATE TABLE analyst_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id   INTEGER REFERENCES alerts (id) ON DELETE CASCADE,
    note       TEXT,
    created_at DATETIME
);

-- AI assistant chat history
CREATE TABLE assistant_messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    role       VARCHAR(16),
    content    TEXT,
    created_at DATETIME
);
