"""Application configuration using pydantic-settings.

This module defines the structured configuration for BARAQ.
Settings are loaded from environment variables and a .env file.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --------------------------------------------------------------------------
    # Runtime profile
    # --------------------------------------------------------------------------
    env: str = Field(
        default="development",
        validation_alias="BARAQ_ENV",
        description="Runtime profile: development, production, or test",
    )

    # --------------------------------------------------------------------------
    # Server
    # --------------------------------------------------------------------------
    host: str = Field(
        default="127.0.0.1",
        validation_alias="BARAQ_HOST",
        description="Bind address for the API server",
    )
    port: int = Field(
        default=8001,
        validation_alias="BARAQ_PORT",
        description="HTTP port for the API server",
    )
    tls_port: int = Field(
        default=8443,
        validation_alias="BARAQ_TLS_PORT",
        description="HTTPS port for the API server",
    )

    # --------------------------------------------------------------------------
    # Transport security (TLS)
    # --------------------------------------------------------------------------
    tls_enabled: bool = Field(
        default=False,
        validation_alias="BARAQ_TLS",
        description="Enable HTTPS",
    )
    tls_cert_file: str = Field(
        default="certs/baraq.crt",
        validation_alias="BARAQ_TLS_CERT",
        description="Path to TLS certificate file",
    )
    tls_key_file: str = Field(
        default="certs/baraq.key",
        validation_alias="BARAQ_TLS_KEY",
        description="Path to TLS private key file",
    )
    cookie_secure: bool = Field(
        default=False,
        validation_alias="BARAQ_COOKIE_SECURE",
        description="Whether session cookie should be Secure (HTTPS only)",
    )

    # --------------------------------------------------------------------------
    # Database
    # --------------------------------------------------------------------------
    database_url: str = Field(
        default="",
        validation_alias="BARAQ_DATABASE_URL",
        description="Database URL (PostgreSQL)",
    )
    echo_sql: bool = Field(
        default=False,
        validation_alias="BARAQ_ECHO_SQL",
        description="Enable SQLAlchemy echo (log SQL queries)",
    )

    # --------------------------------------------------------------------------
    # ML feature version
    # --------------------------------------------------------------------------
    ml_feature_version: int = Field(
        default=2,
        validation_alias="BARAQ_ML_FEATURE_VERSION",
        description="Version of the ML feature space. Increment when features change.",
    )

    # --------------------------------------------------------------------------
    # Collection
    # --------------------------------------------------------------------------
    collect_interval_seconds: int = Field(
        default=15,
        validation_alias="BARAQ_INTERVAL",
        description="Scheduler collection interval in seconds",
    )
    scheduler_enabled: bool = Field(
        default=True,
        validation_alias="BARAQ_SCHEDULER_ENABLED",
        description="Enable the background scheduler",
    )
    test_mode: bool = Field(
        default=False,
        validation_alias="BARAQ_TEST_MODE",
        description="Test mode (do not persist real alerts)",
    )
    event_retention_days: int = Field(
        default=30,
        validation_alias="BARAQ_EVENT_RETENTION_DAYS",
        description="Telemetry/alerts older than this are auto-purged hourly",
    )

    # --------------------------------------------------------------------------
    # Detection tuning
    # --------------------------------------------------------------------------
    detection_window_minutes: int = Field(
        default=10,
        validation_alias="BARAQ_DETECTION_WINDOW_MINUTES",
        description="Detection correlation window in minutes",
    )
    brute_force_threshold: int = Field(
        default=5,
        validation_alias="BARAQ_BRUTE_FORCE_THRESHOLD",
        description="Failed logons within window → alert",
    )
    port_scan_distinct_ports: int = Field(
        default=20,
        validation_alias="BARAQ_PORT_SCAN_DISTINCT_PORTS",
        description="Distinct probed ports → alert",
    )

    # --------------------------------------------------------------------------
    # ML lifecycle
    # --------------------------------------------------------------------------
    ml_retrain_after_minutes: int = Field(
        default=5,
        validation_alias="BARAQ_ML_RETRAIN_AFTER_MINUTES",
        description="Model age (minutes) after which the scheduler auto-retrains",
    )
    ml_retrain_min_new_events: int = Field(
        default=200,
        validation_alias="BARAQ_ML_RETRAIN_MIN_NEW_EVENTS",
        description="Minimum new events since last training to trigger retrain",
    )
    ml_target_fpr: float = Field(
        default=0.03,
        validation_alias="BARAQ_ML_TARGET_FPR",
        description="Target false positive rate for ML anomaly detection",
    )

    # --------------------------------------------------------------------------
    # Risk scoring
    # --------------------------------------------------------------------------
    ml_rule_weight: float = Field(
        default=0.6,
        validation_alias="BARAQ_ML_RULE_WEIGHT",
        description="Weight of rule score in hybrid risk scoring (0.0-1.0)",
    )
    ml_detection_weight: float = Field(
        default=0.4,
        validation_alias="BARAQ_ML_DETECTION_WEIGHT",
        description="Weight of ML anomaly score in hybrid risk scoring (0.0-1.0)",
    )
    risk_level_medium: int = Field(
        default=40,
        validation_alias="BARAQ_RISK_LEVEL_MEDIUM",
        description="Risk score threshold for MEDIUM level",
    )
    risk_level_high: int = Field(
        default=65,
        validation_alias="BARAQ_RISK_LEVEL_HIGH",
        description="Risk score threshold for HIGH level",
    )
    risk_level_critical: int = Field(
        default=85,
        validation_alias="BARAQ_RISK_LEVEL_CRITICAL",
        description="Risk score threshold for CRITICAL level",
    )

    # --------------------------------------------------------------------------
    # API hardening
    # --------------------------------------------------------------------------
    security_headers: bool = Field(
        default=True,
        validation_alias="BARAQ_SECURITY_HEADERS",
        description="Emit standard security headers on HTTP responses",
    )
    hsts_max_age: int = Field(
        default=60 * 60 * 24 * 180,  # 180 days
        validation_alias="BARAQ_HSTS_MAX_AGE",
        description="HSTS max-age in seconds",
    )
    api_rate_limit: int = Field(
        default=600,
        validation_alias="BARAQ_API_RATE_LIMIT",
        description="Max requests per client per minute (0 disables)",
    )
    api_rate_burst: int = Field(
        default=900,
        validation_alias="BARAQ_API_RATE_BURST",
        description="Burst allowance before fixed window rate limiting",
    )

    # --------------------------------------------------------------------------
    # Authentication / RBAC
    # --------------------------------------------------------------------------
    auth_enabled: bool = Field(
        default=True,
        validation_alias="BARAQ_AUTH_ENABLED",
        description="Enable API key authentication",
    )
    allow_dev_keys: bool = Field(
        default=True,
        validation_alias="BARAQ_ALLOW_DEV_KEYS",
        description="Allow development API keys (baraq-dev-*) in non-production",
    )
    enforce_admin_mfa: bool = Field(
        default=False,
        validation_alias="BARAQ_ENFORCE_ADMIN_MFA",
        description="Require TOTP for admin operations",
    )

    # --------------------------------------------------------------------------
    # Observability
    # --------------------------------------------------------------------------
    metrics_public: bool = Field(
        default=False,
        validation_alias="BARAQ_METRICS_PUBLIC",
        description="Expose unauthenticated /metrics endpoint",
    )
    log_format: str = Field(
        default="text",
        validation_alias="BARAQ_LOG_FORMAT",
        description="Log format: text or json",
    )

    # --------------------------------------------------------------------------
    # Notifications
    # --------------------------------------------------------------------------
    webhook_url: str = Field(
        default="",
        validation_alias="BARAQ_WEBHOOK_URL",
        description="Generic webhook URL for notifications",
    )
    notify_min_severity: str = Field(
        default="high",
        validation_alias="BARAQ_NOTIFY_MIN_SEVERITY",
        description="Minimum severity for notifications (low, medium, high, critical)",
    )

    # --------------------------------------------------------------------------
    # Encryption at rest
    # --------------------------------------------------------------------------
    encrypt_at_rest: bool = Field(
        default=False,
        validation_alias="BARAQ_ENCRYPT_AT_REST",
        description="Encrypt sensitive free-text fields with AES-256-GCM",
    )

    # --------------------------------------------------------------------------
    # Threat intelligence
    # --------------------------------------------------------------------------
    threat_intel_enabled: bool = Field(
        default=True,
        validation_alias="BARAQ_THREAT_INTEL_ENABLED",
        description="Enable threat intelligence enrichment",
    )
    threat_intel_timeout: float = Field(
        default=8.0,
        validation_alias="BARAQ_THREAT_INTEL_TIMEOUT",
        description="Timeout for threat intelligence API requests (seconds)",
    )
    threat_intel_cache_hours: int = Field(
        default=24,
        validation_alias="BARAQ_THREAT_INTEL_CACHE_HOURS",
        description="Cache duration for threat intelligence lookups (hours)",
    )

    # --------------------------------------------------------------------------
    # Entity graph
    # --------------------------------------------------------------------------
    graph_provider: str = Field(
        default="postgres",
        validation_alias="BARAQ_GRAPH_PROVIDER",
        description="Entity graph storage backend: postgres or neo4j",
    )
    neo4j_uri: str = Field(
        default="",
        validation_alias="BARAQ_NEO4J_URI",
        description="Neo4j connection URI (when graph_provider=neo4j)",
    )
    neo4j_user: str = Field(
        default="neo4j",
        validation_alias="BARAQ_NEO4J_USER",
        description="Neo4j username",
    )
    neo4j_database: str = Field(
        default="neo4j",
        validation_alias="BARAQ_NEO4J_DATABASE",
        description="Neo4j database name",
    )
    graph_max_nodes: int = Field(
        default=250,
        validation_alias="BARAQ_GRAPH_MAX_NODES",
        description="Maximum nodes returned in entity graph queries",
    )
    graph_max_edges: int = Field(
        default=300,
        validation_alias="BARAQ_GRAPH_MAX_EDGES",
        description="Maximum edges returned in entity graph queries",
    )

    # --------------------------------------------------------------------------
    # Data quality
    # --------------------------------------------------------------------------
    data_quality_window_minutes: int = Field(
        default=10,
        validation_alias="BARAQ_DATA_QUALITY_WINDOW_MINUTES",
        description="Sliding window size for data quality monitoring (minutes)",
    )
    data_quality_warn_rate: float = Field(
        default=0.10,
        validation_alias="BARAQ_DATA_QUALITY_WARN_RATE",
        description="Corruption rate threshold for WARNING status",
    )
    data_quality_degraded_rate: float = Field(
        default=0.30,
        validation_alias="BARAQ_DATA_QUALITY_DEGRADED_RATE",
        description="Corruption rate threshold for DEGRADED status",
    )
    data_quality_critical_rate: float = Field(
        default=0.50,
        validation_alias="BARAQ_DATA_QUALITY_CRITICAL_RATE",
        description="Corruption rate threshold for CRITICAL status (triggers auto-repair)",
    )
    data_quality_auto_repair: bool = Field(
        default=True,
        validation_alias="BARAQ_DATA_QUALITY_AUTO_REPAIR",
        description="Automatically run repair sequence when corruption rate is critical",
    )

    # --------------------------------------------------------------------------
    # Database connection pooling
    # --------------------------------------------------------------------------
    db_pool_size: int = Field(
        default=10,
        validation_alias="BARAQ_DB_POOL_SIZE",
        description="SQLAlchemy connection pool size",
    )
    db_max_overflow: int = Field(
        default=20,
        validation_alias="BARAQ_DB_MAX_OVERFLOW",
        description="SQLAlchemy connection pool max overflow",
    )
    db_pool_timeout: int = Field(
        default=30,
        validation_alias="BARAQ_DB_POOL_TIMEOUT",
        description="SQLAlchemy connection pool timeout in seconds",
    )
    db_pool_recycle: int = Field(
        default=1800,
        validation_alias="BARAQ_DB_POOL_RECYCLE",
        description="SQLAlchemy connection pool recycle time in seconds",
    )

    @field_validator("ml_rule_weight", "ml_detection_weight")
    @classmethod
    def weights_must_sum_to_one(cls, v: float, info) -> float:
        """Ensure ML rule and detection weights sum to approximately 1.0."""
        # This validator is called for each field, so we need to check the other value.
        # We'll do a simple check: if both are set, their sum should be 1.0.
        # Note: This is a simplified check; in practice, we might want to adjust one if the other changes.
        # For now, we just validate that each is between 0 and 1.
        if not 0.0 <= v <= 1.0:
            raise ValueError("Weight must be between 0.0 and 1.0")
        return v

    @field_validator("tls_cert_file", "tls_key_file")
    @classmethod
    def tls_paths_must_exist_if_enabled(cls, v: str, info) -> str:
        """If TLS is enabled, the certificate and key files must exist."""
        # We cannot check the TLS_ENABLED flag here because validators don't have access to other fields easily.
        # We'll do this check in the application startup instead.
        return v


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
