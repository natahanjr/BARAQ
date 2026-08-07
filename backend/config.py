"""Central configuration for SentinelSOC.

All tunable parameters of the platform live here so the application can be
adjusted without touching business logic. Optimised for a low-resource
single Windows 11 laptop (i5 / 12 GB RAM).
"""
import json
import os
import secrets as _secrets
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# Frozen (PyInstaller) layout
# --------------------------------------------------------------------------
#: True when running from a packaged executable.
FROZEN = getattr(sys, "frozen", False)
if FROZEN:
    #: Read-only bundled resources live in the PyInstaller bundle (_MEIPASS).
    BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    #: Writable runtime data (database, logs, reports, .env) lives next to the exe.
    APP_DIR = Path(sys.executable).resolve().parent
else:
    BUNDLE_DIR = Path(__file__).resolve().parent
    APP_DIR = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------
# .env loader (no third-party dependency)
# --------------------------------------------------------------------------
def _load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines from a .env file into os.environ (non-overriding)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv(APP_DIR / ".env")

# --------------------------------------------------------------------------
# First-run secure setup
# --------------------------------------------------------------------------
#: The project .env file (next to this file's parent, i.e. project root).
ENV_PATH = APP_DIR / ".env"

#: These are *names* of environment variables, kept in one place so the
#: marker check below and the persisted .env block always stay in sync.
_first_run_vars = (
    "SENTINEL_ADMIN_PASSWORD",
    "SENTINEL_API_KEYS",
    "SENTINEL_TOKEN_SECRET",
)

#: Additional credential values that may live in .env and should also be
#: migrated into the DPAPI vault (agent keys, AI API key).
_credential_vars = _first_run_vars + ("SENTINEL_AGENT_KEYS", "SENTINEL_AI_API_KEY")


def _seeded_values_from_bundle():
    """Return operator-bundled credentials embedded in the executable.

    The PyInstaller spec bundles ``dist/.env`` as ``.env.seed`` inside the
    exe, so a fully standalone build boots with known credentials on any
    machine - no .env file required. Returns None in development or when
    the seed is incomplete, falling back to random generation.
    """
    seed = BUNDLE_DIR / "seed" / ".env"
    try:
        text = seed.read_text(encoding="utf-8")
    except OSError:
        return None
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key in _first_run_vars and value:
            values[key] = value
    if set(values) == set(_first_run_vars):
        return values
    return None


def _get_vault():
    """Return the DPAPI secret vault (cached; degrades gracefully off-Windows)."""
    from backend.vault import SecretVault

    return SecretVault(APP_DIR / "secrets.dat")


def _migrate_env_secrets_to_vault(vault, env_path: Path) -> None:
    """Move plaintext secrets found in .env into the DPAPI vault.

    Once a value is safely stored in the vault, its plaintext line is removed
    from .env so credentials never linger on disk in cleartext. The current
    process keeps working because values are already in os.environ.
    """
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    secrets = {}
    kept = []
    changed = False
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.partition("=")[0].strip()
            if key in _credential_vars:
                value = stripped.partition("=")[2].strip().strip('"').strip("'")
                if value:
                    secrets[key] = value
                changed = True
                continue
        kept.append(line)
    if not secrets:
        return
    try:
        vault.set_many(secrets)
    except Exception:  # noqa: BLE001 - DPAPI unavailable; keep .env untouched
        return
    if changed:
        try:
            env_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
        except OSError:
            pass


def _ensure_secure_secrets(env_path: Path = ENV_PATH) -> None:
    """Generate random admin credentials on first run and persist them.

    Sensitive credentials are stored DPAPI-encrypted in ``secrets.dat``
    (Windows) so they never sit in plaintext on disk'. When DPAPI is not
    available (non-Windows / CI), they are written to .env instead.

    Runs once at import time. Skipped when credentials are already configured
    (operator-provided via environment/.env, or generated on a previous run),
    or when ``SENTINEL_SKIP_SECRET_GEN=1`` (used by the test suite so tests
    never touch the real .env file). The credentials are printed exactly once
    so the operator can save them.
    """
    if os.environ.get("SENTINEL_SKIP_SECRET_GEN", "").lower() in ("1", "true", "yes"):
        return

    vault = _get_vault()

    # Existing configuration may already be in the vault (preferred) or .env.
    configured = {
        name: vault.get(name) or os.environ.get(name)
        for name in _first_run_vars
    }
    if all(configured.values()):
        _migrate_env_secrets_to_vault(vault, env_path)
        return

    # Migration: secrets exist in plaintext .env but not yet in the vault.
    _migrate_env_secrets_to_vault(vault, env_path)
    if all(vault.get(name) or os.environ.get(name) for name in _first_run_vars):
        return

    try:
        existing = env_path.read_text(encoding="utf-8")
    except OSError:
        existing = ""
    if all(name + "=" in existing for name in _first_run_vars):
        return

    admin_password = _secrets.token_urlsafe(12)
    admin_key = "sentinel-admin-" + _secrets.token_urlsafe(10)
    analyst_key = "sentinel-analyst-" + _secrets.token_urlsafe(10)
    api_keys_json = json.dumps({admin_key: "admin", analyst_key: "analyst"})
    token_secret = _secrets.token_hex(32)

    seeded = _seeded_values_from_bundle()
    if seeded:
        new_values = seeded
        print("Using bundled default credentials from the executable.")
    else:
        new_values = {
            "SENTINEL_ADMIN_PASSWORD": admin_password,
            "SENTINEL_API_KEYS": api_keys_json,
            "SENTINEL_TOKEN_SECRET": token_secret,
        }

    # Prefer the DPAPI vault; fall back to plaintext .env only when needed.
    stored_in_vault = False
    try:
        vault.set_many(new_values)
        stored_in_vault = True
    except Exception:  # noqa: BLE001 - DPAPI unavailable
        try:
            block = (
                "\n# ------------------------------------------------------------------\n"
                "# SentinelSOC first-run generated credentials (keep private)\n"
                "# ------------------------------------------------------------------\n"
                + "".join(f"{k}={v}\n" for k, v in new_values.items())
            )
            with open(env_path, "a", encoding="utf-8") as fh:
                fh.write(block)
        except OSError:
            pass  # session-only credentials below still work for this run

    # Make the current process pick the generated values up immediately.
    for k, v in new_values.items():
        os.environ[k] = v

    username = os.environ.get("SENTINEL_ADMIN_USERNAME", "admin")
    print("=" * 62)
    print("SentinelSOC first-run setup complete")
    print("=" * 62)
    if not seeded:
        print("Random credentials were generated ")
    if stored_in_vault:
        print("and stored encrypted in secrets.dat")
        print(f"  ({ENV_PATH.parent / 'secrets.dat'})")
    else:
        print(f"and saved to: {env_path}")
    print()
    print(f"  Dashboard login : {username} / {admin_password}")
    print(f"  Admin API key   : {admin_key}")
    print(f"  Analyst API key : {analyst_key}")
    print()
    print("Save them now - they will not be shown again.")
    print("=" * 62)


_ensure_secure_secrets()

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
PROJECT_ROOT = APP_DIR
BACKEND_DIR = BUNDLE_DIR
DATABASE_DIR = APP_DIR / "database"
LOG_DIR = APP_DIR / "logs"
REPORT_DIR = APP_DIR / "reports"
DOCUMENTATION_DIR = APP_DIR / "documentation"

for _d in (DATABASE_DIR, LOG_DIR, REPORT_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
DATABASE_URL = os.environ.get(
    "SENTINEL_DATABASE_URL",
    f"sqlite:///{(DATABASE_DIR / 'sentinel.db').as_posix()}",
)
ECHO_SQL = False
EVENT_RETENTION_DAYS = 30

# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------
COLLECT_INTERVAL_SECONDS = int(os.environ.get("SENTINEL_INTERVAL", "15"))
SCHEDULER_ENABLED = os.environ.get("SENTINEL_SCHEDULER_ENABLED", "1").lower() not in (
    "0", "false", "no", "off",
)
#: Test/dev isolation: when enabled, the alerting service still computes
#: findings but does NOT persist real alerts, notify, publish or stream them.
#: Use while exercising rules interactively (''pytest -k ...'', one-off
#: detection probes) so synthetic test traffic never pollutes the DB.
TEST_MODE = os.environ.get("SENTINEL_TEST_MODE", "0").lower() in ("1", "true", "yes", "on")
EVENT_LOG_POLL_BATCH = 500
SECURITY_LOG_CHANNELS = ["Security", "System"]
POWERSHELL_CHANNELS = [
    "Microsoft-Windows-PowerShell/Operational",
    "Windows PowerShell",
]
MAX_RAW_EVENT_SIZE = 64 * 1024

# New collector channels / sources (live only).
USB_EVENT_IDS = {6416, 6420}
SYSMON_CHANNELS = ["Microsoft-Windows-Sysmon/Operational"]
SIGNATURE_LIST = BUNDLE_DIR / "detection" / "signatures.json"
MAIL_INGEST_DIR = os.environ.get("SENTINEL_MAIL_DIR", "")
MAIL_INGEST_EXTENSIONS = (".eml", ".msg", ".json")

#: Mark the session cookie Secure (requires HTTPS; set to 1 in production).
#: TLS_ENABLED below forces it to 1 automatically — see "Transport security".

# --------------------------------------------------------------------------
# Detection tuning
# --------------------------------------------------------------------------
DETECTION_WINDOW_MINUTES = 10
BRUTE_FORCE_THRESHOLD = 5            # failed logons within window
BRUTE_FORCE_ACCOUNTS = 1             # distinct accounts to consider
PORT_SCAN_DISTINCT_PORTS = 20        # distinct ports probed by one source
PORT_SCAN_WINDOW_SECONDS = 120
HONEYPOT_ACCOUNT_PREFIXES = ("administrator", "admin", "sa", "root")

# --------------------------------------------------------------------------
# Alert aggregation / escalation
# --------------------------------------------------------------------------
#: How many re-triggers of the same open alert escalate its severity.
ALERT_ESCALATE_AFTER = 5
#: Severity ladder used for repeat-trigger escalation.
SEVERITY_LADDER = ("low", "medium", "high", "critical")
#: Alert throttling: no more than ALERT_THROTTLE_MAX_PER_WINDOW new alerts per
#: rule within ALERT_THROTTLE_MINUTES minutes (excess findings refresh the most
#: recent open alert instead of opening new ones).
ALERT_THROTTLE_MINUTES = 5
ALERT_THROTTLE_MAX_PER_WINDOW = 5

# --------------------------------------------------------------------------
# ML lifecycle (retraining / staleness)
# --------------------------------------------------------------------------
ML_RETRAIN_AFTER_MINUTES = int(os.environ.get(
    "SENTINEL_ML_RETRAIN_AFTER_MINUTES", "5"
))  # model older than this (minutes) is stale
ML_RETRAIN_MIN_NEW_EVENTS = 200      # ...or more new events since training
ML_RETRAIN_MIN_NEW_VERDICTS = 5      # ...or N analyst verdicts since training
ML_META_FILE = Path(os.environ.get(
    "SENTINEL_ML_META_FILE",
    (PROJECT_ROOT / "database" / "model_meta.json").as_posix(),
))
#: Version of the event feature space; persisted bundles with a different
#: version are ignored and a clean retrain is forced.
ML_FEATURE_VERSION = 3
#: Persisted model bundle (Isolation Forests + supervised + thresholds).
ML_MODEL_BUNDLE = Path(os.environ.get(
    "SENTINEL_ML_MODEL_BUNDLE",
    (Path(ML_META_FILE).parent / "model.bundle.joblib").as_posix(),
))
#: Label-free threshold target: the per-stream anomaly threshold is the
#: ``(1 - ML_TARGET_FPR)`` quantile of the training score distribution, so the
#: detector flags ~ML_TARGET_FPR of the locally-learned baseline while still
#: catching distribution tails (constant-false-alarm-rate calibration).
ML_TARGET_FPR = float(os.environ.get("SENTINEL_ML_TARGET_FPR", "0.03"))

# --------------------------------------------------------------------------
# ML drift guard (anti "attacker becomes normal")
# --------------------------------------------------------------------------
#: When more than this fraction of recent *scored* events lands above the
#: per-stream anomaly threshold, the detector is considered drifted (the
#: learned baseline no longer reflects the live distribution) and is marked
#: stale so the scheduler retrains and the operator sees the drift signal.
ML_DRIFT_RATE = float(os.environ.get("SENTINEL_ML_DRIFT_RATE", "0.35"))
#: Minimum number of recently scored events required before a drift verdict
#: can be produced (avoids deciding on noise).
ML_DRIFT_MIN_SAMPLES = int(os.environ.get("SENTINEL_ML_DRIFT_MIN_SAMPLES", "40"))

# --------------------------------------------------------------------------
# ML tuning
# --------------------------------------------------------------------------
ML_CONTAMINATION = 0.05
ML_TRAIN_MIN_SAMPLES = 30
ML_RANDOM_STATE = 42

# --------------------------------------------------------------------------
# Risk / scoring weights
# --------------------------------------------------------------------------
SEVERITY_SCORES = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
SECURITY_SCORE_START = 100
SECURITY_SCORE_PENALTY = {"critical": 14, "high": 8, "medium": 4, "low": 1}

# --------------------------------------------------------------------------
# Hybrid risk scoring (rule-based detection vs ML anomaly detection)
# --------------------------------------------------------------------------
ML_RULE_WEIGHT = 0.6
ML_DETECTION_WEIGHT = 0.4
RISK_LEVEL_MEDIUM = 40
RISK_LEVEL_HIGH = 65
RISK_LEVEL_CRITICAL = 85

# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------
HOST = "127.0.0.1"
PORT = 8001
#: HTTPS port used by `start.bat secure` (and the LAN/HTTPS launcher).
TLS_PORT = 8443
CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# --------------------------------------------------------------------------
# Transport security (TLS)
# --------------------------------------------------------------------------
#: Enable HTTPS by serving uvicorn with --ssl-certfile/--ssl-keyfile. When on,
#: the session cookie is forced to Secure automatically.
TLS_ENABLED = os.environ.get("SENTINEL_TLS", "0").lower() in ("1", "true", "yes", "on")
#: PEM certificate / private key paths (generated by scripts/gen_cert.ps1).
TLS_CERT_FILE = os.environ.get(
    "SENTINEL_TLS_CERT", (APP_DIR / "certs" / "sentinel.crt").as_posix()
)
TLS_KEY_FILE = os.environ.get(
    "SENTINEL_TLS_KEY", (APP_DIR / "certs" / "sentinel.key").as_posix()
)
#: When TLS is enabled the cookie MUST be Secure — never honours the env override.
COOKIE_SECURE = TLS_ENABLED or os.environ.get("SENTINEL_COOKIE_SECURE", "0").lower() in (
    "1", "true", "yes", "on",
)

#: Maximum accepted request body, in bytes. Requests with a Content-Length
#: above this (or that grow beyond it while streaming) are rejected with 413
#: before any handler runs. Keeps oversized JSON/upload payloads from being
#: parsed or persisted (mitigates decompression/alloc abuse).
MAX_REQUEST_BYTES = int(os.environ.get("SENTINEL_MAX_REQUEST_BYTES", str(16 * 1024 * 1024)))
#: CSRF protection for cookie-authenticated sessions (double-submit pattern):
#: state-changing requests made with the session cookie must echo the
#: ``sentinel_csrf`` cookie value in the ``X-CSRF-Token`` header. API-key and
#: Bearer-header callers are unaffected (cross-site browsers cannot set those
#: headers), so this can stay enabled alongside legacy clients.
CSRF_ENABLED = os.environ.get("SENTINEL_CSRF_ENABLED", "1").lower() in (
    "1", "true", "yes", "on",
)

# --------------------------------------------------------------------------
# Encryption at rest
# --------------------------------------------------------------------------
#: Encrypt sensitive free-text fields (messages, evidence, command lines,
#: email bodies, chat, audit details) with AES-256-GCM before storage.
#: Default ON for the packaged executable, OFF for source/dev runs unless
#: explicitly enabled. Key lives in the DPAPI vault (secrets.dat).
ENCRYPT_AT_REST = FROZEN or os.environ.get("SENTINEL_ENCRYPT_AT_REST", "0").lower() in (
    "1", "true", "yes", "on",
)
#: Vault key name under which the AES master key is stored.
ENCRYPTION_KEY_NAME = "SENTINEL_ENCRYPTION_KEY"

# --------------------------------------------------------------------------
# Authentication / RBAC
# --------------------------------------------------------------------------
# When enabled, every /api/* request must present a valid API key via the
# `X-API-Key` header. Roles: "analyst" (read + standard ops) / "admin".
# Keys are configured as a JSON map {"key": "role"}; a development default
# is provided so the dashboard works out of the box.
AUTH_ENABLED = os.environ.get("SENTINEL_AUTH_ENABLED", "1").lower() not in (
    "0", "false", "no", "off",
)

_DEFAULT_API_KEYS = {
    "sentinel-dev-admin": "admin",
    "sentinel-dev-analyst": "analyst",
}

# Priorities: vault (DPAPI) > environment > .env. The vault is preferred for
# secrets so they never need to live in plaintext on disk.
def _secret(name: str, default: str = "") -> str:
    """Return a secret preferring the DPAPI vault, then the environment."""
    value = os.environ.get(name)
    if value:
        return value
    try:
        value = _get_vault().get(name)
    except Exception:  # noqa: BLE001 - non-Windows / bad vault
        value = None
    return value if value else default

try:
    _env_keys = json.loads(_secret("SENTINEL_API_KEYS", "{}") or "{}")
except (ValueError, TypeError):
    _env_keys = {}
#: Configured API keys. When SENTINEL_API_KEYS is set, it fully replaces the
#: public development defaults so the shipped keys can never stay valid.
API_KEYS: dict[str, str] = (
    {str(k): str(v) for k, v in _env_keys.items()} if _env_keys else dict(_DEFAULT_API_KEYS)
)

#: Allow the public development keys (sentinel-dev-*) to authenticate. In
#: production set SENTINEL_ALLOW_DEV_KEYS=0 (or set SENTINEL_API_KEYS) so the
#: well-known keys are rejected. The dashboard setup banner warns while they
#: are still accepted.
ALLOW_DEV_KEYS = os.environ.get("SENTINEL_ALLOW_DEV_KEYS", "1").lower() in (
    "1", "true", "yes", "on",
)
_USING_DEV_KEYS = bool(_env_keys) is False or set(_env_keys) & set(_DEFAULT_API_KEYS)
if _USING_DEV_KEYS and not ALLOW_DEV_KEYS:
    raise RuntimeError(
        "Public development API keys (sentinel-dev-*) are disabled via "
        "SENTINEL_ALLOW_DEV_KEYS=0. Configure SENTINEL_API_KEYS in .env before starting."
    )

#: Secret used to sign session tokens (override via SENTINEL_TOKEN_SECRET).
AUTH_TOKEN_SECRET = _secret("SENTINEL_TOKEN_SECRET", "sentinel-soc-session-secret")
#: True once the admin password and API keys are configured (via vault/.env or
#: the environment), i.e. the public development defaults are no longer in force.
SECRETS_CONFIGURED = bool(
    _secret("SENTINEL_ADMIN_PASSWORD") and _secret("SENTINEL_API_KEYS")
)
#: Bootstrap admin that is seeded into the users table on first startup.
ADMIN_USERNAME = os.environ.get("SENTINEL_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = _secret("SENTINEL_ADMIN_PASSWORD", "sentineladmin")

# --------------------------------------------------------------------------
# LDAP / Active Directory SSO (SC5b)
# --------------------------------------------------------------------------
#: Authenticate operators against an external directory (opt-in).
LDAP_ENABLED = os.environ.get("SENTINEL_LDAP_ENABLED", "0").lower() in (
    "1", "true", "yes", "on",
)
#: Directory URL: ldap://host[:389] or ldaps://host[:636].
LDAP_URL = os.environ.get("SENTINEL_LDAP_URL", "")
#: Service account used to search the directory (anonymous if empty).
#: Password comes from the vault first (see ``_secret``), then the environment.
LDAP_BIND_DN = _secret("SENTINEL_LDAP_BIND_DN", "")
LDAP_BIND_PASSWORD = _secret("SENTINEL_LDAP_BIND_PASSWORD", "")
#: Search base for user lookups, e.g. DC=corp,DC=local.
LDAP_BASE_DN = os.environ.get("SENTINEL_LDAP_BASE_DN", "")
#: Filter locating a user by login name; ``{username}`` is substituted.
LDAP_USER_FILTER = os.environ.get(
    "SENTINEL_LDAP_USER_FILTER",
    "(&(objectClass=person)(sAMAccountName={username}))",
)
#: Attribute holding the display name (fallback: CN / user name).
LDAP_NAME_ATTRIBUTE = os.environ.get("SENTINEL_LDAP_NAME_ATTRIBUTE", "displayName")
#: Group names (CN or DN substring, case-insensitive) granting the admin role.
LDAP_ADMIN_GROUPS = [
    g.strip()
    for g in os.environ.get("SENTINEL_LDAP_ADMIN_GROUPS", "Domain Admins,Sentinel Admins").split(",")
    if g.strip()
]
#: Seconds to wait for directory connect/search before failing.
LDAP_SEARCH_TIMEOUT = int(os.environ.get("SENTINEL_LDAP_SEARCH_TIMEOUT", "10"))

# --------------------------------------------------------------------------
# OpenID Connect SSO (SC5c)
# --------------------------------------------------------------------------
#: Authenticate operators via an OpenID Provider (opt-in). Requires
#: SENTINEL_OIDC_ISSUER, SENTINEL_OIDC_CLIENT_ID and (by default) a secret.
OIDC_ENABLED = os.environ.get("SENTINEL_OIDC_ENABLED", "0").lower() in (
    "1", "true", "yes", "on",
)
#: Issuer URL (discovery at <issuer>/.well-known/openid-configuration).
OIDC_ISSUER = os.environ.get("SENTINEL_OIDC_ISSUER", "")
#: OAuth2 client credentials (client secret preferred in the vault).
OIDC_CLIENT_ID = _secret("SENTINEL_OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = _secret("SENTINEL_OIDC_CLIENT_SECRET", "")
#: Space-separated scope list requested at the authorization endpoint.
OIDC_SCOPES = os.environ.get("SENTINEL_OIDC_SCOPES", "openid profile email")
#: Public path that completes the flow (frontend browser is redirected here).
OIDC_REDIRECT_PATH = os.environ.get("SENTINEL_OIDC_REDIRECT_PATH", "/api/auth/oidc/callback")
#: Groups claim carrying role groups (e.g. "groups"). The admin list reuses
#: LDAP_ADMIN_GROUPS so one config controls role mapping for both providers.
OIDC_GROUP_CLAIM = os.environ.get("SENTINEL_OIDC_GROUP_CLAIM", "groups")
#: Claim carrying a display name (fallback: "name", then the sub value).
OIDC_NAME_CLAIM = os.environ.get("SENTINEL_OIDC_NAME_CLAIM", "full_name")
#: Clock-skew allowed when validating id_token "exp"/"iat"/"nbf" (seconds).
OIDC_CLOCK_SKEW = int(os.environ.get("SENTINEL_OIDC_CLOCK_SKEW", "30"))

# --------------------------------------------------------------------------
# Centralized logging / SIEM forwarding
# --------------------------------------------------------------------------
#: Output format: "json" (SIEM-friendly) or "text" (human console).
LOG_FORMAT = os.environ.get("SENTINEL_LOG_FORMAT", "text")
#: Optional remote syslog (SIEM) collector. Leave empty to disable.
#: UDP RFC3164 (default) or TCP RFC5424 via SENTINEL_SYSLOG_PROTO=tcp.
SYSLOG_HOST = os.environ.get("SENTINEL_SYSLOG_HOST", "")
SYSLOG_PORT = int(os.environ.get("SENTINEL_SYSLOG_PORT", "514"))
SYSLOG_PROTO = os.environ.get("SENTINEL_SYSLOG_PROTO", "udp").lower()
#: Include audit-trail entries in the syslog stream (recommended ON for SIEM).
SYSLOG_AUDIT = os.environ.get("SENTINEL_SYSLOG_AUDIT", "1").lower() in (
    "1", "true", "yes", "on",
)

# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------
ORGANIZATION_NAME = "SentinelSOC Prototype Lab"
ANALYST_NAME = "SentinelSOC Analyst"

# --------------------------------------------------------------------------
# Notifications (opt-in)
# --------------------------------------------------------------------------
# Generic webhook URL (JSON POST) and/or SMTP relay. Leave empty to disable.
# NOTIFY_MIN_SEVERITY: low | medium | high | critical
WEBHOOK_URL = os.environ.get("SENTINEL_WEBHOOK_URL", "")
SMTP_HOST = os.environ.get("SENTINEL_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SENTINEL_SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SENTINEL_SMTP_USERNAME", "")
# Enforce STARTTLS encryption for SMTP (port 587). Set 0 only for local-only relays.
SMTP_STARTTLS = os.environ.get("SENTINEL_SMTP_STARTTLS", "1").lower() not in (
    "0",
    "false",
    "no",
    "off",
)
SMTP_FROM = os.environ.get("SENTINEL_SMTP_FROM", "sentinel@localhost")
SMTP_TO = os.environ.get("SENTINEL_SMTP_TO", "")
SMTP_PASSWORD = _secret("SENTINEL_SMTP_PASSWORD", "")
NOTIFY_MIN_SEVERITY = os.environ.get("SENTINEL_NOTIFY_MIN_SEVERITY", "high")
# Windows toast notifications (PowerShell helper; best-effort).
TOAST_ENABLED = os.environ.get("SENTINEL_TOAST_ENABLED", "1").lower() not in (
    "0", "false", "no", "off",
)

# --------------------------------------------------------------------------
# Multi-endpoint ingest
# --------------------------------------------------------------------------
# JSON map {"agent_key": "agent-id"} for POST /api/ingest. A development
# default is provided; override via SENTINEL_AGENT_KEYS.
try:
    _env_agent_keys = json.loads(_secret("SENTINEL_AGENT_KEYS", "{}") or "{}")
except (ValueError, TypeError):
    _env_agent_keys = {}
AGENT_KEYS: dict[str, str] = {
    "sentinel-agent-dev": "agent-dev",
    **{str(k): str(v) for k, v in _env_agent_keys.items()},
}

# --------------------------------------------------------------------------
# AI assistant
# --------------------------------------------------------------------------
# When set, the assistant delegates to an OpenAI-compatible endpoint.
# Leave empty to use the fully local rule/TF-IDF engine (default).
AI_API_URL = os.environ.get("SENTINEL_AI_API_URL", "")
AI_API_KEY = _secret("SENTINEL_AI_API_KEY", "")
AI_MODEL = os.environ.get("SENTINEL_AI_MODEL", "local")

# --------------------------------------------------------------------------
# Threat intelligence
# --------------------------------------------------------------------------
# Optional provider API keys. When empty, the local offline reputation feed
# (backend/threatintel/feeds.py) is used; lookups are cached in the database
# for THREAT_INTEL_CACHE_HOURS.
THREAT_INTEL_ENABLED = os.environ.get("SENTINEL_THREAT_INTEL_ENABLED", "1") == "1"
THREAT_INTEL_ABUSEIPDB_KEY = _secret("SENTINEL_ABUSEIPDB_KEY", "")
THREAT_INTEL_OTX_KEY = _secret("SENTINEL_OTX_KEY", "")
THREAT_INTEL_VT_KEY = _secret("SENTINEL_VT_KEY", "")
THREAT_INTEL_CACHE_HOURS = int(os.environ.get("SENTINEL_THREAT_INTEL_CACHE_HOURS", "24"))
THREAT_INTEL_TIMEOUT = float(os.environ.get("SENTINEL_THREAT_INTEL_TIMEOUT", "8"))

# --------------------------------------------------------------------------
# Streaming pipeline (Kafka / Redis / Elasticsearch forwarding)
# --------------------------------------------------------------------------
# Optional outbound bus for normalized events and alerts. Each sink is
# independent: configure the URL of a sink you have running and the exporter
# enables it; unconfigured sinks stay dormant. Missing driver packages
# degrade gracefully (logged once, sink reported as "unavailable") so the
# platform keeps working on a stock install.
STREAM_ENABLED = os.environ.get("SENTINEL_STREAM_ENABLED", "0").lower() in (
    "1", "true", "yes", "on", "kafka", "redis", "es", "all",
)
#: Kafka bootstrap servers (comma-separated host:port) and topic to publish.
KAFKA_BOOTSTRAP_SERVERS = os.environ.get("SENTINEL_KAFKA_BOOTSTRAP", "")
KAFKA_TOPIC = os.environ.get("SENTINEL_KAFKA_TOPIC", "sentinel-events")
#: Redis URL (redis://host:6379) + stream key for Redis Streams / PubSub.
REDIS_URL = os.environ.get("SENTINEL_REDIS_URL", "")
REDIS_STREAM = os.environ.get("SENTINEL_REDIS_STREAM", "sentinel:events")
#: Elasticsearch / OpenSearch base URL + index pattern (rolling daily suffix).
ELASTICSEARCH_URL = os.environ.get("SENTINEL_ELASTICSEARCH_URL", "")
ELASTICSEARCH_INDEX = os.environ.get("SENTINEL_ELASTICSEARCH_INDEX", "sentinel-events")
ELASTICSEARCH_USERNAME = os.environ.get("SENTINEL_ELASTICSEARCH_USERNAME", "")
ELASTICSEARCH_PASSWORD = _secret("SENTINEL_ELASTICSEARCH_PASSWORD", "")
#: Batching / retry tuning for the outbound buffer.
STREAM_BATCH_SIZE = int(os.environ.get("SENTINEL_STREAM_BATCH_SIZE", "25"))
STREAM_FLUSH_SECONDS = float(os.environ.get("SENTINEL_STREAM_FLUSH_SECONDS", "5.0"))
STREAM_MAX_RETRIES = int(os.environ.get("SENTINEL_STREAM_MAX_RETRIES", "2"))

# --------------------------------------------------------------------------
# Entity intelligence graph
# --------------------------------------------------------------------------
# The entity graph is exposed through a provider interface so the storage
# backend can be swapped: "postgres" (default - uses the existing database,
# no extra services) or "neo4j" (requires a running Neo4j server + the
# `neo4j` driver). "auto" tries Neo4j only when SENTINEL_NEO4J_URI is set
# and falls back to Postgres.
GRAPH_PROVIDER = os.environ.get("SENTINEL_GRAPH_PROVIDER", "postgres").lower()
NEO4J_URI = os.environ.get("SENTINEL_NEO4J_URI", "")
NEO4J_USER = os.environ.get("SENTINEL_NEO4J_USER", "neo4j")
NEO4J_PASSWORD = _secret("SENTINEL_NEO4J_PASSWORD", "")
NEO4J_DATABASE = os.environ.get("SENTINEL_NEO4J_DATABASE", "neo4j")
#: Cap on graph expansion (neighbours / node count) served to the UI.
GRAPH_MAX_NODES = int(os.environ.get("SENTINEL_GRAPH_MAX_NODES", "250"))
