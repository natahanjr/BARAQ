"""Central configuration for SentinelSOC.

All tunable parameters of the platform live here so the application can be
adjusted without touching business logic. Optimised for a low-resource
single Windows 11 laptop (i5 / 12 GB RAM).
"""
import json
import os
from pathlib import Path

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


_load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
DATABASE_DIR = PROJECT_ROOT / "database"
LOG_DIR = PROJECT_ROOT / "logs"
REPORT_DIR = PROJECT_ROOT / "reports"
DOCUMENTATION_DIR = PROJECT_ROOT / "documentation"

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
SIGNATURE_LIST = Path(__file__).resolve().parent / "detection" / "signatures.json"
MAIL_INGEST_DIR = os.environ.get("SENTINEL_MAIL_DIR", "")
MAIL_INGEST_EXTENSIONS = (".eml", ".msg", ".json")

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
PORT = 8000
CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]

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
try:
    _env_keys = json.loads(os.environ.get("SENTINEL_API_KEYS", "{}") or "{}")
except (ValueError, TypeError):
    _env_keys = {}
API_KEYS: dict[str, str] = {**_DEFAULT_API_KEYS, **{str(k): str(v) for k, v in _env_keys.items()}}

# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------
ORGANIZATION_NAME = "SentinelSOC Prototype Lab"
ANALYST_NAME = "SentinelSOC Analyst"

# --------------------------------------------------------------------------
# AI assistant
# --------------------------------------------------------------------------
# When set, the assistant delegates to an OpenAI-compatible endpoint.
# Leave empty to use the fully local rule/TF-IDF engine (default).
AI_API_URL = os.environ.get("SENTINEL_AI_API_URL", "")
AI_API_KEY = os.environ.get("SENTINEL_AI_API_KEY", "")
AI_MODEL = os.environ.get("SENTINEL_AI_MODEL", "local")
