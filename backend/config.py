"""Central configuration for SentinelSOC.

All tunable parameters of the platform live here so the application can be
adjusted without touching business logic. Optimised for a low-resource
single Windows 11 laptop (i5 / 12 GB RAM).
"""
import os
from pathlib import Path

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
EVENT_LOG_POLL_BATCH = 500
SECURITY_LOG_CHANNELS = ["Security", "System"]
POWERSHELL_CHANNELS = [
    "Microsoft-Windows-PowerShell/Operational",
    "Windows PowerShell",
]
MAX_RAW_EVENT_SIZE = 64 * 1024

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
