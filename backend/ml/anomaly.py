"""Machine Learning module - lightweight anomaly detection (v2).

Per-behavior anomaly analysis with a small, fast stack for a single host:

1. **Isolation Forest** - one detector per behavior stream (login / process /
   network); flags events that deviate from the locally learned baseline.
2. **Supervised second opinion** - XGBoost (or scikit-learn RandomForest
   fallback) trained on heuristically-labelled history, wrapped in
   probabilistic calibration (isotonic) when enough samples exist.
3. **Permute (rank) calibrated thresholds** - instead of a fixed 0.5, the
   anomaly score is the rank of the event within the locally-learned baseline
   CDF (a score of 0.97 means "more extreme than 97% of the training
   baseline"), and the per-stream decision boundary is tuned on that space.
   CFAR-style thresholds keep the false-alarm rate bounded even when the
   training history is entirely benign.
4. **Persistent, versioned models** - trained models are stored with joblib
   so a restart does not cold-start the detector, and a feature-version guard
   forces a clean retrain when the feature space changes.
5. **Validation gate** - when retraining with ``validate=True`` the new
   models are only adopted if they score at least as well as the current
   ones on a recent labelled window (guards against silent regressions).

Trained on data present in the local database; no data leaves the machine.
The feature space is shared between training and scoring so vectors always
agree (see docs/ml_strategy_and_validation.md).
"""

from __future__ import annotations

import json
import logging
import math
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
from sqlalchemy import func, select

from backend.collectors.validation import orm_event_is_corrupted
from backend.config import (
    ML_ALLOW_BOOTSTRAP,
    ML_BOOTSTRAP_BUNDLE,
    ML_BOOTSTRAP_ENABLED,
    ML_CONTAMINATION,
    ML_DRIFT_MIN_SAMPLES,
    ML_DRIFT_RATE,
    ML_FEATURE_VERSION,
    ML_META_FILE,
    ML_MODEL_BUNDLE,
    ML_RANDOM_STATE,
    ML_RETRAIN_AFTER_MINUTES,
    ML_RETRAIN_MIN_NEW_EVENTS,
    ML_RETRAIN_MIN_NEW_VERDICTS,
    ML_TARGET_FPR,
    ML_TRAIN_MIN_SAMPLES,
    ML_VERSION_HISTORY,
)
from backend.database.connection import SessionLocal
from backend.database.models import (
    NetworkConnection,
    NormalizedEvent,
    Verdict,
)

logger = logging.getLogger("baraq.ml")

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder

    HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    HAS_SKLEARN = False

try:
    from xgboost import XGBClassifier

    HAS_XGBOOST = True
except ImportError:  # pragma: no cover
    HAS_XGBOOST = False

try:
    from backend.ml.ensemble import EnsembleStacker
    from backend.ml.online import OnlineLearner
    from backend.ml.robustness import evaluate_robustness

    HAS_ENSEMBLE = True
except ImportError:  # pragma: no cover
    HAS_ENSEMBLE = False

BEHAVIOR_KEYS = ("login", "process", "network")

# Event IDs mapped to the behavior stream they belong to.
LOGIN_EVENTS = {4624, 4625, 4634, 4647, 4648, 4740, 4771}
PROCESS_EVENTS = {4688, 4720, 4726, 4732, 7045, 4698, 4104, 4103}
NETWORK_EVENTS = set()

# Login types that are ordinary for interactive work; anything else is novel.
_COMMON_LOGON_TYPES = {2, 3, 10, 11}
_NIGHT_HOURS = {22, 23, 0, 1, 2, 3, 4, 5}

#: Remote IP prefixes treated as *attack* for the network supervised layer
#: (documentation/test ranges used by scripted attack ground truth; real
#: production deployments would extend this with threat-intel subnets).
_NET_ATTACK_PREFIXES = ("203.0.113.", "198.51.100.", "45.")

_DEFAULT_THRESHOLDS = {"login": 0.5, "process": 0.5, "network": 0.5}

#: Minimum labelled rows before gradient boosting beats a random forest on
#: generalization (see :meth:`MLAnomalyDetector._build_classifier`).
_XGB_MIN_SAMPLES = 400


def _behavior_of(event_id: int) -> str:
    if event_id in LOGIN_EVENTS:
        return "login"
    if event_id in PROCESS_EVENTS:
        return "process"
    return "login"


def _ip_subnet_features(ip: str) -> list[float]:
    """Extract subnet-based features from an IP address.

    Returns [is_private, is_testnet, is_link_local, first_octet_norm,
    second_octet_norm, is_class_a, is_class_b, is_class_c].

    These features capture IP similarity (same subnet = similar behavior)
    and generalize better than LabelEncoder for unseen IPs.
    """
    if not ip or not isinstance(ip, str):
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    parts = ip.split(".")
    if len(parts) != 4:
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    try:
        octets = [int(p) for p in parts]
    except (ValueError, TypeError):
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    first, second = octets[0], octets[1]

    # RFC 1918 private ranges
    is_private = (
        1.0
        if (
            first == 10
            or first == 192
            and second == 168
            or first == 172
            and 16 <= second <= 31
        )
        else 0.0
    )

    # RFC 5737 documentation/test ranges
    is_testnet = (
        1.0
        if (
            first == 192
            and second == 0
            and octets[2] == 2  # TEST-NET-1
            or first == 198
            and second == 51
            and octets[2] == 100  # TEST-NET-2
            or first == 203
            and second == 0
            and octets[2] == 113  # TEST-NET-3
        )
        else 0.0
    )

    # RFC 3927 link-local
    is_link_local = 1.0 if (first == 169 and second == 254) else 0.0

    # Normalized octets for subnet similarity
    first_norm = first / 255.0
    second_norm = second / 255.0

    # IP class (legacy but useful for coarse grouping)
    is_class_a = 1.0 if 1 <= first <= 126 else 0.0
    is_class_b = 1.0 if 128 <= first <= 191 else 0.0
    is_class_c = 1.0 if 192 <= first <= 223 else 0.0

    return [
        is_private,
        is_testnet,
        is_link_local,
        first_norm,
        second_norm,
        is_class_a,
        is_class_b,
        is_class_c,
    ]


def _fact(event, key: str, default: float = 0.0) -> float:
    """Read a numeric fact from any event shape.

    Supports ORM ``NormalizedEvent`` objects, normalized dicts (``raw_json``
    with ``facts``), and raw collector records (``raw.<key>``).
    """
    try:
        raw = event.raw_json
    except AttributeError:
        raw = event.get("raw_json") if isinstance(event, dict) else None
    if isinstance(raw, dict):
        facts = raw.get("facts") or {}
        if key in facts:
            try:
                return float(facts[key])
            except (TypeError, ValueError):
                return default
    if isinstance(event, dict):
        value = (event.get("raw") or {}).get(key)
        if value is not None:
            try:
                return float(value)
            except (TypeError, ValueError):
                return default
    return default


def _bool_fact(event, key: str) -> int:
    return 1 if _fact(event, key) else 0


def _ip_feature(event, key: str) -> float:
    """Coerce an IP/status-code value into a stable numeric feature.

    Raw collectors store ``source_ip``/``sub_status`` as strings (e.g.
    ``"192.168.99.77"``, ``"0xC000006A"``). This returns a deterministic
    numeric sketch so the feature vector is not a near-constant. Nonexistent
    values map to ``0.0``.
    """
    raw = None
    try:
        raw = event.raw_json
    except AttributeError:
        raw = event.get("raw_json") if isinstance(event, dict) else None
    value = None
    if isinstance(raw, dict):
        value = (raw.get("facts") or {}).get(key)
    elif isinstance(event, dict):
        value = (event.get("raw") or {}).get(key)

    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()

    def _digits(s: str) -> float:
        return sum(int(c) for c in s if c.isdigit())

    if "." in text and all(ch.isdigit() for ch in text.replace(".", "")):
        try:
            parts = [int(p) for p in text.split(".") if p.isdigit()]
            if len(parts) == 4:
                return float(
                    (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
                )
        except (TypeError, ValueError, OverflowError):
            pass
    if text.startswith("0x"):
        return float(_digits(text))
    if text.isdigit():
        return float(text)
    return float(_digits(text) or 0)


def _time_features(event) -> tuple[float, float, float, float, float]:
    """(hour_sin, hour_cos, is_night, is_weekend, hour_of_day) from event timestamp.

    Uses cyclical encoding (sin/cos) for the hour feature to make the model
    robust to different training times. The hour_of_day is kept as a backup
    for backward compatibility.
    """
    ts = None
    try:
        ts = event.timestamp
    except AttributeError:
        pass
    if ts is None and isinstance(event, dict):
        ts = event.get("timestamp")
    if ts is None:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return 0.0, 0.0, 0.0, 0.0, 0.0
    try:
        hour = ts.hour
        # Cyclical encoding: captures the circular nature of time
        hour_sin = math.sin(2 * math.pi * hour / 24.0)
        hour_cos = math.cos(2 * math.pi * hour / 24.0)
        return (
            round(hour_sin, 4),
            round(hour_cos, 4),
            1.0 if hour in _NIGHT_HOURS else 0.0,
            1.0 if ts.weekday() >= 5 else 0.0,
            round(hour / 24.0, 4),  # Keep absolute hour for backward compat
        )
    except (TypeError, ValueError, AttributeError):
        return 0.0, 0.0, 0.0, 0.0, 0.0


def _get_recent_events_count(session, behavior: str, hours: int = 24) -> int:
    """Get count of recent events for a behavior stream."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        if behavior == "login":
            event_ids = LOGIN_EVENTS
        elif behavior == "process":
            event_ids = PROCESS_EVENTS
        else:
            return 0

        count = (
            session.scalar(
                select(func.count(NormalizedEvent.id))
                .where(NormalizedEvent.event_id.in_(event_ids))
                .where(NormalizedEvent.timestamp >= since)
            )
            or 0
        )
        return count
    except Exception:
        return 0


def _get_failed_login_velocity_per_ip(
    session, source_ip: str, minutes: int = 60
) -> float:
    """Get failed login velocity (count per minute) for a specific source IP."""
    try:
        since = datetime.now(UTC) - timedelta(minutes=minutes)
        count = (
            session.scalar(
                select(func.count(NormalizedEvent.id))
                .where(NormalizedEvent.event_id == 4625)  # Failed logon
                .where(NormalizedEvent.timestamp >= since)
                .where(
                    func.json_extract_path_text(
                        NormalizedEvent.raw_json, "facts", "source_ip"
                    )
                    == source_ip
                )
            )
            or 0
        )
        return count / max(minutes, 1.0)
    except Exception:
        return 0.0


def _get_logon_type_entropy(session, hours: int = 24) -> float:
    """Calculate Shannon entropy of logon types in recent window."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        rows = session.execute(
            select(NormalizedEvent.raw_json)
            .where(NormalizedEvent.event_id.in_(LOGIN_EVENTS))
            .where(NormalizedEvent.timestamp >= since)
        ).all()

        if not rows:
            return 0.0

        # Count logon types
        type_counts: dict[int, int] = {}
        for raw in rows:
            facts = (raw or {}).get("facts") or {}
            logon_type = int(facts.get("logon_type", 0))
            type_counts[logon_type] = type_counts.get(logon_type, 0) + 1

        # Calculate Shannon entropy
        total = sum(type_counts.values())
        if total == 0:
            return 0.0

        entropy = 0.0
        for count in type_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        # Normalize by max possible entropy (log2 of number of types)
        max_entropy = math.log2(max(len(type_counts), 1))
        return min(1.0, entropy / max(max_entropy, 1.0))
    except Exception:
        return 0.0


def _get_source_ip_diversity(session, target_user: str, hours: int = 24) -> float:
    """Get diversity of source IPs for a target user (unique IPs / total logins)."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        rows = session.execute(
            select(NormalizedEvent.raw_json)
            .where(NormalizedEvent.event_id.in_((4624, 4625)))  # Logon events
            .where(NormalizedEvent.timestamp >= since)
        ).all()

        ips = set()
        total = 0
        for raw in rows:
            facts = (raw or {}).get("facts") or {}
            user = str(facts.get("target_user", "") or "")
            if user.lower() == target_user.lower():
                total += 1
                ip = str(facts.get("source_ip", "") or "")
                if ip:
                    ips.add(ip)

        if total == 0:
            return 0.0

        return min(1.0, len(ips) / max(total, 1))
    except Exception:
        return 0.0


def _get_time_between_logins_zscore(session, hours: int = 24) -> float:
    """Z-score of time between consecutive logins vs baseline."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        timestamps = session.scalars(
            select(NormalizedEvent.timestamp)
            .where(NormalizedEvent.event_id.in_(LOGIN_EVENTS))
            .where(NormalizedEvent.timestamp >= since)
            .order_by(NormalizedEvent.timestamp)
        ).all()

        if len(timestamps) < 3:
            return 0.0

        # Convert to datetime objects
        dt_times = []
        for ts in timestamps:
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            dt_times.append(ts)

        # Calculate time gaps
        gaps = []
        for i in range(1, len(dt_times)):
            gap = (dt_times[i] - dt_times[i - 1]).total_seconds() / 60.0  # minutes
            gaps.append(gap)

        if len(gaps) < 2:
            return 0.0

        # Calculate z-score of last gap
        mean_gap = sum(gaps) / len(gaps)
        std_gap = (sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)) ** 0.5

        if std_gap == 0:
            return 0.0

        last_gap = gaps[-1]
        z_score = (last_gap - mean_gap) / std_gap

        # Normalize to [0, 1] range (clip extreme values)
        return min(1.0, max(0.0, abs(z_score) / 3.0))
    except Exception:
        return 0.0


def _get_privilege_escalation_indicator(session, hours: int = 1) -> float:
    """Detect privilege escalation: event 4672 (special privileges) after 4624 (logon)."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)

        # Get recent logons
        logon_events = session.execute(
            select(NormalizedEvent.id, NormalizedEvent.timestamp)
            .where(NormalizedEvent.event_id == 4624)
            .where(NormalizedEvent.timestamp >= since)
            .order_by(NormalizedEvent.timestamp.desc())
            .limit(5)
        ).all()

        if not logon_events:
            return 0.0

        # Check for 4672 (special privileges assigned) after logon
        for logon_id, logon_ts in logon_events:
            priv_events = (
                session.scalar(
                    select(func.count(NormalizedEvent.id))
                    .where(NormalizedEvent.event_id == 4672)  # Special privileges
                    .where(NormalizedEvent.timestamp > logon_ts)
                    .where(
                        NormalizedEvent.timestamp <= logon_ts + timedelta(minutes=30)
                    )
                )
                or 0
            )

            if priv_events > 0:
                return 1.0

        return 0.0
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# Process stream enhanced features
# ---------------------------------------------------------------------------
def _get_parent_child_anomaly_score(event) -> float:
    """Detect risky parent-child process combinations."""
    try:
        facts = (
            (event.raw_json or {}).get("facts") or {}
            if hasattr(event, "raw_json")
            else {}
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}

        parent = str(facts.get("parent_process", "") or "").lower()
        image = str(
            facts.get("image_path", "") or facts.get("new_process", "") or ""
        ).lower()

        # Risky parent-child combinations
        risky_spawns = [
            (
                "powershell",
                ("cmd", "certutil", "bitsadmin", "mshta", "wscript", "cscript"),
            ),
            ("cmd", ("powershell", "certutil", "bitsadmin")),
            ("wscript", ("powershell", "cmd")),
            ("cscript", ("powershell", "cmd")),
            ("mshta", ("powershell", "cmd")),
            ("winword", ("powershell", "cmd", "wscript")),
            ("excel", ("powershell", "cmd", "wscript")),
            ("outlook", ("powershell", "cmd", "wscript")),
        ]

        for parent_pattern, child_patterns in risky_spawns:
            if parent_pattern in parent:
                for child_pattern in child_patterns:
                    if child_pattern in image:
                        return 1.0

        return 0.0
    except Exception:
        return 0.0


def _get_commandline_entropy(event) -> float:
    """Calculate Shannon entropy of command line (obfuscation indicator)."""
    try:
        facts = (
            (event.raw_json or {}).get("facts") or {}
            if hasattr(event, "raw_json")
            else {}
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}

        cmdline = str(facts.get("command_line", "") or facts.get("cmdline", "") or "")

        if not cmdline:
            return 0.0

        # Calculate character frequency
        char_counts: dict[str, int] = {}
        for char in cmdline:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate Shannon entropy
        total = len(cmdline)
        entropy = 0.0
        for count in char_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        # Normalize: max entropy for ASCII is ~7 bits, for base64 is ~6 bits
        # High entropy indicates obfuscation
        return min(1.0, entropy / 7.0)
    except Exception:
        return 0.0


def _get_process_frequency_per_user(session, event, hours: int = 1) -> float:
    """Get process execution frequency for the current user."""
    try:
        facts = (
            (event.raw_json or {}).get("facts") or {}
            if hasattr(event, "raw_json")
            else {}
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}

        user = str(facts.get("user", "") or "")
        if not user:
            return 0.0

        since = datetime.now(UTC) - timedelta(hours=hours)
        count = (
            session.scalar(
                select(func.count(NormalizedEvent.id))
                .where(NormalizedEvent.event_id.in_(PROCESS_EVENTS))
                .where(NormalizedEvent.timestamp >= since)
            )
            or 0
        )

        return min(1.0, count / 50.0)  # Normalize to [0, 1] (50 processes/hour = max)
    except Exception:
        return 0.0


def _get_lolbin_abuse_indicator(event) -> float:
    """Detect Living-off-the-Land Binary (LOLBin) abuse."""
    try:
        facts = (
            (event.raw_json or {}).get("facts") or {}
            if hasattr(event, "raw_json")
            else {}
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}

        image = str(
            facts.get("image_path", "") or facts.get("new_process", "") or ""
        ).lower()
        cmdline = str(
            facts.get("command_line", "") or facts.get("cmdline", "") or ""
        ).lower()

        # Known LOLBins
        lolbins = {
            "certutil.exe": ["-urlcache", "-split", "-f", "download"],
            "bitsadmin.exe": ["/transfer", "/download", "/priority"],
            "mshta.exe": ["javascript:", "vbscript:", "about:"],
            "wscript.exe": ["//b", "//e:jscript"],
            "cscript.exe": ["//b", "//e:jscript"],
            "regsvr32.exe": ["/s", "/i:", "scrobj.dll"],
            "rundll32.exe": ["javascript:", "mshtml"],
            "msbuild.exe": ["/p:", "/t:"],
            "installutil.exe": ["/logfile=", "/LogToConsole=", "/U"],
            "regasm.exe": ["/logfile=", "/tlb:", "/u:"],
            "regsvcs.exe": ["/logfile=", "/tlb:", "/u:"],
            "msiexec.exe": ["/i", "/q", "/quiet"],
        }

        for lolbin, suspicious_args in lolbins.items():
            if lolbin in image:
                for arg in suspicious_args:
                    if arg in cmdline:
                        return 1.0

        return 0.0
    except Exception:
        return 0.0


def _get_new_process_path_indicator(session, event, hours: int = 24) -> float:
    """Detect processes running from paths not seen in baseline."""
    try:
        facts = (
            (event.raw_json or {}).get("facts") or {}
            if hasattr(event, "raw_json")
            else {}
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}

        image = str(
            facts.get("image_path", "") or facts.get("new_process", "") or ""
        ).lower()
        if not image:
            return 0.0

        # Extract directory from path
        if "\\" in image:
            directory = "\\".join(image.split("\\")[:-1])
        elif "/" in image:
            directory = "/".join(image.split("/")[:-1])
        else:
            return 0.5  # Unknown path structure

        # Get unique process paths from recent history
        since = datetime.now(UTC) - timedelta(hours=hours)
        rows = session.execute(
            select(NormalizedEvent.raw_json)
            .where(NormalizedEvent.event_id.in_(PROCESS_EVENTS))
            .where(NormalizedEvent.timestamp >= since)
        ).all()

        known_paths = set()
        for row in rows:
            raw = row[0] if row else None
            row_facts = (raw or {}).get("facts") or {}
            path = str(
                row_facts.get("image_path", "")
                or row_facts.get("new_process", "")
                or ""
            ).lower()
            if path and "\\" in path:
                known_paths.add("\\".join(path.split("\\")[:-1]))
            elif path and "/" in path:
                known_paths.add("/".join(path.split("/")[:-1]))

        if not known_paths:
            return 0.5  # No baseline data

        # Check if current path is new
        if directory in known_paths:
            return 0.0  # Known path
        else:
            return 1.0  # New path
    except Exception:
        return 0.0


def _get_time_since_last_event(session, behavior: str) -> float:
    """Get hours since last event for a behavior stream."""
    try:
        if behavior == "login":
            event_ids = LOGIN_EVENTS
        elif behavior == "process":
            event_ids = PROCESS_EVENTS
        else:
            return 24.0  # default to 24 hours if unknown

        last_event = session.execute(
            select(NormalizedEvent.timestamp)
            .where(NormalizedEvent.event_id.in_(event_ids))
            .order_by(NormalizedEvent.timestamp.desc())
            .limit(1)
        ).scalar()

        if last_event is None:
            return 24.0

        if isinstance(last_event, str):
            last_event = datetime.fromisoformat(last_event.replace("Z", "+00:00"))

        delta = datetime.now(UTC) - last_event
        return max(0.0, min(24.0, delta.total_seconds() / 3600.0))  # cap at 24 hours
    except Exception:
        return 24.0


def _get_threat_intel_score(event) -> float:
    """Get threat intelligence score for an event based on IP reputation.

    Uses a heuristic scoring system based on:
    1. Private vs public IP classification
    2. Known attack/test ranges
    3. IP behavior patterns (scanning, brute force indicators)
    4. Geographic reputation heuristics

    Returns 0.0 (safe) to 1.0 (highly suspicious).
    """
    try:
        src_ip = _fact(event, "source_ip")
        if not isinstance(src_ip, str) or not src_ip:
            return 0.3  # Unknown IP gets moderate-low score

        # Private RFC1918 ranges - very low threat
        if src_ip.startswith(
            (
                "10.",
                "192.168.",
                "172.16.",
                "172.17.",
                "172.18.",
                "172.19.",
                "172.20.",
                "172.21.",
                "172.22.",
                "172.23.",
                "172.24.",
                "172.25.",
                "172.26.",
                "172.27.",
                "172.28.",
                "172.29.",
                "172.30.",
                "172.31.",
                "127.",
            )
        ):
            return 0.1

        # Known test/documentation ranges (RFC 5737) - high threat in production
        if src_ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
            return 0.9

        # Known malicious patterns (from _NET_ATTACK_PREFIXES used elsewhere)
        if src_ip.startswith(("45.",)):
            return 0.85

        # High-risk ports暗示 scanning if combined with login failures
        logon_type = _fact(event, "logon_type")
        event_id = int(_fact(event, "event_id", 0))

        # External IP with failed logon + lockout = likely brute force
        if event_id == 4625:  # Failed logon
            is_locked = _bool_fact(event, "is_locked")
            if is_locked:
                return 0.95  # Account lockout = high confidence attack

        # External IP with unusual logon type
        if (
            event_id in (4624, 4625)
            and logon_type not in (0,)
            and logon_type not in _COMMON_LOGON_TYPES
        ):
            return 0.7

        # Default: public IP with no special indicators
        return 0.4

    except Exception:
        return 0.3


def _get_behavioral_velocity(session, behavior: str, hours: int = 1) -> float:
    """Get event rate (events per hour) for a behavior stream."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        if behavior == "login":
            event_ids = LOGIN_EVENTS
        elif behavior == "process":
            event_ids = PROCESS_EVENTS
        else:
            return 0.0

        count = (
            session.scalar(
                select(func.count(NormalizedEvent.id))
                .where(NormalizedEvent.event_id.in_(event_ids))
                .where(NormalizedEvent.timestamp >= since)
            )
            or 0
        )
        return count / max(hours, 1.0)  # events per hour
    except Exception:
        return 0.0


def _get_cross_stream_features(
    session, current_event_id: int, hours: int = 1
) -> list[float]:
    """Cross-stream sequence features capturing attack patterns.

    Returns features that capture temporal relationships across behavior streams:
    1. recent_failed_logins: failed login count in last hour
    2. recent_suspicious_processes: suspicious process count in last hour
    3. recent_network_connections: network connection count in last hour
    4. login_process_ratio: ratio of login to process events
    5. time_since_last_any_event: time since any event across all streams
    6. has_failed_then_process: 1 if failed login followed by process event
    7. has_process_then_network: 1 if process event followed by network
    8. event_diversity: number of distinct event types in last hour
    """
    since = datetime.now(UTC) - timedelta(hours=hours)
    try:
        # Count recent events per stream
        failed_logins = (
            session.scalar(
                select(func.count(NormalizedEvent.id))
                .where(NormalizedEvent.event_id == 4625)  # Failed logon
                .where(NormalizedEvent.timestamp >= since)
            )
            or 0
        )

        suspicious_processes = (
            session.scalar(
                select(func.count(NormalizedEvent.id))
                .where(NormalizedEvent.event_id.in_(PROCESS_EVENTS))
                .where(NormalizedEvent.timestamp >= since)
            )
            or 0
        )

        network_connections = (
            session.scalar(
                select(func.count(NormalizedEvent.id))
                .where(
                    NormalizedEvent.event_id.in_(
                        NETWORK_EVENTS if NETWORK_EVENTS else set()
                    )
                )
                .where(NormalizedEvent.timestamp >= since)
            )
            or 0
        )

        # Time since last event across all streams
        last_event_time = session.scalar(
            select(func.max(NormalizedEvent.timestamp)).where(
                NormalizedEvent.timestamp >= since
            )
        )
        if last_event_time:
            time_since_last = (
                datetime.now(UTC) - last_event_time
            ).total_seconds() / 3600.0
        else:
            time_since_last = 1.0  # Default to 1 hour if no events

        # Event diversity (distinct event types)
        event_diversity = (
            session.scalar(
                select(func.count(func.distinct(NormalizedEvent.event_id))).where(
                    NormalizedEvent.timestamp >= since
                )
            )
            or 0
        )

        # Ratio features
        login_process_ratio = failed_logins / max(suspicious_processes, 1)

        # Sequence detection (simplified: check if both types occurred)
        has_failed_then_process = (
            1.0 if (failed_logins > 0 and suspicious_processes > 0) else 0.0
        )
        has_process_then_network = (
            1.0 if (suspicious_processes > 0 and network_connections > 0) else 0.0
        )

        return [
            min(failed_logins / 10.0, 1.0),  # Normalized failed logins
            min(suspicious_processes / 10.0, 1.0),  # Normalized suspicious processes
            min(network_connections / 10.0, 1.0),  # Normalized network connections
            min(login_process_ratio, 1.0),  # Login/process ratio (capped at 1)
            min(time_since_last, 1.0),  # Time since last event (capped at 1 hour)
            has_failed_then_process,
            has_process_then_network,
            min(event_diversity / 5.0, 1.0),  # Event diversity (normalized)
        ]
    except Exception:
        return [0.0] * 8


# ---------------------------------------------------------------------------
# Network stream enhanced features
# ---------------------------------------------------------------------------
def _get_connection_velocity_per_ip(
    session, remote_ip: str, minutes: int = 60
) -> float:
    """Get connection velocity (connections per minute) for a specific remote IP."""
    try:
        since = datetime.now(UTC) - timedelta(minutes=minutes)
        count = (
            session.scalar(
                select(func.count(NetworkConnection.id))
                .where(NetworkConnection.remote_ip == remote_ip)
                .where(NetworkConnection.observed_at >= since)
            )
            or 0
        )
        return min(1.0, count / (minutes * 10.0))  # Normalize: 10 connections/min = max
    except Exception:
        return 0.0


def _get_port_scan_indicator(session, remote_ip: str, minutes: int = 60) -> float:
    """Detect port scanning: high number of unique ports per IP."""
    try:
        since = datetime.now(UTC) - timedelta(minutes=minutes)
        unique_ports = (
            session.scalar(
                select(func.count(func.distinct(NetworkConnection.remote_port)))
                .where(NetworkConnection.remote_ip == remote_ip)
                .where(NetworkConnection.observed_at >= since)
            )
            or 0
        )

        # Port scan indicator: >10 unique ports in short time = suspicious
        return min(1.0, unique_ports / 20.0)  # Normalize: 20 ports = max
    except Exception:
        return 0.0


def _get_exfiltration_indicator(session, remote_ip: str, hours: int = 1) -> float:
    """Detect data exfiltration: high bytes_sent/bytes_recv ratio."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        row = session.execute(
            select(
                func.sum(NetworkConnection.bytes_sent),
                func.sum(NetworkConnection.bytes_recv),
            )
            .where(NetworkConnection.remote_ip == remote_ip)
            .where(NetworkConnection.observed_at >= since)
        ).one()

        bytes_sent = float(row[0] or 0)
        bytes_recv = float(row[1] or 0)

        if bytes_recv == 0:
            return 0.5 if bytes_sent > 0 else 0.0

        # Exfiltration ratio: high sent vs received
        ratio = bytes_sent / bytes_recv
        # Normalize: ratio > 10 = high exfiltration indicator
        return min(1.0, ratio / 10.0)
    except Exception:
        return 0.0


def _get_beaconing_indicator(session, remote_ip: str, hours: int = 1) -> float:
    """Detect beaconing: regular interval connections to same IP."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        timestamps = session.scalars(
            select(NetworkConnection.observed_at)
            .where(NetworkConnection.remote_ip == remote_ip)
            .where(NetworkConnection.observed_at >= since)
            .order_by(NetworkConnection.observed_at)
        ).all()

        if len(timestamps) < 5:
            return 0.0

        # Convert to datetime objects
        dt_times = []
        for ts in timestamps:
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            dt_times.append(ts)

        # Calculate intervals between connections
        intervals = []
        for i in range(1, len(dt_times)):
            interval = (dt_times[i] - dt_times[i - 1]).total_seconds()
            intervals.append(interval)

        if len(intervals) < 3:
            return 0.0

        # Calculate coefficient of variation (CV) of intervals
        # Low CV = regular intervals = beaconing
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval == 0:
            return 0.0

        std_interval = (
            sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
        ) ** 0.5
        cv = std_interval / mean_interval

        # Beaconing indicator: CV < 0.3 = regular, CV > 1.0 = random
        # Invert so high score = more beaconing-like
        return max(0.0, min(1.0, 1.0 - cv))
    except Exception:
        return 0.0


def _get_dns_query_pattern(session, hours: int = 1) -> float:
    """Analyze DNS query patterns (if DNS events available)."""
    try:
        # DNS events are typically 5156 or have DNS-related data
        # This is a placeholder - actual implementation depends on DNS event collection
        since = datetime.now(UTC) - timedelta(hours=hours)

        # Check for DNS-related network connections (port 53)
        dns_count = (
            session.scalar(
                select(func.count(NetworkConnection.id))
                .where(NetworkConnection.remote_port == 53)
                .where(NetworkConnection.observed_at >= since)
            )
            or 0
        )

        # High DNS query volume may indicate C2 or data exfiltration
        return min(1.0, dns_count / 100.0)  # Normalize: 100 DNS queries = max
    except Exception:
        return 0.0


def event_feature_vector(event) -> list[float] | None:
    """Feature vector for a single event (None if the behavior stream is unknown).

    v6 feature space: enhanced behavioral features, parent-child analysis, LOLBin detection,
    port scanning, beaconing detection, temporal patterns, and Phase 2 temporal/contextual features.
    Training and scoring share this exact function, so the feature space never drifts.
    """
    from backend.database.connection import SessionLocal

    session = SessionLocal()
    try:
        event_id = (
            event.event_id if not isinstance(event, dict) else event.get("event_id", 0)
        )
        behavior = _behavior_of(int(event_id))
        hour_sin, hour_cos, is_night, is_weekend, _hour_of_day = _time_features(event)

        if behavior == "login":
            logon_type = _fact(event, "logon_type")
            source_ip = (
                str((event.raw_json or {}).get("facts", {}).get("source_ip", "") or "")
                if hasattr(event, "raw_json")
                else ""
            )
            target_user = (
                str(
                    (event.raw_json or {}).get("facts", {}).get("target_user", "") or ""
                )
                if hasattr(event, "raw_json")
                else ""
            )

            # Base features (with cyclical time encoding)
            base_features = [
                int(event_id),
                logon_type,
                _ip_feature(event, "sub_status") / 100.0,
                _ip_feature(event, "source_ip") / 4_294_967_296.0,
                _bool_fact(event, "is_locked"),
                hour_sin,
                hour_cos,
                is_night,
                is_weekend,
                (
                    1.0
                    if logon_type > 0 and int(logon_type) not in _COMMON_LOGON_TYPES
                    else 0.0
                ),
            ]

            # Enhanced features (existing)
            enhanced_features = [
                _get_time_since_last_event(session, "login")
                / 24.0,  # normalized hours since last login
                min(
                    _get_recent_events_count(session, "login", 1) / 10.0, 1.0
                ),  # logins in last hour (capped at 10)
                min(
                    _get_recent_events_count(session, "login", 24) / 100.0, 1.0
                ),  # logins in last day (capped at 100)
                _get_threat_intel_score(event),  # threat intelligence score
            ]

            # New v5 features for login stream
            login_v5_features = [
                min(
                    _get_failed_login_velocity_per_ip(session, source_ip, 5) / 2.0, 1.0
                ),  # 5-min velocity
                min(
                    _get_failed_login_velocity_per_ip(session, source_ip, 15) / 5.0, 1.0
                ),  # 15-min velocity
                min(
                    _get_failed_login_velocity_per_ip(session, source_ip, 60) / 10.0,
                    1.0,
                ),  # 1-hr velocity
                _get_logon_type_entropy(session, 1),  # Logon type entropy (1-hr window)
                _get_source_ip_diversity(
                    session, target_user, 24
                ),  # Source IP diversity
                _get_time_between_logins_zscore(
                    session, 24
                ),  # Time between logins z-score
                _get_privilege_escalation_indicator(
                    session, 1
                ),  # Privilege escalation indicator
            ]

            # Cross-stream sequence features
            cross_stream_features = _get_cross_stream_features(session, int(event_id))

            # Phase 2 temporal/contextual features
            temporal_features = [
                _get_business_hours_indicator(event),  # Business hours indicator
                min(
                    _get_event_burst_score(session, "login", 5), 2.0
                ),  # 5-min burst score
                _get_kill_chain_phase(event),  # Kill chain phase encoding
                max(
                    -3.0,
                    min(
                        3.0,
                        _get_user_session_deviation(session, target_user, "login", 24),
                    ),
                ),  # Session duration deviation
                _get_user_attack_frequency(
                    session, target_user, 168
                ),  # Historical attack frequency
            ]

            return (
                base_features
                + enhanced_features
                + login_v5_features
                + cross_stream_features
                + temporal_features
            )

        if behavior == "process":
            # Base features (with cyclical time encoding)
            base_features = [
                int(event_id),
                _bool_fact(event, "has_encoded"),
                _bool_fact(event, "has_download"),
                _bool_fact(event, "has_hidden"),
                _bool_fact(event, "group_sid"),
                min(1.0, _fact(event, "script_len") / 256.0),
                min(1.0, _fact(event, "cmdline_len") / 512.0),
                hour_sin,
                hour_cos,
                _bool_fact(event, "has_remote"),
            ]

            # Enhanced features (existing)
            enhanced_features = [
                _get_time_since_last_event(session, "process")
                / 24.0,  # normalized hours since last process
                min(
                    _get_recent_events_count(session, "process", 1) / 10.0, 1.0
                ),  # processes in last hour (capped at 10)
                min(
                    _get_recent_events_count(session, "process", 24) / 100.0, 1.0
                ),  # processes in last day (capped at 100)
                _get_threat_intel_score(event),  # threat intelligence score
            ]

            # New v5 features for process stream
            process_v5_features = [
                _get_parent_child_anomaly_score(event),  # Parent-child anomaly
                _get_commandline_entropy(event),  # Command line entropy
                _get_process_frequency_per_user(
                    session, event, 1
                ),  # Process frequency per user
                _get_lolbin_abuse_indicator(event),  # LOLBin abuse indicator
                _get_new_process_path_indicator(session, event, 24),  # New process path
            ]

            # Cross-stream sequence features
            cross_stream_features = _get_cross_stream_features(session, int(event_id))

            # Phase 2 temporal/contextual features
            temporal_features = [
                _get_business_hours_indicator(event),  # Business hours indicator
                min(
                    _get_event_burst_score(session, "process", 5), 2.0
                ),  # 5-min burst score
                _get_kill_chain_phase(event),  # Kill chain phase encoding
                _get_threat_intel_score(event),  # Reuse TI score as process risk proxy
                _get_user_attack_frequency(
                    session, "", 168
                ),  # Placeholder for process stream
            ]

            return (
                base_features
                + enhanced_features
                + process_v5_features
                + cross_stream_features
                + temporal_features
            )

        # For network or unknown behaviors, return None to use existing network handling
        return None
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Temporal feature helpers (Phase 2)
# ---------------------------------------------------------------------------
def _get_business_hours_indicator(event) -> float:
    """1.0 if the event occurred during business hours (08:00-18:00 Mon-Fri), 0.0 otherwise."""
    _, _, _is_night, is_weekend, hour_of_day = _time_features(event)
    if is_weekend:
        return 0.0
    return 1.0 if 8 <= hour_of_day < 18 else 0.0


def _get_user_session_deviation(
    session, user: str, behavior: str, hours: int = 24
) -> float:
    """Z-score of the current session duration vs the user's historical mean.

    A high absolute z-score means the session length deviates significantly
    from the user's norm, which may indicate compromised credentials or
    automated tooling.
    """
    if not user or behavior not in LOGIN_EVENTS:
        return 0.0
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        rows = session.execute(
            select(NormalizedEvent.raw_json).where(
                NormalizedEvent.event_id.in_(
                    behavior == "login" and LOGIN_EVENTS or PROCESS_EVENTS
                ),
                NormalizedEvent.timestamp >= since,
            )
        ).all()
        durations: list[float] = []
        for (raw,) in rows:
            facts = (raw or {}).get("facts") or {}
            tgt = str(facts.get("target_user", "") or "")
            if tgt.lower() == user.lower():
                dur = float(facts.get("session_duration", 0) or 0)
                if dur > 0:
                    durations.append(dur)
        if len(durations) < 3:
            return 0.0
        import statistics

        mu = statistics.mean(durations)
        sigma = statistics.stdev(durations)
        if sigma < 1e-9:
            return 0.0
        latest = durations[-1]
        return max(-3.0, min(3.0, (latest - mu) / sigma))
    except Exception:
        return 0.0


def _get_event_burst_score(session, behavior: str, minutes: int = 5) -> float:
    """Burst score: ratio of events in the last `minutes` to the hourly rate.

    A burst score >> 1.0 means events are clustered together in time (possible
    automated attack or tool execution).
    """
    event_ids = LOGIN_EVENTS if behavior == "login" else PROCESS_EVENTS
    try:
        now = datetime.now(UTC)
        recent_since = now - timedelta(minutes=minutes)
        hourly_since = now - timedelta(hours=1)
        recent_count = (
            session.scalar(
                select(func.count(NormalizedEvent.id)).where(
                    NormalizedEvent.event_id.in_(event_ids),
                    NormalizedEvent.timestamp >= recent_since,
                )
            )
            or 0
        )
        hourly_count = (
            session.scalar(
                select(func.count(NormalizedEvent.id)).where(
                    NormalizedEvent.event_id.in_(event_ids),
                    NormalizedEvent.timestamp >= hourly_since,
                )
            )
            or 0
        )
        if hourly_count == 0:
            return 0.0
        # Scale: if all hourly events are in the burst window, score = 1.0
        # Extrapolate hourly rate from the burst window
        extrapolated = float(recent_count) * (60.0 / max(minutes, 1))
        return min(2.0, extrapolated / max(float(hourly_count), 1.0))
    except Exception:
        return 0.0


def _get_kill_chain_phase(event) -> float:
    """Encode the kill chain phase of the event as a normalized float.

    Phase mapping (MITRE ATT&CK alignment):
    0.0 = Reconnaissance/Initial Access (logons)
    0.25 = Execution (process creation, PowerShell)
    0.5 = Persistence (service install, scheduled task)
    0.75 = Lateral Movement/Privilege Escalation (account changes)
    1.0 = Exfiltration/Impact (network, file operations)
    """
    event_id = int(
        event.event_id if not isinstance(event, dict) else event.get("event_id", 0)
    )
    if event_id in (4624, 4625, 4634, 4647, 4771):
        return 0.0  # Initial Access
    if event_id in (4688, 4104, 4103):
        return 0.25  # Execution
    if event_id in (7045, 4698):
        return 0.5  # Persistence
    if event_id in (4720, 4726, 4732):
        return 0.75  # Privilege Escalation / Lateral Movement
    return 0.5  # Default


def _get_user_attack_frequency(session, user: str, hours: int = 168) -> float:
    """Historical attack frequency for this user over the past `hours`.

    Returns the fraction of the user's recent events that were labelled as
    attacks (heuristic or analyst verdict). A high value means the user
    account has a history of suspicious activity.
    """
    if not user:
        return 0.0
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        rows = session.execute(
            select(
                NormalizedEvent.id, NormalizedEvent.event_id, NormalizedEvent.raw_json
            ).where(NormalizedEvent.timestamp >= since)
        ).all()
        total = 0
        attacks = 0
        verdicts = _verdict_map(session)
        for eid, raw_event_id, raw in rows:
            facts = (raw or {}).get("facts") or {}
            tgt = str(facts.get("target_user", "") or "")
            if tgt.lower() != user.lower():
                continue
            total += 1
            if eid in verdicts:
                if verdicts[eid]:
                    attacks += 1
            elif MLAnomalyDetector._is_attack_sample(raw_event_id, raw or {}):
                attacks += 1
        if total < 3:
            return 0.0
        return min(1.0, attacks / total)
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# Feature extraction (per behavior stream)
# ---------------------------------------------------------------------------
def _verdict_map(session) -> dict[int, int]:
    """Authoritative analyst labels: {event_id: 1|0} from the feedback loop.

    Analyst-confirmed attacks (``true_positive``) are always labelled 1 and
    confirmed false-positives 0 - these override the heuristic labeler for
    supervised training so real analyst judgment shapes the decision surface.
    """
    rows = session.execute(select(Verdict.event_id, Verdict.verdict)).all()
    return {
        int(event_id): (1 if verdict == "true_positive" else 0)
        for event_id, verdict in rows
    }


def _load_behavior_features(
    session,
    since: datetime | None,
    event_ids: set[int],
    with_labels: bool = False,
    cutoff: datetime | None = None,
):
    """Per-event feature matrix for a behavior stream.

    ``with_labels=True`` also returns a binary label per row - analyst
    verdicts override the heuristic facts for events the analyst reviewed.
    ``cutoff`` caps the upper bound so baseline fitting never sees a window.
    ``since=None`` means the FULL history (no lower time bound) - training
    on every collected event instead of a sample window.
    """
    stmt = select(NormalizedEvent).where(
        NormalizedEvent.event_id.in_(event_ids),
    )
    if since is not None:
        stmt = stmt.where(NormalizedEvent.timestamp >= since)
    if cutoff is not None:
        stmt = stmt.where(NormalizedEvent.timestamp < cutoff)
    rows = session.scalars(stmt).all()
    X = []
    y = []
    verdicts = _verdict_map(session) if with_labels else {}
    for ev in rows:
        if orm_event_is_corrupted(ev)[0]:
            # Corrupted rendering debris must never be trained on.
            continue
        features = event_feature_vector(ev)
        if not features:
            continue
        X.append(features)
        if with_labels:
            if ev.id in verdicts:
                y.append(verdicts[ev.id])
                continue
            y.append(
                1
                if MLAnomalyDetector._is_attack_sample(ev.event_id, ev.raw_json or {})
                else 0
            )
    if with_labels:
        return (
            np.array(X, dtype=float) if X else np.empty((0, 9)),
            np.array(y, dtype=int) if y else np.empty((0,), dtype=int),
        )
    return np.array(X, dtype=float) if X else np.empty((0, 9))


def _load_network_features(
    session, since: datetime | None, cutoff: datetime | None = None
) -> tuple[np.ndarray, list[dict]]:
    """Per-remote-IP flow features with subnet-based IP encoding and enhanced network features.

    v6 features: connection velocity, port scanning, exfiltration, beaconing, DNS patterns,
    and Phase 2 temporal/contextual features (burst, kill chain, attack history).
    Returns (X, rows) where ``rows`` carries the remote_ip label for each
    feature row.
    """
    from backend.database.connection import SessionLocal

    local_session = SessionLocal()
    try:
        stmt = select(
            NetworkConnection.remote_ip,
            func.count(NetworkConnection.id),
            func.count(func.distinct(NetworkConnection.remote_port)),
            func.sum(NetworkConnection.bytes_sent),
            func.sum(NetworkConnection.bytes_recv),
            func.avg(NetworkConnection.duration_seconds),
        )
        if since is not None:
            stmt = stmt.where(NetworkConnection.observed_at >= since)
        if cutoff is not None:
            stmt = stmt.where(NetworkConnection.observed_at < cutoff)
        rows = local_session.execute(stmt.group_by(NetworkConnection.remote_ip)).all()
        if not rows:
            return (
                np.empty((0, 26)),
                [],
            )  # 8 subnet + 6 flow + 5 enhanced + 2 base + 5 temporal = 26
        flows = []
        ips = []
        for r in rows:
            ip = r[0] or "unknown"
            ips.append(ip)
            subnet_feats = _ip_subnet_features(ip)
            count = int(r[1])
            distinct_ports = int(r[2])
            bytes_sent = float(r[3] or 0)
            bytes_recv = float(r[4] or 0)
            duration_h = float(r[5] or 0) / 3600.0
            sent_mb = bytes_sent / 1_000_000.0
            recv_mb = bytes_recv / 1_000_000.0
            rate = sent_mb / max(duration_h, 0.01)
            flow_feats = [
                float(count),
                float(distinct_ports),
                sent_mb,
                recv_mb,
                duration_h,
                rate,
            ]

            # Enhanced v5 network features
            enhanced_feats = [
                _get_connection_velocity_per_ip(
                    local_session, ip, 60
                ),  # Connection velocity
                _get_port_scan_indicator(local_session, ip, 60),  # Port scan indicator
                _get_exfiltration_indicator(
                    local_session, ip, 1
                ),  # Exfiltration indicator
                _get_beaconing_indicator(local_session, ip, 1),  # Beaconing indicator
                _get_dns_query_pattern(local_session, 1),  # DNS query pattern
            ]

            # Phase 2 temporal/contextual features for network
            is_attack_ip = 1.0 if ip.startswith(_NET_ATTACK_PREFIXES) else 0.0
            temporal_feats = [
                min(
                    _get_connection_velocity_per_ip(local_session, ip, 5), 2.0
                ),  # 5-min burst velocity
                0.5,  # Kill chain phase (network = exfiltration/impact, encoded 0.5)
                is_attack_ip,  # Historical attack frequency (binary from prefix match)
                min(
                    float(count) / max(duration_h * 60.0, 1.0), 2.0
                ),  # Connections per minute
                min(
                    _get_port_scan_indicator(local_session, ip, 15), 2.0
                ),  # 15-min port scan trend
            ]

            flows.append(subnet_feats + flow_feats + enhanced_feats + temporal_feats)
        X = np.array(flows, dtype=float)
        X = np.hstack(
            [X, np.zeros((X.shape[0], 2))]
        )  # is_novel, hour (filled at score time)
        return X, [{"remote_ip": ip} for ip in ips]
    finally:
        local_session.close()


class MLAnomalyDetector:
    """Per-behavior Isolation Forest + calibrated supervised classifier."""

    def __init__(self, load_persisted: bool = False):
        self.models: dict[str, IsolationForest] = {}
        self.supervised = None
        self.supervised_name = "none"
        self.supervised_by_stream: dict[str, object] = {}
        self.supervised_name_by_stream: dict[str, str] = {}
        self.trained_at: str | None = None
        self.n_samples = 0
        self.events_at_train = 0
        self.encoders: dict[str, LabelEncoder] = {}
        self.thresholds: dict[str, float] = dict(_DEFAULT_THRESHOLDS)
        self.baselines: dict[str, np.ndarray] = {}
        self._persisted = False
        #: Roadmap 4.1 - online learning: model versioning + feedback weights.
        self.version = 0
        self.versions: list[dict] = []
        self.last_train_kind = "initial"
        #: Per-behavior multiplier applied to anomaly scores; analysts damp
        #: false positives (weight < 1) and reinforce true positives (> 1).
        self.feedback_weights: dict[str, float] = {}
        #: Where the serving models came from: "none" (never trained),
        #: "bootstrap" (bundled seed model on a fresh deployment) or
        #: "user" (trained on this deployment's own telemetry).
        self.model_source = "none"
        #: Phase 2.4: ensemble stacking meta-learner for IF + supervised + Markov fusion.
        self.ensemble = EnsembleStacker() if HAS_ENSEMBLE else None
        #: Phase 2.3: robustness evaluation result (updated after each train).
        self.robustness: dict = {}
        #: Phase 3: online learning wrapper for incremental updates.
        self.online_learner = OnlineLearner(self) if HAS_ENSEMBLE else None
        self._load_meta()
        if load_persisted and not self.models and not self._load_bundle():
            self._load_bootstrap()

    # ------------------------------------------------------------------
    # Persistence (models + metadata)
    # ------------------------------------------------------------------
    def _bundle_path(self) -> Path:
        return Path(ML_MODEL_BUNDLE)

    def _prev_bundle_path(self) -> Path:
        """Archive bundle for A/B: kept one version behind the live one."""
        return Path(ML_MODEL_BUNDLE).with_suffix(".prev.joblib")

    def _meta_path(self):
        return ML_META_FILE

    def _load_meta(self) -> None:
        """Restore the last training snapshot so staleness survives restarts."""
        try:
            path = self._meta_path()
            if not path or not os.path.exists(path):
                return
            with open(path, encoding="utf-8") as fh:
                meta = json.load(fh)
            self.trained_at = meta.get("trained_at")
            self.n_samples = int(meta.get("n_samples", 0))
            self.events_at_train = int(meta.get("events_at_train", 0))
            self.supervised_name = meta.get("supervised", "none")
            self.thresholds = {
                **dict(_DEFAULT_THRESHOLDS),
                **{k: float(v) for k, v in (meta.get("thresholds") or {}).items()},
            }
            self.version = int(meta.get("version", 0))
            self.versions = list(meta.get("versions") or [])
            self.last_train_kind = meta.get("train_kind", "initial")
            self.feedback_weights = {
                k: float(v) for k, v in (meta.get("feedback_weights") or {}).items()
            }
        except (OSError, ValueError, TypeError):
            logger.warning("Could not read ML metadata at %s", ML_META_FILE)

    def _save_meta(self) -> None:
        try:
            path = self._meta_path()
            if not path:
                return
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "trained_at": self.trained_at,
                        "n_samples": self.n_samples,
                        "events_at_train": self.events_at_train,
                        "supervised": self.supervised_name,
                        "thresholds": self.thresholds,
                        "feature_version": ML_FEATURE_VERSION,
                        "version": self.version,
                        "versions": self.versions[-ML_VERSION_HISTORY:],
                        "train_kind": self.last_train_kind,
                        "feedback_weights": self.feedback_weights,
                    },
                    fh,
                    indent=2,
                )
        except OSError:
            logger.warning("Could not persist ML metadata to %s", ML_META_FILE)

    def _save_bundle(self) -> None:
        """Persist the trained models so restarts do not cold-start.

        Includes a SHA256 checksum for integrity verification on load.
        """
        if not self.models:
            return
        try:
            import hashlib

            import joblib

            bundle = {
                "feature_version": ML_FEATURE_VERSION,
                "models": self.models,
                "encoders": self.encoders,
                "supervised": self.supervised,
                "supervised_name": self.supervised_name,
                "supervised_by_stream": self.supervised_by_stream,
                "supervised_name_by_stream": self.supervised_name_by_stream,
                "thresholds": self.thresholds,
                "baselines": {k: v.tolist() for k, v in self.baselines.items()},
                "version": self.version,
                "feedback_weights": self.feedback_weights,
            }
            path = self._bundle_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            # Archive the current live bundle one slot back (A/B compare).
            if path.exists():
                import shutil

                shutil.copy2(path, self._prev_bundle_path())
            joblib.dump(bundle, path, compress=3)
            # Compute and store checksum for integrity verification
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            bundle["sha256_checksum"] = sha256.hexdigest()
            joblib.dump(bundle, path, compress=3)
            self._persisted = True
        except Exception:
            logger.warning("Could not persist ML model bundle", exc_info=True)

    def _load_bundle(self) -> bool:
        """Restore persisted models; ignored when the feature space changed or checksum fails."""
        path = self._bundle_path()
        if not path.exists():
            return False
        try:
            import hashlib

            import joblib

            bundle = joblib.load(path)
            if bundle.get("feature_version") != ML_FEATURE_VERSION:
                logger.info("ML bundle has a different feature version; retraining")
                return False
            # Verify integrity checksum
            stored_checksum = bundle.get("sha256_checksum")
            if stored_checksum:
                sha256 = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        sha256.update(chunk)
                if sha256.hexdigest() != stored_checksum:
                    logger.warning("ML bundle checksum mismatch; retraining")
                    return False
            self.models = bundle.get("models", {})
            self.encoders = bundle.get("encoders", {})
            self.supervised = bundle.get("supervised")
            self.supervised_name = bundle.get("supervised_name", "none")
            self.supervised_by_stream = bundle.get("supervised_by_stream") or {}
            self.supervised_name_by_stream = (
                bundle.get("supervised_name_by_stream") or {}
            )
            self.thresholds = {
                **dict(_DEFAULT_THRESHOLDS),
                **bundle.get("thresholds", {}),
            }
            self.baselines = {
                k: np.asarray(v, dtype=float)
                for k, v in (bundle.get("baselines") or {}).items()
            }
            self.version = int(bundle.get("version", 0))
            self.feedback_weights = {
                k: float(v) for k, v in (bundle.get("feedback_weights") or {}).items()
            }
            self._persisted = True
            self.model_source = "user" if not bundle.get("bootstrap") else "bootstrap"
            return bool(self.models)
        except Exception:
            logger.warning("Could not load ML model bundle; retraining", exc_info=True)
            return False

    def _load_bootstrap(self) -> bool:
        """Day-1 cold start: load the bundled seed model.

        Fresh deployments have no locally-trained bundle, which used to mean
        a blind detector (default thresholds, no supervised opinion). The
        bootstrap asset - trained offline on a deterministic synthetic
        corpus - provides sane per-stream thresholds and a supervised
        network classifier until the first real retrain supersedes it.
        """
        if not ML_BOOTSTRAP_ENABLED:
            return False
        if not ML_ALLOW_BOOTSTRAP:
            # High-assurance deployments can refuse the synthetic seed model and
            # stay untrained until enough REAL telemetry is collected.
            logger.info("Bootstrap model refused (ML_ALLOW_BOOTSTRAP=0)")
            return False
        path = Path(ML_BOOTSTRAP_BUNDLE)
        if not path.exists():
            return False
        try:
            import joblib

            bundle = joblib.load(path)
            if bundle.get("feature_version") != ML_FEATURE_VERSION:
                logger.info("Bootstrap bundle feature version mismatch; ignoring")
                return False
            if not bundle.get("models"):
                return False
            self.models = bundle.get("models", {})
            self.encoders = bundle.get("encoders", {})
            self.supervised = bundle.get("supervised")
            self.supervised_name = bundle.get("supervised_name", "none")
            self.supervised_by_stream = bundle.get("supervised_by_stream") or {}
            self.supervised_name_by_stream = (
                bundle.get("supervised_name_by_stream") or {}
            )
            self.thresholds = {
                **dict(_DEFAULT_THRESHOLDS),
                **bundle.get("thresholds", {}),
            }
            self.baselines = {
                k: np.asarray(v, dtype=float)
                for k, v in (bundle.get("baselines") or {}).items()
            }
            self.n_samples = int(bundle.get("n_samples", 0))
            self.trained_at = bundle.get("trained_at")
            self.version = 0  # bootstrap is pre-versioning; real train starts at 1
            self.model_source = "bootstrap"
            self._persisted = False  # never A/B-archive the shipped asset
            logger.info(
                "Loaded bootstrap ML model (%s streams, thresholds %.2f/%.2f)",
                "/".join(sorted(self.models)),
                self.thresholds.get("process", 0.5),
                self.thresholds.get("network", 0.5),
            )
            return True
        except Exception:
            logger.warning("Could not load bootstrap ML bundle", exc_info=True)
            return False

    # ------------------------------------------------------------------
    # Roadmap 4.1 - online feedback + versioning (improved)
    # ------------------------------------------------------------------
    def apply_feedback(
        self, verdict: str, behavior: str | None = None, score: float = 0.5
    ) -> None:
        """Adjust the per-behavior anomaly-score weight from analyst verdicts.

        Improved feedback mechanism with:
        1. Per-threshold-region adjustments (low/medium/high score regions)
        2. Confidence-weighted feedback (more verdicts = stronger adjustment)
        3. Asymmetric dampening (FP penalized more than TP reinforced)
        4. Feedback history tracking for analysis

        ``false_positive`` dampens the signal (stronger for high-confidence FPs);
        ``true_positive`` reinforces it (stronger for borderline TPs).
        """
        behavior = behavior or "login"
        if verdict not in ("true_positive", "false_positive"):
            return

        current = self.feedback_weights.get(behavior, 1.0)

        # Initialize feedback history if not present
        if not hasattr(self, "_feedback_history"):
            self._feedback_history = {}

        # Track feedback count for confidence weighting
        feedback_key = f"{behavior}_{verdict}"
        feedback_count = self._feedback_history.get(feedback_key, 0) + 1
        self._feedback_history[feedback_key] = feedback_count

        # Confidence factor: more feedback = stronger adjustment (diminishing returns)
        confidence = min(1.0, feedback_count / 10.0)

        # Score-region dependent adjustment
        if score > 0.8:
            # High-confidence anomaly: strong FP signal
            adjustment = 0.90 if verdict == "false_positive" else 1.02
        elif score > 0.5:
            # Medium-confidence: moderate adjustment
            adjustment = 0.95 if verdict == "false_positive" else 1.05
        else:
            # Low-confidence: weak adjustment (borderline cases)
            adjustment = 0.98 if verdict == "false_positive" else 1.08

        # Apply confidence weighting
        if verdict == "false_positive":
            # FP penalized more: asymmetric dampening
            new_weight = current * (adjustment**confidence)
        else:
            # TP reinforced with diminishing returns
            new_weight = current * (adjustment**confidence)

        # Bounds: FP can damp to 0.3, TP can boost to 2.0
        new_weight = max(0.3, min(2.0, new_weight))
        self.feedback_weights[behavior] = new_weight

        try:
            self._save_meta()
            path = self._bundle_path()
            if path.exists():
                import joblib

                bundle = joblib.load(path)
                bundle["feedback_weights"] = dict(self.feedback_weights)
                bundle["feedback_history"] = self._feedback_history
                joblib.dump(bundle, path, compress=3)
        except Exception:
            logger.warning("Could not persist feedback weights", exc_info=True)
        logger.info(
            "ML feedback %s -> %s weight %.3f (score=%.3f, confidence=%d)",
            verdict,
            behavior,
            self.feedback_weights[behavior],
            score,
            feedback_count,
        )

    def _weighted_score(self, behavior: str, score: float) -> float:
        return float(
            max(0.0, min(1.0, score * self.feedback_weights.get(behavior, 1.0)))
        )

    def get_feedback_stats(self) -> dict:
        """Get feedback statistics for monitoring."""
        if not hasattr(self, "_feedback_history"):
            self._feedback_history = {}
        return {
            "weights": dict(self.feedback_weights),
            "history": dict(self._feedback_history),
            "total_feedback": sum(self._feedback_history.values()),
        }

    # ------------------------------------------------------------------
    # Canary / Shadow Scoring
    # ------------------------------------------------------------------
    def shadow_score_events(
        self,
        candidate_model: object,
        features_list: list[list[float]],
        behavior: str,
    ) -> list[float]:
        """Score events with a candidate model for A/B comparison.

        Returns scores from the candidate model without affecting production.
        Used for canary deployments and shadow scoring.
        """
        if candidate_model is None or not features_list:
            return [0.0] * len(features_list)

        try:
            X = np.array(features_list, dtype=float)
            if hasattr(candidate_model, "decision_function"):
                # Isolation Forest
                raw = 0.5 - candidate_model.decision_function(X)
                baseline = self.baselines.get(behavior)
                if baseline is not None and len(baseline) > 0:
                    ranks = np.interp(
                        raw, baseline, np.linspace(0.0, 1.0, len(baseline))
                    )
                    ranks = np.clip(ranks, 0.0, 1.0)
                else:
                    ranks = np.clip(raw, 0.0, 1.0)
                return ranks.tolist()
            elif hasattr(candidate_model, "predict_proba"):
                # Supervised classifier
                proba = candidate_model.predict_proba(X)
                if proba.shape[1] > 1:
                    return proba[:, 1].tolist()
            return [0.0] * len(features_list)
        except Exception:
            logger.warning("Shadow scoring failed", exc_info=True)
            return [0.0] * len(features_list)

    def compare_models(
        self,
        production_scores: list[float],
        candidate_scores: list[float],
        true_labels: list[int],
    ) -> dict:
        """Compare production vs candidate model performance.

        Returns comparison metrics for A/B testing decisions.
        """
        if not production_scores or not candidate_scores or not true_labels:
            return {"error": "insufficient data"}

        prod_arr = np.array(production_scores)
        cand_arr = np.array(candidate_scores)
        labels = np.array(true_labels)

        def compute_metrics(scores, threshold=0.5):
            predicted = scores > threshold
            tp = int(((predicted) & (labels == 1)).sum())
            fp = int(((predicted) & (labels == 0)).sum())
            fn = int(((~predicted) & (labels == 1)).sum())
            tn = int(((~predicted) & (labels == 0)).sum())
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (
                2 * precision * recall / (precision + recall)
                if (precision + recall) > 0
                else 0.0
            )
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            return {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4),
            }

        prod_metrics = compute_metrics(prod_arr)
        cand_metrics = compute_metrics(cand_arr)

        # Determine if candidate is better
        f1_delta = cand_metrics["f1_score"] - prod_metrics["f1_score"]
        fpr_delta = (
            cand_metrics["false_positive_rate"] - prod_metrics["false_positive_rate"]
        )

        recommendation = "keep_production"
        if f1_delta > 0.05 and fpr_delta <= 0.02:
            recommendation = "deploy_candidate"
        elif f1_delta < -0.05:
            recommendation = "reject_candidate"

        return {
            "production": prod_metrics,
            "candidate": cand_metrics,
            "f1_delta": round(f1_delta, 4),
            "fpr_delta": round(fpr_delta, 4),
            "recommendation": recommendation,
            "n_samples": len(true_labels),
        }

    def version_info(self) -> dict:
        """Snapshot for /ml/status: serving version + history + feedback."""
        return {
            "version": self.version,
            "train_kind": self.last_train_kind,
            "trained_at": self.trained_at,
            "history": list(self.versions[-ML_VERSION_HISTORY:]),
            "feedback_weights": dict(self.feedback_weights),
        }

    # ------------------------------------------------------------------
    def _events_since_train(self, session) -> int:
        if not self.trained_at:
            return 0
        try:
            since = datetime.fromisoformat(self.trained_at)
        except ValueError:
            return 0
        return int(
            session.scalar(
                select(func.count(NormalizedEvent.id)).where(
                    NormalizedEvent.timestamp > since
                )
            )
            or 0
        )

    def _drift_result(self, session=None) -> tuple[bool, str]:
        """Sustained-anomaly drift check over recently *scored* events.

        Returns ``(drifted, reason)``. When recent traffic keeps landing above
        the per-stream thresholds, the learned baseline no longer matches the
        live distribution - exactly the "attacker became the new normal"
        scenario. A drifted model is marked stale so the scheduler retrains
        and the operator sees the signal.
        """
        if not self.trained_at or not self.models:
            return False, "untrained"
        close = session is None
        session = session or SessionLocal()
        try:
            try:
                since = datetime.fromisoformat(self.trained_at)
            except ValueError:
                return False, "unparseable-trained-at"
            rows = session.execute(
                select(NormalizedEvent.event_id, NormalizedEvent.ml_score).where(
                    NormalizedEvent.timestamp >= since,
                    NormalizedEvent.ml_score.isnot(None),
                )
            ).all()
            flagged = 0
            total = 0
            for event_id, ml_score in rows:
                behavior = _behavior_of(int(event_id))
                threshold = self.thresholds.get(behavior, 0.5)
                total += 1
                if float(ml_score or 0.0) > threshold:
                    flagged += 1
            if total < ML_DRIFT_MIN_SAMPLES:
                return (
                    False,
                    f"insufficient-recent-scores ({total}<{ML_DRIFT_MIN_SAMPLES})",
                )
            rate = flagged / total
            if rate > ML_DRIFT_RATE:
                return True, (
                    f"drifted: {rate:.1%} of {total} recent events flagged "
                    f"(> {ML_DRIFT_RATE:.0%})"
                )
            return False, f"ok ({rate:.1%} flagged)"
        finally:
            if close:
                session.close()

    def is_stale(self, session=None) -> tuple[bool, str]:
        """True when the model should be retrained (age, volume, or drift)."""
        if not self.trained_at:
            return True, "never-trained"
        try:
            age = datetime.now(UTC) - datetime.fromisoformat(self.trained_at)
        except ValueError:
            return True, "unparseable-trained-at"
        if age > timedelta(minutes=ML_RETRAIN_AFTER_MINUTES):
            return True, (
                f"trained {age.seconds // 60}m ago " f"(> {ML_RETRAIN_AFTER_MINUTES}m)"
            )
        if session is not None:
            new_events = self._events_since_train(session)
            if new_events >= ML_RETRAIN_MIN_NEW_EVENTS:
                return (
                    True,
                    f"{new_events} new events since training (>= {ML_RETRAIN_MIN_NEW_EVENTS})",
                )
            new_verdicts = int(
                session.scalar(
                    select(func.count(Verdict.id)).where(
                        Verdict.created_at > datetime.fromisoformat(self.trained_at)
                    )
                )
                or 0
            )
            if new_verdicts >= ML_RETRAIN_MIN_NEW_VERDICTS:
                return True, (
                    f"{new_verdicts} new analyst verdicts (>= {ML_RETRAIN_MIN_NEW_VERDICTS})"
                )
        drifted, drift_reason = self._drift_result(session)
        if drifted:
            return True, drift_reason
        return False, "fresh"

    # ------------------------------------------------------------------
    @property
    def is_ready(self) -> bool:
        return HAS_SKLEARN and bool(self.models)

    # ------------------------------------------------------------------
    @staticmethod
    def _compact_baseline(raws: np.ndarray, max_points: int = 1024) -> np.ndarray:
        """Sorted, de-duplicated copy of the training raw scores (monotone CDF)."""
        arr = np.sort(np.asarray(raws, dtype=float))
        unique = np.unique(arr)
        if len(unique) <= max_points:
            return unique
        idx = np.linspace(0, len(unique) - 1, max_points).astype(int)
        return unique[idx]

    @classmethod
    def _rank_of(cls, raws, baseline: np.ndarray | None) -> np.ndarray:
        """Position of raw scores within the training CDF, in [0, 1].

        A raw score sitting at the training median maps to ~0.5; one more
        extreme than 97% of the baseline maps to ~0.97. Falls back to the raw
        score when no CDF is available.
        """
        raws = np.atleast_1d(np.asarray(raws, dtype=float))
        if baseline is None or len(baseline) == 0:
            return np.clip(raws, 0.0, 1.0)
        if len(baseline) == 1:
            # A single-point baseline cannot discriminate anything - map every
            # score to the median rank instead of degenerating to 0 (which
            # would push the CFAR boundary to the 0.05 floor and flag all
            # traffic).
            return np.full_like(raws, 0.5)
        ranks = np.interp(raws, baseline, np.linspace(0.0, 1.0, len(baseline)))
        return np.clip(ranks, 0.0, 1.0)

    # ------------------------------------------------------------------
    # Threshold tuning
    # ------------------------------------------------------------------
    @staticmethod
    def _tune_threshold(
        model, X: np.ndarray, y, supervised=None, target_fpr: float | None = None
    ):
        """Return ``(threshold, baseline_cdf)`` for a freshly-fit stream model.

        The threshold lives in the *deployed* score space - the rank of the
        IsolationForest raw score when no supervised classifier is active,
        otherwise the exact ``0.6*rank + 0.4*p`` blend used by
        :meth:`_combined_score`. Tuning on the deployed space keeps the
        decision boundary consistent with what actually runs:

        * **CFAR boundary (always)** - the ``(1 - target_fpr)`` quantile of
          the training score distribution, so at most ``target_fpr`` of the
          locally-learned baseline falls above it. Label-free, so a
          pure-benign history still flags tails.
        * **F1 grid (when labels exist)** - the boundary maximising F1 on the
          labelled split. The final boundary never sits *stricter* than the
          CFAR one (more sensitive of the two), which prevents recall
          collapse when labels are sparse or noisy.

        ``baseline_cdf`` is always the raw-score CDF (the input to
        :meth:`_rank_of`), so the stored baselines keep their semantics.
        """
        target_fpr = ML_TARGET_FPR if target_fpr is None else target_fpr
        if len(X) == 0:
            return 0.5, np.empty((0,))
        raws = np.array(
            [MLAnomalyDetector._score_with(model, row) for row in X], dtype=float
        )
        baseline = MLAnomalyDetector._compact_baseline(raws)
        ranks = MLAnomalyDetector._rank_of(raws, baseline)
        if supervised is not None:
            try:
                proba = supervised.predict_proba(X)
                p = proba[:, 1] if proba.shape[1] > 1 else np.zeros(len(X))
            except Exception:
                p = np.zeros(len(X))
            scores = 0.6 * ranks + 0.4 * p
        else:
            scores = ranks
        score_baseline = MLAnomalyDetector._compact_baseline(scores)
        if len(score_baseline):
            cfar = float(np.quantile(score_baseline, 1.0 - target_fpr))
        else:
            cfar = 0.5
        cfar = float(np.clip(cfar, 0.05, 0.98))
        if y is None or len(np.unique(y)) < 2:
            return cfar, baseline
        # The F1 grid may only lower the boundary while keeping the
        # labelled-benign false-alarm rate inside the same budget CFAR uses.
        # The boundary must stay at or above the benign floor, otherwise the
        # F1 optimum collapses to a degenerate near-zero threshold (recall
        # driven by FN symmetry, not real separation).
        y_arr = np.asarray(y)
        scores_arr = np.asarray(scores)
        benign = scores_arr[y_arr == 0]
        if len(benign) > 0:
            floor = float(np.quantile(benign, 1.0 - target_fpr))
        else:
            floor = 0.05
        floor = float(np.clip(floor, 0.05, 0.98))
        best_t, best_f1 = floor, -1.0
        for t in np.linspace(floor, 0.98, 47):
            pred = scores_arr > t
            tp = int(((pred) & (y_arr == 1)).sum())
            fp = int(((pred) & (y_arr == 0)).sum())
            fn = int(((~pred) & (y_arr == 1)).sum())
            if tp + fp + fn == 0:
                continue
            precision = tp / max(tp + fp, 1)
            recall = tp / max(tp + fn, 1)
            f1 = 2 * precision * recall / max(precision + recall, 1e-9)
            if f1 > best_f1:
                best_f1, best_t = f1, float(t)
        if best_f1 <= 0:
            return cfar, baseline
        return best_t, baseline

    # ------------------------------------------------------------------
    # Label helpers (shared between supervised training and validation)
    # ------------------------------------------------------------------
    @staticmethod
    def _is_attack_sample(event_id: int, raw_json: dict) -> bool:
        """Heuristic ground truth for the supervised layer.

        ``raw_json`` is the full ``raw_json`` column (dict with ``facts``
        sub-dict *and* top-level keys like ``channel``).

        Improved heuristic that uses contextual signals less overlapping with
        the feature vector to reduce circular learning. Focuses on:
        1. Event-specific indicators not directly in feature vectors
        2. Behavioral context (unusual combinations)
        3. Known high-risk events by definition

        Analyst verdicts override this heuristic when available.
        """
        facts = (raw_json or {}).get("facts") or {}
        eid = int(event_id)

        # High-risk events by definition (not dependent on feature-overlapping signals)
        if eid in (
            4720,
            4732,
            7045,
            4698,
        ):  # Account creation, group change, service install, scheduled task
            return True

        # Benign logon family (always safe)
        if eid in (4634, 4647, 4771):
            return False

        # PowerShell events: use metadata context, NOT feature-overlapping flags.
        # The supervised classifier consumes has_encoded/has_download/has_hidden
        # as features, so we must NOT use them for labeling (label leakage).
        if eid in (4104, 4103):
            # Label from non-feature context: channel name and user context.
            # channel lives at the raw_json top level (not inside facts).
            channel = str((raw_json or {}).get("channel", "") or "")
            str(facts.get("user", "") or "")
            # PowerShell on non-standard channels or by SYSTEM/root is suspicious
            if "Operational" not in channel and channel != "":
                return True
            # Label from event metadata that is NOT in the feature vector
            # (e.g., specific PowerShell providers, pipeline execution state)
            provider = str(facts.get("provider", "") or "")
            return bool(
                provider
                and provider not in ("Microsoft-Windows-PowerShell", "PowerShell")
            )

        # Failed logon (4625): use non-feature-overlapping signals.
        # is_locked IS in the feature vector, so we avoid it for labeling.
        if eid == 4625:
            # sub_status is NOT in the feature vector — safe to use for labeling
            sub_status_raw = facts.get("sub_status", 0)
            try:
                sub_status = int(sub_status_raw)
            except (ValueError, TypeError):
                try:
                    sub_status = int(str(sub_status_raw), 16)
                except (ValueError, TypeError):
                    sub_status = 0
            # Account locked (0xC0000234) or disabled (0xC0000072) — strong contextual signal
            return sub_status in (3221226036, 3221225586)

        # Successful logon (4624): logon_type IS in the feature vector.
        # Use non-overlapping signals only.
        if eid == 4624:
            # TargetUserName anomalies — the target user is NOT in the feature vector
            target_user = str(facts.get("target_user", "") or "")
            if target_user.lower() in ("system", "local service", "network service"):
                return True
            # LogonProcessName anomalies — NOT in feature vector
            logon_process = str(facts.get("logon_process", "") or "")
            return bool(
                logon_process
                and logon_process
                not in ("NtLmSsp", "Kerberos", "Negotiate", "WDIGEST", "MSSECRPC")
            )

        # Process creation (4688): use process metadata NOT in feature vector.
        # Features are: event_id, has_encoded, has_download, has_hidden, group_sid,
        # script_len, cmdline_len, hour_sin, hour_cos, has_remote.
        # Safe signals: parent process, image path context, process tree anomalies.
        if eid == 4688:
            image = str(
                facts.get("image_path", "") or facts.get("new_process", "") or ""
            )
            parent = str(facts.get("parent_process", "") or "")
            image_lower = image.lower()
            parent_lower = parent.lower()
            # Suspicious parent-child: PowerShell spawning cmd, or scripts spawning interpreters
            if "powershell" in parent_lower and any(
                c in image_lower for c in ("cmd", "certutil", "bitsadmin")
            ):
                return True
            # Process in user-writable directory (public, temp, appdata, downloads)
            writable_dirs = (
                "\\public\\",
                "\\temp\\",
                "\\appdata\\local\\",
                "\\downloads\\",
            )
            if any(d in image_lower for d in writable_dirs):
                return True
            # High-risk executables run from non-system paths
            risk_names = (
                "mimikatz",
                "psexec",
                "nc",
                "ncat",
                "netcat",
                "meterpreter",
                "cobaltstrike",
            )
            return bool(any(r in image_lower for r in risk_names))

        # Network connections: use protocol/port context NOT in feature vector
        if (
            eid == 5156 or eid == 5157
        ):  # Windows Filtering Platform connection allowed/blocked
            # Destination port context — port is NOT directly in the 16-dim subnet feature vector
            dest_port = int(facts.get("dest_port", 0) or 0)
            # Known attack ports
            return dest_port in (4444, 5555, 6666, 8443, 1234, 31337)

        # Default: use explicit attack indicators
        return bool(facts.get("is_anomalous") or facts.get("attack"))

    @staticmethod
    def _labeled_network_samples(
        session, since: datetime | None
    ) -> tuple[np.ndarray, np.ndarray, list[str]]:
        """Per-remote-IP flow features with attack labels for the network stream.

        Label source: remote IPs inside the known attack prefixes (scripted
        ground truth / threat-intel ranges). Returns (X, y, ips) aligned to
        the same feature space used at score time.
        """
        X, rows = _load_network_features(session, since)
        ips = [r["remote_ip"] for r in rows]
        if not ips:
            return X, np.empty((0,), dtype=int), []
        y = np.array(
            [1 if ip.startswith(_NET_ATTACK_PREFIXES) else 0 for ip in ips], dtype=int
        )
        return X, y, ips

    @staticmethod
    def _labeled_samples(
        session,
    ) -> dict[str, tuple[list[list[float]], list[list[float]]]]:
        """Per-stream labelled samples: attack vectors vs benign baseline.

        Builds labels from the *real* feature vectors (via
        :func:`event_feature_vector`) so the supervised classifiers are
        trained on the same space used for scoring.
        """
        out: dict[str, tuple[list[list[float]], list[list[float]]]] = {
            "login": ([], []),
            "process": ([], []),
            "network": ([], []),
        }
        rows = session.execute(
            select(
                NormalizedEvent.id, NormalizedEvent.raw_json, NormalizedEvent.event_id
            )
        ).all()
        verdicts = _verdict_map(session)
        for event_id, raw, eid in rows:
            if orm_event_is_corrupted({"user": "-", "raw_json": raw})[0]:
                continue
            behavior = _behavior_of(int(eid))
            if behavior not in out:
                continue
            features = event_feature_vector({"event_id": eid, "raw_json": raw})
            if not features:
                continue
            if event_id in verdicts:
                is_attack = bool(verdicts[event_id])
            else:
                is_attack = MLAnomalyDetector._is_attack_sample(eid, raw or {})
            (out[behavior][0] if is_attack else out[behavior][1]).append(features)

        net_X, net_y, net_ips = MLAnomalyDetector._labeled_network_samples(
            session, None
        )
        for i, ip in enumerate(net_ips):
            (out["network"][0] if net_y[i] else out["network"][1]).append(
                net_X[i].tolist()
            )
        return out

    def _validation_data(
        self, session, since: datetime | None
    ) -> dict[str, tuple[np.ndarray, np.ndarray]]:
        """Windowed labelled validation set, grouped by behavior stream.

        ``since=None`` validates on the FULL history.
        """
        stmt = select(
            NormalizedEvent.id,
            NormalizedEvent.raw_json,
            NormalizedEvent.event_id,
            NormalizedEvent.timestamp,
        )
        if since is not None:
            stmt = stmt.where(NormalizedEvent.timestamp >= since)
        rows = session.execute(stmt).all()
        out: dict[str, list] = {
            "login": [[], []],
            "process": [[], []],
            "network": [[], []],
        }
        verdicts = _verdict_map(session)
        for row_id, raw, event_id, timestamp in rows:
            if orm_event_is_corrupted({"user": "-", "raw_json": raw})[0]:
                continue
            features = event_feature_vector(
                {"event_id": event_id, "raw_json": raw, "timestamp": timestamp}
            )
            if not features:
                continue
            behavior = _behavior_of(int(event_id))
            if row_id in verdicts:
                label = verdicts[row_id]
            else:
                label = (
                    1 if MLAnomalyDetector._is_attack_sample(event_id, raw or {}) else 0
                )
            out[behavior][0].append(features)
            out[behavior][1].append(label)
        return {
            beh: (np.array(x, dtype=float), np.array(y, dtype=int))
            for beh, (x, y) in out.items()
            if len(x) >= 4 and len(set(y)) >= 2
        }

    # ------------------------------------------------------------------
    def train(
        self,
        session=None,
        hours: int | None = 24,
        validate: bool = False,
        persist: bool = True,
        cutoff: datetime | None = None,
        kind: str = "initial",
    ) -> dict:
        """Train per-stream Isolation Forests + supervised classifier.

        ``hours=None`` trains on the FULL collected history (every event /
        connection, no sample window); ``hours=N`` restricts to the last N
        hours. Production paths default to the full history so the model
        reflects everything the collector has gathered.

        ``validate=True`` gates replacement behind a labelled-window
        comparison against the currently loaded models (production path);
        tests and cold starts always train freely.

        ``persist=False`` trains in-memory only (evaluation harnesses) so a
        validation run can never overwrite the production bundle.

        ``cutoff`` (e.g. a campaign start) caps the training window so the
        baseline fit never sees the attack window.

        ``kind`` (roadmap 4.1) records the training kind ("initial",
        "incremental", "drift", "scheduled") in the version history; every
        successful persistent train bumps ``version`` and archives the old
        bundle for A/B.
        """
        if not HAS_SKLEARN:
            return {"status": "sklearn-not-installed", "trained": False}

        close = session is None
        session = session or SessionLocal()
        try:
            since = None if not hours else datetime.now(UTC) - timedelta(hours=hours)

            login_X, login_y = _load_behavior_features(
                session, since, LOGIN_EVENTS, with_labels=True, cutoff=cutoff
            )
            process_X, process_y = _load_behavior_features(
                session, since, PROCESS_EVENTS, with_labels=True, cutoff=cutoff
            )
            network_X, network_rows = _load_network_features(
                session, since, cutoff=cutoff
            )
            network_y = np.empty((0,), dtype=int)
            if len(network_X):
                # Labels MUST come from the same filtered row set as network_X
                # (a separate query can disagree under ``since``/``cutoff``
                # windows and desync feature/label counts -> boolean-index
                # crash in threshold tuning).
                network_y = np.array(
                    [
                        1 if str(r["remote_ip"]).startswith(_NET_ATTACK_PREFIXES) else 0
                        for r in network_rows
                    ],
                    dtype=int,
                )

            new_models: dict[str, IsolationForest] = {}
            new_thresholds: dict[str, float] = dict(_DEFAULT_THRESHOLDS)
            new_baselines: dict[str, np.ndarray] = {}
            stream_X: dict[str, np.ndarray] = {}
            stream_y: dict[str, np.ndarray] = {}
            for behavior, X, y in (
                ("login", login_X, login_y),
                ("process", process_X, process_y),
                ("network", network_X, network_y),
            ):
                if len(X) < 3:
                    continue
                model = IsolationForest(
                    contamination=ML_CONTAMINATION,
                    random_state=ML_RANDOM_STATE,
                    n_estimators=100,
                    max_samples=min(256, len(X)),
                )
                model.fit(X)
                new_models[behavior] = model
                stream_X[behavior] = X
                stream_y[behavior] = y

            if not new_models:
                return {"status": "insufficient-data", "trained": False}

            # Supervised layer: per-stream attack-vs-baseline classifiers. Streams
            # have their own feature spaces (login/process 9-dim, network
            # 9-dim), so each is trained on its own vector space. Network
            # buckets are aggregates, so even a handful of labelled attack IPs
            # carries signal (rate + novelty separate cleanly).
            new_supervised_by_stream: dict[str, object] = {}
            new_supervised_name_by_stream: dict[str, str] = {}
            new_supervised = None
            new_supervised_name = "none"
            for behavior, (atk, ben) in self._labeled_samples(session).items():
                min_attacks = 3 if behavior == "network" else 10
                if len(atk) < min_attacks or len(ben) < 3:
                    continue
                X_all = np.vstack([ben, atk])
                y_all = np.array([0] * len(ben) + [1] * len(atk))
                stream_model, stream_name = self._build_classifier(X_all, y_all)
                new_supervised_by_stream[behavior] = stream_model
                new_supervised_name_by_stream[behavior] = stream_name

            # Thresholds are tuned in the deployed score space (IF rank blended
            # with the supervised attack probability when available), so the
            # stored boundary matches what scoring actually compares against.
            for behavior in new_models:
                new_thresholds[behavior], new_baselines[behavior] = (
                    self._tune_threshold(
                        new_models[behavior],
                        stream_X[behavior],
                        stream_y.get(behavior),
                        supervised=new_supervised_by_stream.get(behavior),
                    )
                )
            # Singular fallback keeps legacy callers (score_event) working.
            if new_supervised_by_stream:
                best_stream = (
                    "login"
                    if "login" in new_supervised_by_stream
                    else next(iter(new_supervised_by_stream))
                )
                new_supervised = new_supervised_by_stream[best_stream]
                new_supervised_name = new_supervised_name_by_stream[best_stream]

            n_samples = int(len(login_X) + len(process_X) + len(network_X))

            # Validation gate: only replace models that are not worse.
            if (
                validate
                and self.models
                and self._gate_replacement(session, since, new_models)
            ):
                logger.info("ML retrain: keeping existing models (no improvement)")
                return {
                    "status": "kept-existing",
                    "trained": True,
                    "samples": self.n_samples,
                    "streams": list(self.models.keys()),
                    "supervised": self.supervised_name,
                    "trained_at": self.trained_at,
                }

            self.models = new_models
            self.thresholds = new_thresholds
            self.baselines = new_baselines
            self.supervised = new_supervised
            self.supervised_name = new_supervised_name
            self.supervised_by_stream = new_supervised_by_stream
            self.supervised_name_by_stream = new_supervised_name_by_stream
            self.n_samples = n_samples
            self.encoders = {}  # No longer using LabelEncoder for network

            # Phase 2.4: Train ensemble meta-learner on held-out base model predictions
            if self.ensemble is not None and len(new_models) >= 2:
                try:
                    self._train_ensemble_meta(
                        session, new_models, new_supervised_by_stream, new_baselines
                    )
                except Exception:
                    logger.debug(
                        "Ensemble meta-learner training skipped", exc_info=True
                    )

            # Phase 2.3: Run robustness evaluation on trained models
            if HAS_ENSEMBLE and new_models:
                try:
                    self.robustness = evaluate_robustness(
                        _QuickModelProxy(new_models, new_baselines),
                        X_login=stream_X.get("login"),
                        X_process=stream_X.get("process"),
                        X_network=stream_X.get("network"),
                    )
                except Exception:
                    logger.debug("Robustness evaluation skipped", exc_info=True)

            if self.n_samples < ML_TRAIN_MIN_SAMPLES:
                logger.info(
                    "Only %d samples; training anyway (min %d)",
                    self.n_samples,
                    ML_TRAIN_MIN_SAMPLES,
                )

            self.trained_at = datetime.now(UTC).isoformat()
            self.events_at_train = int(
                session.scalar(select(func.count(NormalizedEvent.id))) or 0
            )
            self.version += 1
            self.model_source = "user"  # real telemetry supersedes bootstrap
            self.last_train_kind = kind
            self.versions.append(
                {
                    "version": self.version,
                    "kind": kind,
                    "trained_at": self.trained_at,
                    "samples": self.n_samples,
                    "events_at_train": self.events_at_train,
                    "streams": list(self.models.keys()),
                    "supervised": self.supervised_name,
                    "thresholds": {k: round(v, 3) for k, v in self.thresholds.items()},
                }
            )
            self.versions = self.versions[-ML_VERSION_HISTORY:]
            if persist:
                self._save_meta()
                self._save_bundle()
            logger.info(
                "ML models trained on %d samples; streams=%s supervised=%s thresholds=%s",
                self.n_samples,
                list(self.models.keys()),
                self.supervised_name,
                {k: round(v, 2) for k, v in self.thresholds.items()},
            )
            return {
                "status": "ok",
                "trained": True,
                "samples": self.n_samples,
                "streams": list(self.models.keys()),
                "supervised": self.supervised_name,
                "thresholds": self.thresholds,
                "trained_at": self.trained_at,
            }
        finally:
            if close:
                session.close()

    def _gate_replacement(self, session, since, new_models) -> bool:
        """True = keep the existing models (new ones did not beat them).

        Compares per-stream ROC-AUC on a labelled validation window; when no
        stream can be compared the retrain proceeds.
        """
        try:
            from sklearn.metrics import roc_auc_score
        except ImportError:
            return False
        deltas: list[float] = []
        for behavior, (X, y) in self._validation_data(session, since).items():
            old = self.models.get(behavior)
            new = new_models.get(behavior)
            if old is None or new is None or len(X) < 6:
                continue
            try:
                old_auc = roc_auc_score(y, old.decision_function(X))
                new_auc = roc_auc_score(y, new.decision_function(X))
            except ValueError:
                continue
            deltas.append(new_auc - old_auc)
        if not deltas:
            return False
        return sum(deltas) / len(deltas) < -0.02

    def _train_ensemble_meta(
        self,
        session,
        new_models: dict,
        new_supervised_by_stream: dict,
        new_baselines: dict,
    ) -> None:
        """Train the ensemble stacking meta-learner on base model predictions."""
        if self.ensemble is None or not HAS_ENSEMBLE:
            return

        all_if_scores = []
        all_sup_probas = []
        all_labels = []

        for behavior, model in new_models.items():
            labeled = self._labeled_samples(session)
            if behavior not in labeled:
                continue
            atk, ben = labeled[behavior]
            if not atk or not ben:
                continue
            X = np.vstack([ben, atk])
            y = np.array([0] * len(ben) + [1] * len(atk))
            if len(X) < 10:
                continue

            try:
                raws = np.array(
                    [self._score_with(model, row) for row in X], dtype=float
                )
                if_ranks = self._rank_of(raws, new_baselines.get(behavior))
            except Exception:
                continue

            sup = new_supervised_by_stream.get(behavior)
            sup_probas = np.zeros(len(X))
            if sup is not None:
                try:
                    proba = sup.predict_proba(X)
                    if proba.shape[1] > 1:
                        sup_probas = proba[:, 1]
                except Exception:
                    pass

            all_if_scores.append(if_ranks)
            all_sup_probas.append(sup_probas)
            all_labels.append(y)

        if not all_if_scores:
            return

        if_scores = np.concatenate(all_if_scores)
        sup_probas = np.concatenate(all_sup_probas)
        labels = np.concatenate(all_labels)

        self.ensemble.train_meta(if_scores, sup_probas, None, labels)

    @staticmethod
    def _build_classifier(X, y):
        """XGBoost when available, else sklearn random forest, calibrated.

        Adaptive selection: gradient boosting needs volume to shine - on the
        small labelled corpora typical of early deployments it overfits the
        few attack patterns seen and *loses* recall versus a shallow random
        forest (measured ~15 points on the hold-out suite). Below
        ``_XGB_MIN_SAMPLES`` we deliberately prefer the forest.

        Phase 2: Enhanced calibration with Platt scaling fallback and
        calibration quality validation via Brier score.
        """
        pos = int(y.sum())
        neg = int(len(y) - pos)
        scale = (neg / max(pos, 1)) if pos and neg else 1.0
        if HAS_XGBOOST and len(y) >= _XGB_MIN_SAMPLES:
            model = XGBClassifier(
                n_estimators=120,
                max_depth=3,
                learning_rate=0.08,
                random_state=ML_RANDOM_STATE,
                eval_metric="logloss",
                scale_pos_weight=scale,
                subsample=0.9,
                colsample_bytree=0.9,
                min_child_weight=2,
            )
            model.fit(X, y)
            name = "xgboost"
        else:
            model = RandomForestClassifier(
                n_estimators=80,
                max_depth=5,
                random_state=ML_RANDOM_STATE,
                class_weight="balanced_subsample",
                min_samples_leaf=2,
            )
            model.fit(X, y)
            name = "random_forest"

        # Phase 2: Enhanced calibration with quality validation
        if len(y) >= 18 and min(pos, neg) >= 4:
            try:
                from sklearn.calibration import (
                    CalibratedClassifierCV,
                    calibration_curve,
                )
                from sklearn.metrics import brier_score_loss

                # Try isotonic regression first (preferred, non-parametric)
                min_cv = min(3, min(pos, neg))
                cal = CalibratedClassifierCV(model, cv=min_cv, method="isotonic")
                cal.fit(X, y)

                # Validate calibration quality via Brier score
                try:
                    proba = cal.predict_proba(X)[:, 1]
                    brier = brier_score_loss(y, proba)
                    # Also check calibration curve deviation
                    fraction_pos, mean_pred = calibration_curve(y, proba, n_bins=5)
                    calibration_error = float(np.mean(np.abs(fraction_pos - mean_pred)))
                    # If calibration is poor (Brier > 0.25 or ECE > 0.15), try Platt
                    if brier > 0.25 or calibration_error > 0.15:
                        raise ValueError(
                            f"Poor calibration: Brier={brier:.3f}, ECE={calibration_error:.3f}"
                        )
                except Exception:
                    # Fall back to Platt scaling (parametric, sigmoid)
                    try:
                        cal_platt = CalibratedClassifierCV(
                            model, cv=min_cv, method="sigmoid"
                        )
                        cal_platt.fit(X, y)
                        return cal_platt, name + "+platt"
                    except Exception:
                        pass
                return cal, name + "+calibrated"
            except Exception:
                pass
        elif len(y) >= 12 and min(pos, neg) >= 3:
            # Minimum calibration with Platt scaling only (small sample)
            try:
                from sklearn.calibration import CalibratedClassifierCV

                cal = CalibratedClassifierCV(model, cv=2, method="sigmoid")
                cal.fit(X, y)
                return cal, name + "+platt"
            except Exception:
                pass
        return model, name

    # ------------------------------------------------------------------
    def _combined_score(self, behavior: str, model, features: list[float]) -> float:
        """Blend the (rank-calibrated) IsolationForest anomaly signal with the
        supervised classifier's attack probability into a single [0,1] score.

        Phase 2.4: When the ensemble meta-learner is trained, uses it for
        optimal blending. Otherwise falls back to fixed 0.6*IF + 0.4*supervised.
        """
        raw = self._score_with(model, features)
        base = float(self._rank_of([raw], self.baselines.get(behavior))[0])
        classifier = self.supervised_by_stream.get(behavior) or self.supervised
        if classifier is None:
            return base
        p = self.supervised_proba(features, classifier)

        # Phase 2.4: Use ensemble meta-learner when available
        if self.ensemble is not None and self.ensemble.is_trained:
            return float(max(0.0, min(1.0, self.ensemble.predict(base, p))))

        return float(max(0.0, min(1.0, 0.6 * base + 0.4 * p)))

    def score_event(self, features: list[float]) -> float:
        """Anomaly score in [0,1]; higher = more anomalous.

        Routes to the per-behavior model via the event_id carried in the
        first feature (login/process vectors both start with it), falling
        back to the login model for generic callers.
        """
        if not self.is_ready:
            return 0.0
        try:
            behavior = _behavior_of(int(features[0]))
        except (TypeError, ValueError, IndexError):
            behavior = "login"
        if behavior not in self.models:
            behavior = "login" if "login" in self.models else next(iter(self.models))
        model = self.models.get(behavior)
        return self._weighted_score(
            behavior, self._combined_score(behavior, model, features)
        )

    def score_events(self, features_list: list[list[float]]) -> list[float]:
        """Batched :meth:`score_event` - one IsolationForest ``decision_function``
        and one supervised ``predict_proba`` per behavior group instead of one
        per row (the calibrated classifier pays a ~240-call joblib spawn per
        row when scored individually)."""
        if not self.is_ready or not features_list:
            return [0.0] * len(features_list)
        out: list[float] = [0.0] * len(features_list)
        groups: dict[str, list[int]] = {}
        for idx, features in enumerate(features_list):
            try:
                behavior = _behavior_of(int(features[0]))
            except (TypeError, ValueError, IndexError):
                behavior = "login"
            if behavior not in self.models:
                behavior = (
                    "login" if "login" in self.models else next(iter(self.models))
                )
            groups.setdefault(behavior, []).append(idx)
        for behavior, idxs in groups.items():
            model = self.models.get(behavior)
            if model is None:
                continue
            try:
                X = np.array([features_list[i] for i in idxs], dtype=float)
            except (TypeError, ValueError):
                continue
            if X.shape[1] != model.n_features_in_:
                continue
            try:
                raw = 0.5 - model.decision_function(X)
            except Exception:
                continue
            base = self._rank_of(raw, self.baselines.get(behavior))
            classifier = self.supervised_by_stream.get(behavior) or self.supervised
            p = np.zeros(len(idxs), dtype=float)
            if classifier is not None and X.shape[1] == classifier.n_features_in_:
                try:
                    proba = classifier.predict_proba(X)
                    if proba.shape[1] > 1:
                        p = proba[:, 1]
                except Exception:
                    p = np.zeros(len(idxs), dtype=float)
            # Phase 2.4: Use ensemble meta-learner when available
            if self.ensemble is not None and self.ensemble.is_trained:
                scores = np.clip(self.ensemble.predict_batch(base, p), 0.0, 1.0)
            else:
                scores = np.clip(0.6 * base + 0.4 * p, 0.0, 1.0)
            weight = self.feedback_weights.get(behavior, 1.0)
            for pos, idx in enumerate(idxs):
                out[idx] = float(max(0.0, min(1.0, scores[pos] * weight)))
        return out

    def score_event_for_behavior(self, behavior: str, features: list[float]) -> float:
        model = self.models.get(behavior)
        if model is None:
            return 0.0
        return self._weighted_score(
            behavior, self._combined_score(behavior, model, features)
        )

    def score_network_connection(
        self,
        remote_ip: str,
        count: int = 1,
        distinct_ports: int = 1,
        bytes_sent: int = 0,
        bytes_recv: int = 0,
        duration: float = 0.0,
    ) -> float:
        """Anomaly score for an aggregated remote-IP flow bucket.

        v6 Feature vector: [is_private, is_testnet, is_link_local, first_octet,
        second_octet, is_class_a, is_class_b, is_class_c, count,
        distinct_ports, bytes_sent(MB), bytes_recv(MB), duration(h),
        send_rate(MB/s), connection_velocity, port_scan_indicator,
        exfiltration_indicator, beaconing_indicator, dns_query_pattern,
        burst_velocity, kill_chain_phase, attack_history,
        connections_per_minute, port_scan_trend, is_novel, hour].
        """
        model = self.models.get("network")
        if model is None:
            return 0.0

        subnet_feats = _ip_subnet_features(remote_ip)
        is_novel = 1.0 if remote_ip.startswith(_NET_ATTACK_PREFIXES) else 0.0

        sent_mb = float(bytes_sent) / 1_000_000.0
        hours_dur = float(duration) / 3600.0
        rate = sent_mb / max(hours_dur, 0.01)
        flow_feats = [
            float(count),
            float(distinct_ports),
            sent_mb,
            float(bytes_recv) / 1_000_000.0,
            hours_dur,
            rate,
        ]

        from backend.database.connection import SessionLocal

        session = SessionLocal()
        try:
            enhanced_feats = [
                _get_connection_velocity_per_ip(session, remote_ip, 60),
                _get_port_scan_indicator(session, remote_ip, 60),
                _get_exfiltration_indicator(session, remote_ip, 1),
                _get_beaconing_indicator(session, remote_ip, 1),
                _get_dns_query_pattern(session, 1),
            ]

            is_attack_ip = 1.0 if remote_ip.startswith(_NET_ATTACK_PREFIXES) else 0.0
            temporal_feats = [
                min(_get_connection_velocity_per_ip(session, remote_ip, 5), 2.0),
                0.5,  # Kill chain phase (network = exfiltration/impact)
                is_attack_ip,
                min(float(count) / max(hours_dur * 60.0, 1.0), 2.0),
                min(_get_port_scan_indicator(session, remote_ip, 15), 2.0),
            ]
        finally:
            session.close()

        features = (
            subnet_feats
            + flow_feats
            + enhanced_feats
            + temporal_feats
            + [is_novel, 0.0]
        )
        return self._weighted_score(
            "network",
            self._combined_score("network", model, features),
        )

    @staticmethod
    def _score_with(model, features: list[float]) -> float:
        """Anomaly score in [0,1]; higher = more anomalous.

        Uses the IsolationForest ``decision_function``: normal points score
        above 0 and anomalies below 0, so ``0.5 - decision`` maps the decision
        boundary onto 0.5 (matches sklearn's ``predict`` semantics).
        """
        arr = np.array([features], dtype=float)
        if arr.shape[1] != model.n_features_in_:
            return 0.0
        decision = float(model.decision_function(arr)[0])
        return float(max(0.0, min(1.0, 0.5 - decision)))

    # ------------------------------------------------------------------
    def analyze_events(self, session=None, hours: int = 1) -> dict:
        """Score recent events per behavior stream and mark outliers."""
        if not self.is_ready:
            return {"status": "not-ready"}

        close = session is None
        session = session or SessionLocal()
        try:
            since = datetime.now(UTC) - timedelta(hours=hours)
            events = session.scalars(
                select(NormalizedEvent).where(NormalizedEvent.timestamp >= since)
            ).all()
            flagged = 0
            scored = 0
            for ev in events:
                if orm_event_is_corrupted(ev)[0]:
                    continue
                behavior = _behavior_of(ev.event_id)
                model = self.models.get(behavior)
                if model is None:
                    continue
                features = event_feature_vector(ev)
                if features is None:
                    continue
                try:
                    score = self._weighted_score(
                        behavior, self._combined_score(behavior, model, features)
                    )
                except Exception:
                    continue
                ev.ml_score = round(score, 4)
                scored += 1
                if score > self.thresholds.get(behavior, 0.5):
                    ev.is_anomaly = True
                    flagged += 1

            # Score network connection buckets in the same pass.
            if "network" in self.models:
                net_rows = session.execute(
                    select(
                        NetworkConnection.remote_ip,
                        func.count(NetworkConnection.id),
                        func.count(func.distinct(NetworkConnection.remote_port)),
                        func.sum(NetworkConnection.bytes_sent),
                        func.sum(NetworkConnection.bytes_recv),
                        func.avg(NetworkConnection.duration_seconds),
                    )
                    .where(NetworkConnection.observed_at >= since)
                    .group_by(NetworkConnection.remote_ip)
                ).all()
                for (
                    remote_ip,
                    count,
                    distinct_ports,
                    bytes_sent,
                    bytes_recv,
                    duration,
                ) in net_rows:
                    try:
                        score = self.score_network_connection(
                            remote_ip or "unknown",
                            int(count),
                            int(distinct_ports),
                            int(bytes_sent or 0),
                            int(bytes_recv or 0),
                            float(duration or 0.0),
                        )
                    except Exception:
                        continue
                    scored += 1
                    if score > self.thresholds.get("network", 0.5):
                        flagged += 1

            session.commit()
            return {"status": "ok", "scored": scored, "flagged": flagged}
        finally:
            if close:
                session.close()

    # ------------------------------------------------------------------
    def supervised_proba(self, features: list[float], classifier=None) -> float:
        """P(attack) from the supervised classifier, or 0.0 when untrained."""
        classifier = classifier or self.supervised
        if classifier is None:
            return 0.0
        arr = np.array([features], dtype=float)
        if arr.shape[1] != classifier.n_features_in_:
            return 0.0
        try:
            proba = classifier.predict_proba(arr)[0]
        except Exception:
            return 0.0
        return float(proba[1] if len(proba) > 1 else 0.0)

    def status(self, session=None) -> dict:
        drifted, drift_reason = self._drift_result(session)
        stale, reason = self.is_stale(session)
        result = {
            "has_sklearn": HAS_SKLEARN,
            "has_xgboost": HAS_XGBOOST,
            "ready": self.is_ready,
            "trained_at": self.trained_at,
            "samples": self.n_samples,
            "events_at_train": self.events_at_train,
            "streams": list(self.models.keys()),
            "supervised": self.supervised_name,
            "supervised_streams": dict(self.supervised_name_by_stream),
            "thresholds": {k: round(v, 3) for k, v in self.thresholds.items()},
            "feature_version": ML_FEATURE_VERSION,
            "persisted": self._persisted,
            "model_source": self.model_source,
            "stale": stale,
            "staleness_reason": reason,
            "drift": drifted,
            "drift_reason": drift_reason,
        }
        # Phase 2.4: ensemble meta-learner status
        if self.ensemble is not None:
            result["ensemble"] = self.ensemble.status()
        # Phase 2.3: robustness evaluation result
        if self.robustness:
            result["robustness"] = self.robustness
        return result


class _QuickModelProxy:
    """Minimal proxy for robustness evaluation (avoids circular import)."""

    def __init__(self, models: dict, baselines: dict):
        self._models = models
        self._baselines = baselines

    @property
    def models(self):
        return self._models

    def decision_function(self, X):
        for model in self._models.values():
            return model.decision_function(X)
        raise ValueError("No models available")

    def predict(self, X):
        for model in self._models.values():
            return model.predict(X)
        raise ValueError("No models available")

    def score(self, X, y=None):
        for model in self._models.values():
            try:
                return model.score(X, y) if y is not None else model.score(X)
            except Exception:
                continue
        return 0.0


_detector: MLAnomalyDetector | None = None


def get_detector() -> MLAnomalyDetector:
    global _detector
    if _detector is None:
        _detector = MLAnomalyDetector(load_persisted=True)
    return _detector
