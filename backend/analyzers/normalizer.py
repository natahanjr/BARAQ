"""Event Processing Engine - normalizes raw collector records.

Converts a heterogeneous raw record:

    {source: "eventlog", event_id: 4625, message: "...", raw: {...}}

into the canonical SentinelSOC event:

    Event ID: 4625 | Category: Authentication | User: Admin | Risk: Medium | Timestamp: ...

Also parses structured facts (source IPs, logon types, accounts, binaries)
out of messages so detection rules can reason over real data.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

logger = logging.getLogger("sentinel.analyzers.normalizer")

# Numeric risk scale (0-100) per risk band; enables risk-based prioritization.
RISK_BAND_SCORES = {"Low": 15, "Medium": 45, "High": 75}

# ---------------------------------------------------------------------------
# Event metadata tables
# ---------------------------------------------------------------------------
EVENT_META: dict[int, dict[str, str]] = {
    4624: {"category": "Authentication", "risk": "Low", "severity": "info"},
    4625: {"category": "Authentication", "risk": "Medium", "severity": "low"},
    4634: {"category": "Authentication", "risk": "Low", "severity": "info"},
    4647: {"category": "Authentication", "risk": "Low", "severity": "info"},
    4648: {"category": "Authentication", "risk": "Medium", "severity": "low"},
    4672: {"category": "Privilege", "risk": "Medium", "severity": "medium"},
    4688: {"category": "Process", "risk": "Low", "severity": "info"},
    4720: {"category": "Account Management", "risk": "High", "severity": "medium"},
    4722: {"category": "Account Management", "risk": "Medium", "severity": "medium"},
    4724: {"category": "Account Management", "risk": "High", "severity": "high"},
    4725: {"category": "Account Management", "risk": "Medium", "severity": "medium"},
    4726: {"category": "Account Management", "risk": "High", "severity": "high"},
    4728: {"category": "Account Management", "risk": "High", "severity": "high"},
    4732: {"category": "Account Management", "risk": "High", "severity": "high"},
    4734: {"category": "Account Management", "risk": "Medium", "severity": "medium"},
    4740: {"category": "Authentication", "risk": "Medium", "severity": "medium"},
    4768: {"category": "Authentication", "risk": "Low", "severity": "info"},
    4769: {"category": "Authentication", "risk": "Low", "severity": "info"},
    4771: {"category": "Authentication", "risk": "Medium", "severity": "medium"},
    4698: {"category": "Persistence", "risk": "High", "severity": "medium"},
    4702: {"category": "Persistence", "risk": "High", "severity": "high"},
    7036: {"category": "Service", "risk": "Low", "severity": "info"},
    7040: {"category": "Service", "risk": "Medium", "severity": "medium"},
    7045: {"category": "Service", "risk": "High", "severity": "medium"},
    4103: {"category": "PowerShell", "risk": "Medium", "severity": "medium"},
    4104: {"category": "PowerShell", "risk": "Medium", "severity": "medium"},
    400: {"category": "PowerShell", "risk": "Low", "severity": "info"},
    403: {"category": "PowerShell", "risk": "Medium", "severity": "medium"},
}

MESSAGE_PATTERNS = {
    "account_name": re.compile(r"Account Name:\s+(\S+)", re.IGNORECASE),
    "new_account": re.compile(r"(?:New Account|Account Name):\s+(\S+)", re.IGNORECASE),
    "source_ip": re.compile(r"Source Network Address:\s+(\S+)", re.IGNORECASE),
    "client_ip": re.compile(r"Client Address:\s+(\S+)", re.IGNORECASE),
    "logon_type": re.compile(r"Logon Type:\s+(\d+)", re.IGNORECASE),
    "new_process": re.compile(r"New Process Name:\s+(\S+)", re.IGNORECASE),
    "service_name": re.compile(r"Service Name:\s+(\S+)", re.IGNORECASE),
    "service_file": re.compile(r"Service File Name:\s+(\S+)", re.IGNORECASE),
    "task_name": re.compile(r"Task Name:\s+(\S+)", re.IGNORECASE),
    "group_name": re.compile(r"Group:\s+([\w\s-]+?)\.\s+Subject", re.IGNORECASE),
}


class Normalizer:
    """Converts raw records into normalized event dicts ready for the DB."""

    def __init__(self, hostname: str | None = None):
        import socket
        self.hostname = hostname or socket.gethostname()

    # ------------------------------------------------------------------
    @staticmethod
    def _safe_ts(raw_ts: Any) -> datetime:
        if isinstance(raw_ts, datetime):
            return raw_ts
        if isinstance(raw_ts, (int, float)):
            return datetime.fromtimestamp(raw_ts).astimezone()
        if isinstance(raw_ts, str):
            try:
                return datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now().astimezone()

    @staticmethod
    def _extract_facts(record: dict) -> dict:
        message = record.get("message", "")
        raw = record.get("raw") or {}
        facts = dict(raw)
        for key, pattern in MESSAGE_PATTERNS.items():
            if key not in facts:
                m = pattern.search(message)
                if m:
                    facts[key] = m.group(1).rstrip(".,;: ")
        return facts

    # ------------------------------------------------------------------
    def normalize(self, record: dict) -> dict:
        """Normalize one raw record into a canonical event dict."""
        event_id = int(record.get("event_id") or 0)
        meta = EVENT_META.get(event_id, {"category": "Other", "risk": "Low", "severity": "info"})
        facts = self._extract_facts(record)

        # Resolve the user: prefer structured, fall back to message parse.
        user = record.get("user") or facts.get("account_name") or facts.get("new_account") or "-"
        if user in (None, "", "-") and facts.get("new_account"):
            user = facts["new_account"]

        timestamp = self._safe_ts(record.get("timestamp"))

        # Compose a readable one-line message.
        message = record.get("message") or self._compose_message(event_id, facts, meta)

        risk_score = RISK_BAND_SCORES.get(meta["risk"], 15)
        risk_score = min(100, risk_score + self._risk_modifiers(event_id, facts))

        return {
            "event_id": event_id,
            "category": meta["category"],
            "risk": meta["risk"],
            "risk_score": float(risk_score),
            "severity": meta["severity"],
            "source": record.get("source", "unknown"),
            "user": str(user)[:128],
            "host": record.get("raw", {}).get("computer") or self.hostname,
            "message": str(message)[:8192],
            "timestamp": timestamp,
            "raw_json": {
                "facts": {k: v for k, v in facts.items() if isinstance(v, (str, int, float, bool))},
                "channel": record.get("channel", ""),
                "record_number": record.get("raw", {}).get("record_number"),
            },
        }

    @staticmethod
    def _risk_modifiers(event_id: int, facts: dict) -> float:
        """Additional risk points for aggravating factors in the event."""
        bonus = 0.0
        if event_id == 4625 and str(facts.get("sub_status", "")) in ("0xC000006D", "0xC0000234"):
            bonus += 10  # locked-account / bad-password attempts
        if event_id in (4720, 4732) and "admin" in str(facts.get("new_account", "")).lower():
            bonus += 10  # admin-named account creation
        if event_id == 4732 and facts.get("group_sid") == "S-1-5-32-544":
            bonus += 15  # Administrators group membership
        if event_id == 7045 and re.search(r"public|temp|downloads", str(facts.get("image_path", "")), re.IGNORECASE):
            bonus += 10  # service binary dropped in user-writable path
        if event_id == 4104 and facts.get("has_encoded"):
            bonus += 15  # encoded PowerShell
        if event_id == 4104 and facts.get("has_download"):
            bonus += 10  # download-execute PowerShell
        if event_id == 4698 and re.search(r"public|temp|downloads", str(facts.get("image_path", "")), re.IGNORECASE):
            bonus += 10
        return bonus

    # ------------------------------------------------------------------
    @staticmethod
    def _compose_message(event_id: int, facts: dict, meta: dict) -> str:
        label = EVENT_META.get(event_id, {}).get("category", "Event")
        bits = [f"Event {event_id} ({label})"]
        if facts.get("new_account"):
            bits.append(f"account={facts['new_account']}")
        if facts.get("account_name"):
            bits.append(f"account={facts['account_name']}")
        if facts.get("source_ip"):
            bits.append(f"source_ip={facts['source_ip']}")
        if facts.get("new_process"):
            bits.append(f"process={facts['new_process']}")
        if facts.get("service_name"):
            bits.append(f"service={facts['service_name']}")
        return " | ".join(bits)

    # ------------------------------------------------------------------
    def normalize_batch(self, records: list[dict]) -> list[dict]:
        return [self.normalize(r) for r in records]
