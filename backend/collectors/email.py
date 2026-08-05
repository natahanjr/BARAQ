"""Email / phishing telemetry collector (live only).

Ingests message metadata from a configured directory of exported messages
(``SENTINEL_MAIL_DIR`` env var, default empty). Supported files: .eml,
.msg and .json mail exports. The collector parses sender, recipient,
subject, body snippet, attachments and source IP so the phishing rule can
score real messages.

Pure-live: when no directory is configured the collector is disabled and
returns no records.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from backend.collectors.base import BaseCollector
from backend.config import MAIL_INGEST_DIR, MAIL_INGEST_EXTENSIONS

logger = logging.getLogger("sentinel.collectors.email")

ATTACHMENT_RE = re.compile(
    r"attachment|\.exe|\.scr|\.js|\.vbs|\.ps1|\.bat|\.cmd|\.rar|\.7z|\.zip|\.docm|\.xlsm|\.lnk",
    re.IGNORECASE,
)


class EmailCollector(BaseCollector):
    """Parses exported messages into normalized email records."""

    name = "email"

    def __init__(self, ingest_dir: str | None = None):
        super().__init__()
        raw_dir = ingest_dir if ingest_dir is not None else MAIL_INGEST_DIR
        self.ingest_dir = Path(raw_dir) if raw_dir else None
        self._seen: set[str] = set()

    def enabled(self) -> bool:
        return bool(self.ingest_dir) and self.ingest_dir.is_dir()

    # ------------------------------------------------------------------
    @staticmethod
    def _header(headers, key: str, default: str = "") -> str:
        return str(headers.get(key, default) or default)

    def _parse_eml(self, path: Path) -> dict | None:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        headers: dict = {}
        body_parts: list[str] = []
        in_body = False
        for line in raw.splitlines()[:400]:
            if not in_body and line == "":
                in_body = True
                continue
            if not in_body:
                if ":" in line:
                    key, _, value = line.partition(":")
                    headers[key.strip().lower()] = value.strip()
            else:
                body_parts.append(line)
        attachments = [a for a in ATTACHMENT_RE.findall(raw) if a != "attachment"]
        return {
            "sender": self._header(headers, "from"),
            "recipient": self._header(headers, "to"),
            "subject": self._header(headers, "subject"),
            "body": " ".join(body_parts)[:4000],
            "attachment_types": ",".join(sorted(set(attachments)))[:512],
            "ip_address": self._header(headers, "x-originating-ip").strip("[]"),
            "timestamp": self._header(headers, "date"),
        }

    def _parse_json(self, path: Path) -> dict | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        return {
            "sender": str(data.get("sender", "")),
            "recipient": str(data.get("recipient", "")),
            "subject": str(data.get("subject", "")),
            "body": str(data.get("body", ""))[:4000],
            "attachment_types": str(data.get("attachment_types", ""))[:512],
            "ip_address": str(data.get("ip_address", "")),
            "timestamp": str(data.get("received_at", "")),
        }

    def _parse(self, path: Path) -> dict | None:
        if path.suffix.lower() == ".json":
            data = self._parse_json(path)
        else:
            data = self._parse_eml(path)
        if not data:
            return None
        if not data["sender"] and not data["subject"]:
            return None
        return {**data, "source": "email"}

    # ------------------------------------------------------------------
    def collect(self) -> list[dict]:
        if not self.enabled():
            return []
        out: list[dict] = []
        try:
            files = [
                p
                for p in self.ingest_dir.rglob("*")
                if p.is_file() and p.suffix.lower() in MAIL_INGEST_EXTENSIONS
            ]
        except OSError:
            return []
        for path in files:
            if str(path) in self._seen:
                continue
            parsed = self._parse(path)
            if parsed:
                self._seen.add(str(path))
                out.append(parsed)
        self.logger.debug("Collected %d email message(s)", len(out))
        return out
