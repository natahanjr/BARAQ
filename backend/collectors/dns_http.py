"""DNS & HTTP(S) monitoring collector (live only).

Reads real DNS query activity from the Sysmon operational channel
(Event 22 = DNS query) and, when a local HTTP monitor log is configured
(``SENTINEL_HTTP_LOG`` env var, JSON-lines), HTTP request metadata.

Pure-live: when Sysmon is unavailable / pywin32 missing, the DNS part is a
no-op and no simulation is generated.
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from backend.collectors.base import BaseCollector
from backend.collectors.eventlog import WindowsEventLogCollector
from backend.config import SYSMON_CHANNELS

logger = logging.getLogger("sentinel.collectors.dns_http")

HTTP_LOG = os.environ.get("SENTINEL_HTTP_LOG", "")
MAX_RECORDS_PER_CYCLE = 500


class DnsHttpCollector(BaseCollector):
    """Collects DNS queries (Sysmon E22) and HTTP request metadata."""

    name = "dns_http"

    def __init__(self):
        super().__init__()
        self._eventlog = WindowsEventLogCollector(
            channels=SYSMON_CHANNELS, extra_event_ids={22, 3}
        )
        self._http_log = Path(HTTP_LOG) if HTTP_LOG else None
        self._http_seen: set[tuple] = set()

    def enabled(self) -> bool:
        return self._eventlog.enabled() or bool(self._http_log)

    # ------------------------------------------------------------------
    def _parse_dns(self, rec: dict) -> dict | None:
        message = rec.get("message", "") or ""
        raw = rec.get("raw") or {}
        query = raw.get("query") or ""
        if not query:
            m = re.search(r"QueryName:\s*(\S+)", message)
            query = m.group(1) if m else ""
        if not query:
            return None
        if query in ("_wpad", "*") or query.endswith(".in-addr.arpa"):
            return None
        response = raw.get("response", "") or ""
        return {
            "source": "dns",
            "process": raw.get("process", rec.get("user", "")),
            "pid": int(raw.get("pid", 0) or 0),
            "query": query[:512],
            "response": response[:512],
            "response_size": int(raw.get("response_size", 0) or 0),
            "timestamp": rec.get("timestamp"),
        }

    def _collect_dns(self) -> list[dict]:
        out: list[dict] = []
        for rec in self._eventlog.collect():
            if rec.get("event_id") != 22:
                continue
            parsed = self._parse_dns(rec)
            if parsed:
                out.append(parsed)
        return out

    # ------------------------------------------------------------------
    def _collect_http(self) -> list[dict]:
        if not self._http_log or not self._http_log.is_file():
            return []
        out: list[dict] = []
        try:
            lines = self._http_log.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        for line in lines[-MAX_RECORDS_PER_CYCLE:]:
            try:
                data = json.loads(line)
            except (ValueError, TypeError):
                continue
            key = (data.get("url"), data.get("method"), data.get("timestamp", ""))
            if key in self._http_seen:
                continue
            self._http_seen.add(key)
            url = str(data.get("url", ""))
            if not url:
                continue
            host = data.get("host", "")
            if not host:
                try:
                    host = url.split("/")[2]
                except IndexError:
                    host = ""
            out.append({
                "source": "http",
                "process": str(data.get("process", "")),
                "pid": int(data.get("pid", 0) or 0),
                "method": str(data.get("method", "GET")),
                "url": url[:1024],
                "host": host[:256],
                "status_code": int(data.get("status_code", 0) or 0),
                "request_body_size": int(data.get("request_body_size", 0) or 0),
                "response_body_size": int(data.get("response_body_size", 0) or 0),
                "timestamp": data.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            })
        return out

    # ------------------------------------------------------------------
    def collect(self) -> list[dict]:
        records: list[dict] = []
        if self._eventlog.enabled():
            records.extend(self._collect_dns())
        records.extend(self._collect_http())
        self.logger.debug("Collected %d DNS/HTTP records", len(records))
        return records
