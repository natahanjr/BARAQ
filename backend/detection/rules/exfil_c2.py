"""Rules - exfiltration & C2: cloud-sync uploads (T1567.002), webhook-based
C2 (T1102.001) and DNS tunneling (T1071.004).

Cloud sync and webhook C2 are command-line / DNS detections; DNS tunneling
uses Sysmon 22 / snoop DNS telemetry (query length, label structure, volume).
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from backend.database.models import DnsQuery
from backend.detection.rules.base import BaseRule, DetectionResult


class CloudSyncExfilRule(BaseRule):
    rule_id = "cloud_sync_exfil"
    name = "Exfiltration to Cloud Storage"
    description = (
        "Cloud storage upload tooling (rclone, aws s3, azcopy, gsutil, "
        "s3cmd) copying or syncing data - attacker moving stolen files to "
        "OneDrive, Google Drive, S3 or similar."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1567.002"
    recommendation = (
        "Block the cloud endpoint, review the scope of data exfiltrated, "
        "rotate credentials, and restrict cloud-storage access from endpoint "
        "accounts via policy."
    )

    _CMDLINE = re.compile(
        r"\brclone\b[^\n]*?\b(?:copy|move|sync)\b|"
        r"\baws\b[^\n]*\bs3\b[^\n]*?\b(?:cp|mv|sync)\b|"
        r"\bazcopy\b[^\n]*?\bcopy\b|"
        r"\bgsutil\b[^\n]*?\bcp\b|"
        r"\bs3cmd\b[^\n]*?\b(?:put|sync|mv)\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Cloud storage upload by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class WebhookC2Rule(BaseRule):
    rule_id = "webhook_c2"
    name = "Webhook Dead-Drop C2"
    description = (
        "Traffic to legitimate webhook endpoints (Slack, Teams, Discord, "
        "Telegram) from non-browser processes - command-and-control or "
        "exfiltration hidden inside normal SaaS webhook use."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1102.001"
    recommendation = (
        "Investigate the process contacting the webhook, block the endpoint "
        "at the egress proxy, and review the SaaS workspace audit logs for "
        "the channel used."
    )

    _WEBHOOK_HOSTS = re.compile(
        r"hooks\.slack\.com|(?:[a-z0-9-]+\.)*webhook\.office\.com|"
        r"webhookb2|api\.telegram\.org|discord(?:app)?\.com/api/webhooks",
        re.IGNORECASE,
    )
    _CMDLINE = re.compile(
        r"https://hooks\.slack\.com/services/|"
        r"(?:[a-z0-9-]+\.)*webhook\.office\.com/webhookb2/|"
        r"discord(?:app)?\.com/api/webhooks/\d+|"
        r"api\.telegram\.org/bot\d+:[A-Za-z0-9_-]+/sendMessage",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Webhook endpoint reference by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )

        for q in self.session.scalars(
            select(DnsQuery).where(
                DnsQuery.observed_at >= since,
                *self._org_conds(DnsQuery),
            )
        ).all():
            if not self._WEBHOOK_HOSTS.search(q.query or ""):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"DNS resolution of webhook endpoint '{q.query}' by "
                        f"process '{q.process}' (pid {q.pid})."
                    ),
                    event_ids=[],
                )
            )
        return findings


class DnsTunnelingRule(BaseRule):
    rule_id = "dns_tunneling"
    name = "DNS Tunneling"
    description = (
        "DNS traffic shaped like a tunnel: very long labels, unusual label "
        "structure, oversized TXT-style responses, or high unique-query "
        "volume to one base domain from a single process - encoded data "
        "flowing over DNS."
    )
    severity = "medium"
    confidence = 0.6
    mitre_id = "T1071.004"
    recommendation = (
        "Block the tunneling domain at the resolver, hunt for the client "
        "process, and review the DNS logs for the full tunnel window to bound "
        "the data exfiltrated."
    )

    _MAX_LABEL_LEN = 30
    _MAX_QUERY_LEN = 90
    _MIN_UNIQUE_QUERIES = 20
    _LARGE_RESPONSE = 400

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(DnsQuery).where(
                DnsQuery.observed_at >= since,
                *self._org_conds(DnsQuery),
            )
        ).all()
        if not rows:
            return findings

        long_label: list[str] = []
        long_query: list[str] = []
        big_responses = 0
        by_base: Counter[tuple[str, str, int]] = Counter()
        for q in rows:
            query = (q.query or "").lower().rstrip(".")
            if not query:
                continue
            labels = query.split(".")
            if len(labels) >= 3 and max(len(x) for x in labels[:-2]) > self._MAX_LABEL_LEN:
                long_label.append(query)
            if len(query) > self._MAX_QUERY_LEN:
                long_query.append(query)
            if (q.response_size or 0) >= self._LARGE_RESPONSE:
                big_responses += 1
            base = ".".join(labels[-2:]) if len(labels) >= 2 else query
            by_base[(q.process or "", q.pid, base)] += 1

        loud = [k for k, c in by_base.items() if c >= self._MIN_UNIQUE_QUERIES]
        if long_label:
            findings.append(self._result(
                evidence=(
                    f"DNS queries with tunnel-style long labels: "
                    f"{', '.join(long_label[:5])}."
                ),
                event_ids=[],
                confidence=min(0.9, self.confidence + 0.15),
            ))
        if long_query:
            findings.append(self._result(
                evidence=(
                    f"DNS queries longer than {self._MAX_QUERY_LEN} chars: "
                    f"{', '.join(long_query[:5])}."
                ),
                event_ids=[],
            ))
        if big_responses >= 5:
            findings.append(self._result(
                evidence=(
                    f"{big_responses} oversized DNS responses (>= "
                    f"{self._LARGE_RESPONSE} B) - possible TXT-payload "
                    f"tunneling."
                ),
                event_ids=[],
            ))
        for process, pid, base in loud:
            findings.append(self._result(
                evidence=(
                    f"Process '{process}' (pid {pid}) issued "
                    f"{by_base[(process, pid, base)]} unique queries to base "
                    f"domain '{base}' - DNS tunneling volume."
                ),
                event_ids=[],
                severity="high",
                confidence=min(0.9, self.confidence + 0.2),
            ))
        return findings
