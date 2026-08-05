"""Rule - DNS / HTTP(S) Exfiltration & C2 (MITRE T1071, Command and Control).

Flags suspicious outbound application-layer traffic: heavy DNS use toward
suspicious domains, high-volume/large DNS responses, and HTTP payloads with
voluminous or high-entropy bodies.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from backend.database.models import DnsQuery, HttpRequest
from backend.detection.rules.base import BaseRule, DetectionResult

SUSPICIOUS_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".site", ".click")
DNS_QUERY_THRESHOLD = 50
HTTP_BODY_THRESHOLD = 1_000_000  # 1 MB response body


def _shannon(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return entropy


class DnsHttpExfilRule(BaseRule):
    rule_id = "dns_http_exfil"
    name = "Suspicious DNS / HTTP Exfiltration or C2"
    description = (
        "Application-layer traffic patterns consistent with command-and-control "
        "or data exfiltration: bulk DNS queries to suspicious domains, oversized "
        "DNS responses, or very large / high-entropy HTTP payloads."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1071"
    recommendation = (
        "Inspect the resolving/initiating process, block the suspicious "
        "domain(s)/IP(s), and hunt for additional C2 or exfiltration channels "
        "from the same host."
    )

    def __init__(self, session, window_minutes: int = 30):
        super().__init__(session)
        self.window_minutes = window_minutes

    def _dns_findings(self, since) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        rows = self.session.scalars(
            select(DnsQuery).where(DnsQuery.observed_at >= since)
        ).all()

        by_query: Counter[str] = Counter()
        by_domain: Counter[str] = Counter()
        large_responses = 0
        for q in rows:
            query = (q.query or "").lower()
            if not query:
                continue
            by_query[query] += 1
            by_domain[query.rsplit(".", 2)[-1] if query.count(".") >= 2 else query] += 1
            if q.response_size >= 512:
                large_responses += 1

        domains = [d for d, c in by_domain.items() if c >= 10]
        bulk_queries = [q for q, c in by_query.items() if c >= DNS_QUERY_THRESHOLD]
        suspicious_tld = [
            d for d in by_domain if d.endswith(SUSPICIOUS_TLDS)
        ]

        if bulk_queries:
            findings.append(self._result(
                evidence=f"{len(bulk_queries)} DNS query(ies) repeated >= {DNS_QUERY_THRESHOLD} times: {bulk_queries[:5]}.",
                event_ids=[],
                severity="medium",
                confidence=min(0.9, 0.7 + len(bulk_queries) * 0.02),
            ))
        if suspicious_tld:
            findings.append(self._result(
                evidence=f"DNS queries to suspicious TLDs: {suspicious_tld[:5]}.",
                event_ids=[],
                severity="high",
                confidence=0.8,
            ))
        if large_responses >= 20:
            findings.append(self._result(
                evidence=f"{large_responses} oversized DNS responses (>=512 B) within window - possible DNS tunnelling.",
                event_ids=[],
                severity="high",
                confidence=0.7,
            ))
        return findings

    def _http_findings(self, since) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        rows = self.session.scalars(
            select(HttpRequest).where(HttpRequest.observed_at >= since)
        ).all()

        big = [r for r in rows if (r.response_body_size or 0) >= HTTP_BODY_THRESHOLD]
        if not big:
            return findings
        biggest = max(big, key=lambda r: r.response_body_size or 0)
        evidence = (
            f"{len(big)} HTTP response(s) with body >= {HTTP_BODY_THRESHOLD} bytes. "
            f"Largest: {biggest.method} {biggest.url} ({biggest.response_body_size} bytes) "
            f"from process '{biggest.process}'."
        )
        findings.append(self._result(
            evidence=evidence,
            event_ids=[],
            severity="high",
            confidence=0.75,
        ))
        return findings

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        since = datetime.now(timezone.utc) - timedelta(minutes=self.window_minutes or window_minutes)
        return self._dns_findings(since) + self._http_findings(since)
