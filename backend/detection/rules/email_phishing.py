"""Rule - Email Phishing Detection (MITRE T1566, Initial Access).

Heuristic scoring of collected email metadata: suspicious sender domains,
impersonation language, urgency, and malicious attachment types.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.database.models import EmailMessage
from backend.detection.rules.base import BaseRule, DetectionResult

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".site", ".click", ".info"}
URGENT_WORDS = [
    "urgent", "account locked", "password reset", "verify", "unusual sign-in",
    "invoice", "payment", "suspended", "deactivated", "action required",
    "security alert", "w-2", "wire transfer", "gift card",
]
BAD_ATTACHMENTS = {".exe", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".lnk", ".docm", ".xlsm", ".iso"}


class EmailPhishingRule(BaseRule):
    rule_id = "email_phishing"
    name = "Phishing / Malicious Email Detected"
    description = (
        "An ingested email message scored high on phishing indicators such as "
        "a suspicious sender domain, urgent/credential-themed language, or a "
        "malicious attachment type."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1566"
    recommendation = (
        "Block the sender domain at the gateway, quarantine the message, and "
        "alert any recipients to review their mailbox for follow-on activity."
    )

    def __init__(self, session, threshold: float = 2.0, window_minutes: int = 120):
        super().__init__(session)
        self.threshold = threshold
        self.window_minutes = window_minutes

    def _score(self, email: EmailMessage) -> tuple[float, list[str]]:
        score = 0.0
        reasons: list[str] = []
        text = f"{email.subject} {email.body}".lower()
        sender = (email.sender or "").lower()

        if any(tld in sender.rsplit("@", 1)[-1] for tld in SUSPICIOUS_TLDS):
            score += 1.5
            reasons.append("suspicious sender TLD")
        if sender.count("@") != 1:
            score += 1.0
            reasons.append("malformed sender")
        hits = [w for w in URGENT_WORDS if w in text]
        if hits:
            score += min(2.0, 0.5 * len(hits))
            reasons.append("urgent/credential language")
        attachments = (email.attachment_types or "").lower()
        for ext in BAD_ATTACHMENTS:
            if ext in attachments:
                score += 1.0
                reasons.append(f"malicious attachment type {ext}")
        if "http://" in text.lower() or "https://" in text.lower():
            score += 0.25
        return score, reasons

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        since = datetime.now(timezone.utc) - timedelta(minutes=self.window_minutes or window_minutes)
        findings: list[DetectionResult] = []

        emails = self.session.scalars(
            select(EmailMessage).where(EmailMessage.received_at >= since)
        ).all()

        for email in emails:
            score, reasons = self._score(email)
            if score < self.threshold:
                continue
            evidence = (
                f"Email from '{email.sender}' to '{email.recipient}' scored "
                f"{score:.1f} (threshold {self.threshold}); indicators: {', '.join(reasons)}. "
                f"Subject: '{email.subject}'. Attachments: {email.attachment_types or 'none'}."
            )
            findings.append(
                self._result(
                    evidence=evidence,
                    event_ids=[],
                    severity="critical" if score >= 4.0 else self.severity,
                    confidence=min(0.98, self.confidence + score * 0.04),
                )
            )
        return findings
