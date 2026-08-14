"""Rule set - Initial Access techniques (TA0001).

Covers spearphishing attachment/link delivery (T1566.001/.002), drive-by
compromise from malicious web content (T1189), and exploitation of
internet-facing services (T1190).
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.database.models import EmailMessage, HttpRequest, NetworkConnection
from backend.detection.rules.base import BaseRule, DetectionResult

BAD_ATTACHMENTS = {
    ".exe", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".lnk",
    ".docm", ".xlsm", ".xlsb", ".pptm", ".iso", ".hta", ".jar",
}
SHORTENER_HOSTS = re.compile(
    r"(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|"
    r"ow\.ly|buff\.ly|tiny\.cc|v\.gd)",
    re.IGNORECASE,
)
SUSPICIOUS_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".site", ".click", ".info", ".zip")
BROWSER_PROCESSES = ("chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe")

#: High-value service ports adversaries probe / exploit on public hosts.
HIGH_VALUE_PORTS = {
    22, 445, 1433, 3306, 3389, 5432, 5985, 5986, 6379, 7001, 8000, 8080,
    8443, 9000, 9200, 27017,
}

_IP_ONLY_URL = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", re.IGNORECASE)


def _is_external(ip: str) -> bool:
    """True when the address is routable (not private/loopback/link-local)."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if addr.exploded.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
        return True
    if addr.is_loopback or addr.is_link_local or addr.is_private:
        return False
    if addr.is_multicast or addr.is_reserved:
        return False
    return True


class SpearphishingAttachmentRule(BaseRule):
    rule_id = "spearphishing_attachment"
    name = "Spearphishing Attachment Delivery"
    description = (
        "An email carried an executable, script or macro-enabled document "
        "attachment - the classic vector for initial access via phishing."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1566.001"
    recommendation = (
        "Quarantine the message, block the sender domain, disable macros for "
        "external content, and alert recipients to inspect their hosts for "
        "follow-on execution."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        findings: list[DetectionResult] = []
        rows = self.session.scalars(
            select(EmailMessage).where(
                EmailMessage.received_at >= since,
                *self._org_conds(EmailMessage),
            )
        ).all()
        for email in rows:
            attachments = (email.attachment_types or "").lower()
            hits = [ext for ext in BAD_ATTACHMENTS if ext in attachments]
            if not hits:
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Email from '{email.sender}' to '{email.recipient}' carried "
                        f"dangerous attachment type(s): {', '.join(hits)}. "
                        f"Subject: '{email.subject}'."
                    ),
                    event_ids=[],
                )
            )
        return findings


class SpearphishingLinkRule(BaseRule):
    rule_id = "spearphishing_link"
    name = "Spearphishing Link Delivery"
    description = (
        "An email contained a URL shortener or raw-IP link commonly used to "
        "obscure phishing destinations from inspection."
    )
    severity = "medium"
    confidence = 0.7
    mitre_id = "T1566.002"
    recommendation = (
        "Reputate the expanded link target, block the shortener domain if "
        "unsolicited, and warn recipients before they click."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        findings: list[DetectionResult] = []
        rows = self.session.scalars(
            select(EmailMessage).where(
                EmailMessage.received_at >= since,
                *self._org_conds(EmailMessage),
            )
        ).all()
        for email in rows:
            text = f"{email.subject} {email.body}"
            indicators = []
            if SHORTENER_HOSTS.search(text):
                indicators.append("URL shortener")
            if _IP_ONLY_URL.search(text):
                indicators.append("raw-IP link")
            if not indicators:
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Email from '{email.sender}' to '{email.recipient}' contains "
                        f"{', '.join(indicators)}. Subject: '{email.subject}'."
                    ),
                    event_ids=[],
                )
            )
        return findings


class DriveByCompromiseRule(BaseRule):
    rule_id = "drive_by_compromise"
    name = "Drive-by Compromise Traffic"
    description = (
        "A browser made requests to a raw-IP URL or a suspicious TLD - a "
        "pattern consistent with exploit-kit or malicious-ad delivery."
    )
    severity = "medium"
    confidence = 0.65
    mitre_id = "T1189"
    recommendation = (
        "Block the destination host, review the referring page, and scan the "
        "host for recent downloads or injected processes."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        findings: list[DetectionResult] = []
        rows = self.session.scalars(
            select(HttpRequest).where(
                HttpRequest.observed_at >= since,
                *self._org_conds(HttpRequest),
            )
        ).all()
        for req in rows:
            process = (req.process or "").lower()
            if not any(b in process for b in BROWSER_PROCESSES):
                continue
            indicators = []
            if _IP_ONLY_URL.search(req.url or ""):
                indicators.append("raw-IP URL")
            host = (req.host or "").lower()
            if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
                indicators.append(f"suspicious TLD '{host.rsplit('.', 1)[-1]}'")
            if not indicators:
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Browser process '{req.process}' requested {req.method} "
                        f"{req.url} ({', '.join(indicators)})."
                    ),
                    event_ids=[],
                )
            )
        return findings


class ExternalServiceExploitRule(BaseRule):
    rule_id = "external_service_exploit"
    name = "External Access to Exposed Service"
    description = (
        "An external address connected to a high-value service port on this "
        "host - a precursor to exploitation of a public-facing application."
    )
    severity = "high"
    confidence = 0.6
    mitre_id = "T1190"
    recommendation = (
        "Verify the service is intentionally exposed, review authentication "
        "failures and exploit attempts on that port, and restrict access via "
        "firewall rules or a VPN."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        findings: list[DetectionResult] = []
        rows = self.session.scalars(
            select(NetworkConnection).where(
                NetworkConnection.observed_at >= since,
                NetworkConnection.state == "ESTABLISHED",
                *self._org_conds(NetworkConnection),
            )
        ).all()
        for conn in rows:
            if not _is_external(conn.remote_ip or ""):
                continue
            if conn.local_port not in HIGH_VALUE_PORTS:
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"External host {conn.remote_ip} established a connection to "
                        f"local port {conn.local_port} (process '{conn.process or '?'}', "
                        f"pid {conn.pid})."
                    ),
                    event_ids=[],
                )
            )
        return findings