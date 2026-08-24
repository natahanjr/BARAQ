"""Rule set - Command and Control (TA0011) and Exfiltration (TA0010).

Covers proxy/C2 tooling (T1090), application-layer protocol C2 (T1071.001
via unusual ports), encrypted channels (T1573) and exfiltration to
alternative protocols (T1048.003) and web services (T1567).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.database.models import HttpRequest, NetworkConnection
from backend.detection.rules.base import BaseRule, DetectionResult

_PROXY_TOOL = re.compile(
    r"\b(?:proxychains|frp|nps|iox|venom|stowaway|chisel|socat)\b|"
    r"\bssh\b[^\n]*\b(?:-D|-L|-R)\b|"
    r"\bnetsh\b[^\n]*\bportproxy\b|"
    r"\b(?:curl|wget)\b[^\n]*\b--proxy\b|"
    r"\bsocks\b[^\n]*\b(?:proxy|tunnel)\b",
    re.IGNORECASE,
)
_UNUSUAL_PORT = re.compile(
    r"\\binvoke-WebRequest\b[^\n]*\b-Proxy\b|"
    r"\b(?:-Proxy|--proxy)\b[^\n]*\b(?:socks4|socks5|http)\b://",
    re.IGNORECASE,
)
_ENCRYPTED_C2 = re.compile(
    r"\b(?:openssl|s_client)\b[^\n]*\b(?:s_client|-connect)\b|"
    r"\b(?:ncat|nc\.exe)\b[^\n]*(?<!\w)(?:-e|-c)\b[^\n]*\b(?:cmd|powershell|bash|sh)\b",
    re.IGNORECASE,
)
_EXFIL_ALT = re.compile(
    r"\bftp\b[^\n]*(?<!\w)(?:-s\b|put\b|mput\b)|"
    r"\bcurl\b[^\n]*(?<!\w)(?:-T\b|--upload-file\b|--data-binary\b)\b[^\n]*\b(?:ftp://|sftp://)|"
    r"\b(?:scp|sftp)\b[^\n]*\b(?:-r\b)?[^\n]*:",
    re.IGNORECASE,
)
_EXFIL_WEB = re.compile(
    r"\bcurl\b[^\n]*\b(?:-X\s+POST|-d\b|--data)\b[^\n]*\b(?:pastebin|transfer\.sh|file\.io|0x0\.st|"
    r"webhook\.site|pipedream|gofile\.io|catbox\.moe)",
    re.IGNORECASE,
)

#: Ports that are common for legitimate traffic; anything else outbound to
#: an external host from a non-browser process warrants a look.
_COMMON_PORTS = {21, 22, 25, 53, 80, 110, 123, 143, 443, 445, 853, 993, 995, 3389, 5985, 5986}
_BROWSER_PROCS = ("chrome.exe", "msedge.exe", "msedgewebview2.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe")
#: Processes that legitimately open many outbound connections to arbitrary
#: external hosts/ports (residential proxy agents, VPN/relay daemons, P2P).
#: Extendable at runtime with BARAQ_TRUSTED_PROCESSES (comma separated).
_TRUSTED_AGENT_PROCS = ("infatica_agent.exe",)


def _trusted_agent_procs() -> tuple[str, ...]:
    import os

    extra = os.environ.get("BARAQ_TRUSTED_PROCESSES", "")
    items = [p.strip().lower() for p in extra.split(",") if p.strip()]
    return _TRUSTED_AGENT_PROCS + tuple(items)


def _is_external(ip: str) -> bool:
    import ipaddress

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


class ProxyToolRule(BaseRule):
    rule_id = "proxy_tool"
    name = "Proxy / Tunnel Tooling"
    description = (
        "A network proxy or tunnelling tool (proxychains, chisel, frp, ssh "
        "dynamic forwarding, netsh portproxy) was invoked - creating covert "
        "C2 or pivoting channels."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1090"
    recommendation = (
        "Kill the tunnelling process, block the destination, review the "
        "established port-forwards, and audit for additional pivot hosts."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _PROXY_TOOL.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Proxy/tunnel tooling by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class UnusualPortRule(BaseRule):
    rule_id = "unusual_port"
    name = "C2 over Unusual Port"
    description = (
        "A non-browser process maintained an outbound connection to an "
        "external host on a non-standard port - consistent with C2 or "
        "exfiltration over an unusual channel."
    )
    severity = "medium"
    confidence = 0.55
    mitre_id = "T1571"
    recommendation = (
        "Identify the initiating process, block the external host, and "
        "hunt for additional connections to the same infrastructure."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(NetworkConnection).where(
                NetworkConnection.observed_at >= since,
                NetworkConnection.state == "ESTABLISHED",
                *self._org_conds(NetworkConnection),
            )
        ).all()
        seen: set[tuple] = set()
        for conn in rows:
            if not _is_external(conn.remote_ip or ""):
                continue
            if conn.remote_port in _COMMON_PORTS:
                continue
            proc = (conn.process or "").lower()
            if any(b in proc for b in _BROWSER_PROCS):
                continue
            if any(t in proc for t in _trusted_agent_procs()):
                continue
            key = (conn.process, conn.remote_ip, conn.remote_port)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                self._result(
                    evidence=(
                        f"Process '{conn.process or '?'}' (pid {conn.pid}) connected to "
                        f"external host {conn.remote_ip} on unusual port "
                        f"{conn.remote_port}."
                    ),
                    event_ids=[],
                )
            )
        return findings


class EncryptedChannelRule(BaseRule):
    rule_id = "encrypted_channel"
    name = "Encrypted Covert Channel"
    description = (
        "OpenSSL/ncat-style encrypted reverse shells or covert channels "
        "were set up - evading detection while tunnelling command traffic."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1573"
    recommendation = (
        "Terminate the channel, block the peer, and review the processes "
        "that initiated the connection."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _ENCRYPTED_C2.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Encrypted covert channel by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class ExfilAlternativeProtocolRule(BaseRule):
    rule_id = "exfil_alternative_protocol"
    name = "Exfiltration over Alternative Protocol"
    description = (
        "Data was transferred out via FTP/SFTP/SCP - exfiltration over a "
        "non-standard channel that bypasses HTTP(S) egress inspection."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1048.003"
    recommendation = (
        "Block the destination, review the transferred data volume, and "
        "hunt for matching data on the receiving host."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _EXFIL_ALT.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Alternative-protocol exfiltration by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class ExfilWebServiceRule(BaseRule):
    rule_id = "exfil_web_service"
    name = "Exfiltration to Web Service"
    description = (
        "Data was POSTed to a public file-sharing or webhook service - "
        "exfiltration to a legitimate-looking third-party host."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1567"
    recommendation = (
        "Block the destination domain, recover the uploaded data where "
        "possible, and review the exfiltrating process and file paths."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _EXFIL_WEB.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Web-service exfiltration by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )

        rows = self.session.scalars(
            select(HttpRequest).where(
                HttpRequest.observed_at >= since,
                HttpRequest.method.in_(["POST", "PUT"]),
                *self._org_conds(HttpRequest),
            )
        ).all()
        for req in rows:
            host = (req.host or "").lower()
            if not any(
                marker in host
                for marker in ("pastebin", "transfer.sh", "file.io", "0x0.st", "webhook.site", "pipedream", "catbox.moe")
            ):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"HTTP {req.method} to {host} ({req.url}) with "
                        f"{req.request_body_size} bytes by '{req.process or '?'}' - "
                        f"possible exfiltration to a file-sharing service."
                    ),
                    event_ids=[],
                )
            )
        return findings