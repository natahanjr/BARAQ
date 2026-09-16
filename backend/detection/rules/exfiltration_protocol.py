"""T1048 - Exfiltration Over Alternative Protocol.

Detects data exfiltration via DNS tunneling, ICMP tunneling,
or other alternative protocols that bypass normal HTTP/S channels.
"""

from __future__ import annotations

import re

from backend.detection.rules.base import BaseRule, DetectionResult

DNS_TUNNEL_PATTERNS = [
    (r"nslookup.*-type=TXT.*\.", "DNS TXT record query (potential tunnel)"),
    (r"nslookup.*-type=NULL", "DNS NULL record query"),
    (r"nslookup.*-type=CNAME", "DNS CNAME record query"),
    (r"dig\s+.*\+short", "Dig query for DNS tunneling"),
    (r"dnscat", "DNS cat tunnel tool"),
    (r"iodine", "Iodine DNS tunnel tool"),
    (r"dnscmd", "DNS server command (potential tunnel)"),
    (r"powershell.*Resolve-DnsName.*-Type TXT", "PowerShell DNS TXT query"),
    (r"powershell.*[System.Net.Dns]::GetHostAddresses", "PowerShell DNS resolution"),
]

ICMP_TUNNEL_PATTERNS = [
    (r"ping.*-l\s+\d{4,}", "Large ICMP payload (potential tunnel)"),
    (r"ping.*-s\s+\d{4,}", "Large ICMP size (potential tunnel)"),
    (r"ptunnel", "ICMP tunnel tool"),
    (r"icmptx", "ICMP tunnel tool"),
]

EXFIL_TOOL_PATTERNS = [
    (r"ncat.*-w.*-e", "Ncat reverse shell"),
    (r"netcat.*-e", "Netcat reverse shell"),
    (r"socat", "Socat connection"),
    (r"plink", "PuTTY link (tunnel)"),
    (r"ssh.*-L\s+\d+:", "SSH local port forwarding"),
    (r"ssh.*-R\s+\d+:", "SSH remote port forwarding"),
    (r"ssh.*-D\s+\d+", "SSH dynamic port forwarding (SOCKS proxy)"),
    (r"stunnel", "Stunnel SSL tunnel"),
    (r"chisel", "Chisel tunnel tool"),
    (r"frp", "Fast reverse proxy"),
    (r"ngrok", "Ngrok tunnel"),
    (r"localtunnel", "Local tunnel"),
]

HIGH_VOLUME_PATTERNS = [
    (r"powershell.*invoke-webrequest.*-outfile", "Web request with file output"),
    (r"powershell.*start-bitstransfer", "BITS transfer"),
    (r"curl.*-o\s+\S+\s+http", "Curl file download"),
    (r"wget.*http.*-O", "Wget file download"),
]


class ExfiltrationProtocolRule(BaseRule):
    rule_id = "BARAQ-EXFIL-002"
    title = "Exfiltration Over Alternative Protocol"
    description = "Detects data exfiltration via DNS tunneling, ICMP, or alternative protocols"
    mitre_id = "T1048"
    severity = "high"
    confidence = 0.75

    def evaluate(self, event: dict) -> DetectionResult | None:
        if event.get("source") != "process":
            return None
        cmdline = (event.get("command_line") or "").lower()
        if not cmdline:
            return None

        evidence = []

        for pattern, desc in DNS_TUNNEL_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        for pattern, desc in ICMP_TUNNEL_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        for pattern, desc in EXFIL_TOOL_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        if not evidence:
            return None

        severity = "critical" if len(evidence) >= 2 else self.severity
        confidence = min(0.95, self.confidence + 0.05 * len(evidence))

        return DetectionResult(
            confidence=confidence,
            severity=severity,
            mitre_id=self.mitre_id,
            evidence=evidence[:5],
            recommendation="Investigate for data exfiltration via alternative protocol",
        )
