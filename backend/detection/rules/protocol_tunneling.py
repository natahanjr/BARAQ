"""T1572 - Protocol Tunneling.

Detects tunneling protocols used for C2 or exfiltration:
SSH tunnels, HTTP tunnels, DNS tunneling tools, VPN over
non-standard ports, and encapsulated protocols.
"""

from __future__ import annotations

import re

from backend.detection.rules.base import BaseRule, DetectionResult

TUNNEL_TECHNIQUES = [
    (r"ssh.*-f.*-N", "SSH tunnel (background, no command)"),
    (r"ssh.*-L\s+\d+:.*:\d+", "SSH local port forward"),
    (r"ssh.*-R\s+\d+:.*:\d+", "SSH remote port forward"),
    (r"ssh.*-D\s+\d+", "SSH dynamic SOCKS proxy"),
    (r"ssh.*-w\s+\d+:\d+", "SSH tun device"),
    (r"plink.*-L\s+\d+:.*:\d+", "PuTTY local port forward"),
    (r"plink.*-R\s+\d+:.*:\d+", "PuTTY remote port forward"),
    (r"plink.*-D\s+\d+", "PuTTY dynamic SOCKS proxy"),
    (r"chisel", "Chisel tunnel tool"),
    (r"frpc", "Fast reverse proxy client"),
    (r"frps", "Fast reverse proxy server"),
    (r"ngrok", "Ngrok tunnel"),
    (r"localtunnel", "Local tunnel"),
    (r"bore", "Bore tunnel tool"),
    (r"cloudflared", "Cloudflare tunnel"),
    (r"rathole", "Rathole tunnel"),
    (r"zrok", "zrok tunnel"),
    (r"netsh\s+interface\s+portproxy", "Windows port proxy"),
    (r"netsh.*interface.*portproxy.*add", "Adding port proxy"),
    (r"ssh.*-o.*ProxyCommand", "SSH with proxy command"),
    (r"ssh.*-o.*StrictHostKeyChecking=no", "SSH with disabled host key check"),
    (r"ssh.*-o.*UserKnownHostsFile=/dev/null", "SSH ignoring known hosts"),
    (r"socat.*tcp:", "Socat TCP tunnel"),
    (r"ncat.*-e", "Ncat reverse shell"),
    (r"ncat.*--ssl", "Ncat SSL tunnel"),
    (r"hping3", "hping3 packet crafting"),
    (r"reGeorg", "ReGeorg SOCKS proxy"),
    (r"tunneln", "Tunnel tool"),
    (r" earthworm", "EarthWorm tunneling tool"),
    (r"lcx", "LCX tunneling tool"),
    (r"TERMITE", "Termite proxy agent"),
]


class ProtocolTunnelingRule(BaseRule):
    rule_id = "BARAQ-C2-005"
    title = "Protocol Tunneling Detected"
    description = "Detects protocol tunneling techniques used for C2 or data exfiltration"
    mitre_id = "T1572"
    severity = "high"
    confidence = 0.80

    def evaluate(self, event: dict) -> DetectionResult | None:
        if event.get("source") != "process":
            return None
        cmdline = (event.get("command_line") or "").lower()
        if not cmdline:
            return None

        evidence = []
        for pattern, desc in TUNNEL_TECHNIQUES:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        if not evidence:
            return None

        severity = "critical" if len(evidence) >= 3 else self.severity

        return DetectionResult(
            confidence=min(0.95, self.confidence + 0.03 * len(evidence)),
            severity=severity,
            mitre_id=self.mitre_id,
            evidence=evidence[:5],
            recommendation="Investigate tunneling for unauthorized C2 or exfiltration",
        )
