"""Rule - System binary proxy execution / LOLBins (MITRE T1218).

Flags abuse of trusted Windows binaries to proxy malicious execution:
rundll32 with javascript:/mshtml, mshta with remote or script content,
regsvr32 /s /i:http (squiblydoo), certutil -urlcache/-decode,
bitsadmin /transfer, installutil/regasm/regsvc, cmstp, pcalua and
hh.exe with remote content.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from backend.detection.rules.base import BaseRule, DetectionResult

_LOLBIN_FLAGS = (
    (r"\brundll32(?:\.exe)?\b[^\n]*?(javascript:|vbscript:|https?://|\.hta\b)", "rundll32 script/remote execution"),
    (r"\bmshta(?:\.exe)?\b[^\n]*?(javascript:|vbscript:|https?://|\.hta\b|ftp://)", "mshta executing script or remote .hta"),
    (r"\bregsvr32(?:\.exe)?\b[^\n]*?/s\b[^\n]*?(https?://|scrobj|\.sct\b)", "regsvr32 squiblydoo (scrobj/remote .sct)"),
    (r"\bregsvr32(?:\.exe)?\b[^\n]*?/i:[^\s]*?https?://", "regsvr32 remote scriptlet"),
    (r"\bcertutil(?:\.exe)?\b[^\n]*?(-urlcache|-decode|/decode|-ping|-split)", "certutil download/decode abuse"),
    (r"\bbitsadmin(?:\.exe)?\b[^\n]*?/transfer", "bitsadmin transfer (BITS job)"),
    (r"\binstallutil(?:\.exe)?\b", "installutil execution"),
    (r"\bregasm(?:\.exe)?\b", "regasm execution"),
    (r"\bregsvc(?:\.exe)?\b", "regsvc execution"),
    (r"\bcmstp(?:\.exe)?\b", "cmstp execution"),
    (r"\bpcalua(?:\.exe)?\b", "pcalua execution"),
    (r"\bhh\.exe\b[^\n]*?https?://", "hh.exe opening remote CHM"),
    (r"\bmsiexec(?:\.exe)?\b[^\n]*?/i\b[^\n]*?https?://", "msiexec installing remote MSI"),
    (r"\bw(?:script|cscript)\.exe\b[^\n]*?(\\temp\\|\\users\\public|\\appdata|\\downloads)", "script host executing from user-writable path"),
)

_SUSPICIOUS_DIRS = re.compile(r"\\Temp\\|\\Users\\Public\\|\\AppData\\|\\Downloads\\", re.IGNORECASE)


class LolBinExecutionRule(BaseRule):
    rule_id = "lolbin_execution"
    name = "System Binary Proxy Execution"
    description = (
        "A trusted Windows binary (rundll32, mshta, regsvr32, certutil, "
        "bitsadmin, installutil, ...) was invoked in a way that is commonly "
        "abused to proxy malicious code and bypass allow-lists."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1218"
    recommendation = (
        "Investigate the invoked content, block the remote host, restrict "
        "these binaries (Software Restriction Policy / WDAC) and review the "
        "parent process chain."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            flags = [flag for pattern, flag in _LOLBIN_FLAGS if re.search(pattern, cmdline, re.IGNORECASE)]
            if not flags:
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"LOLBin abuse by '{user}' ({label}): {', '.join(flags)}. "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings