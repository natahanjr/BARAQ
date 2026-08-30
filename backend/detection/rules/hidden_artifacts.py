"""Rule - Artifact hiding (MITRE T1564).

Flags NTFS alternate-data-stream usage and hidden-attribute toggling in
command lines - techniques used to conceal payloads and data.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from backend.detection.rules.base import BaseRule, DetectionResult

# file.ext:stream (a stream after a file name) - requires a real path
# (drive letter or \ or / separator, contiguous last segment) so Python
# "module:function" references like "backend.main:app" in command lines
# are not misclassified as ADS.
_ADS = re.compile(
    r"(?:[A-Za-z]:)?[\\/](?:[\w .\-]+[\\/])*[\w\-]+\.\w{1,5}:[\w$]+",
    re.IGNORECASE,
)
# attrib +h / +s / +r used to hide a target.
_ATTRIB_HIDE = re.compile(r"\battrib(?:\s+[+\-/][rsh])+\s+\S+", re.IGNORECASE)


class HiddenArtifactsRule(BaseRule):
    rule_id = "hidden_artifacts"
    name = "Artifact Hiding Activity"
    description = (
        "Command lines indicate file hiding: NTFS alternate data streams "
        "(file:stream) or attrib-set hidden attributes."
    )
    severity = "medium"
    confidence = 0.7
    mitre_id = "T1564"
    recommendation = (
        "Extract and inspect the stream payload, scan for additional streams "
        "and hidden files, and review the initiating process chain."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            indicators: list[str] = []
            for match in _ADS.finditer(cmdline):
                indicators.append(f"ADS reference '{match.group(0)}'")
            if _ATTRIB_HIDE.search(cmdline):
                indicators.append("attribute hiding (attrib +h)")

            if indicators:
                findings.append(
                    self._result(
                        evidence=(
                            f"Artifact-hiding activity by '{user}' ({label}): "
                            f"{'; '.join(indicators)}. Command line: {cmdline[:300]}"
                        ),
                        event_ids=[],
                    )
                )
        return findings
