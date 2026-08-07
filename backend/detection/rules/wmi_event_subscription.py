"""Rule - WMI permanent event subscription (MITRE T1546.003).

Flags command lines that create WMI event subscriptions
(EventFilter + EventConsumer + FilterToConsumerBinding) to run a payload
when a defined event fires - a stealthy persistence technique.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from backend.detection.rules.base import BaseRule, DetectionResult

_WMI_SUB = re.compile(
    r"wmic\b[^\n]*?\\root\\(?:subscription)"
    r"|wmic\b[^\n]*?(CommandLineEventConsumer|ActiveScriptEventConsumer|__EventFilter|_FilterToConsumerBinding)"
    r"|(CommandLineEventConsumer|ActiveScriptEventConsumer|_FilterToConsumerBinding|__EventFilter|__InstanceCreationEvent)"
    r"|Set-WmiInstance[^\n]*?(Class\s+[Ii]d\s+EventFilter|__EventConsumer)"
    r"|-CommandLineEventConsumer|ActiveScriptEventConsumer",
    re.IGNORECASE,
)


class WmiEventSubscriptionRule(BaseRule):
    rule_id = "wmi_event_subscription"
    name = "WMI Event Subscription Created"
    description = (
        "A command created a permanent WMI event subscription, a persistence "
        "mechanism that executes a payload when a system event occurs."
    )
    severity = "critical"
    confidence = 0.85
    mitre_id = "T1546.003"
    recommendation = (
        "Enumerate and remove the subscription under the root\\subscription "
        "namespace (Get-WmiObject -Namespace root\\subscription), delete any "
        "dropped payload and harden WMI namespace ACLs."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            if not _WMI_SUB.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"WMI event subscription activity by '{user}' ({label}): "
                        f"{cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings