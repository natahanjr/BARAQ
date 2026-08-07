"""Rule - Administrative account manipulation (MITRE T1098).

Flags high-impact changes to admin-named accounts: password reset attempts,
account deletion and enable/disable toggling of privileged accounts.
Complementary to the privilege-escalation rule (account creation and
group membership); focuses on existing privileged accounts being tampered.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

_ADMIN_NAME = re.compile(r"(^|[\s_.-])(admin|administrator|sysadmin|root)([\s_.-]|$)", re.IGNORECASE)


def _is_admin_named(account: str) -> bool:
    return bool(_ADMIN_NAME.search(account or ""))


class AccountTamperingRule(BaseRule):
    rule_id = "account_tampering"
    name = "Administrative Account Tampering"
    description = (
        "An administrative account was the target of a password reset, "
        "deletion or enable/disable change - possible backdoor or sabotage."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1098"
    recommendation = (
        "Verify the change with the account owner, reset the credentials if "
        "tampered, re-enable/restore the account and audit who performed the change."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id.in_([4724, 4726, 4738, 4725, 4722]),
                NormalizedEvent.timestamp >= since,
            )
        ).all()

        for event in rows:
            facts = (event.raw_json or {}).get("facts", {}) if event.raw_json else {}
            target = (
                facts.get("target_account_name")
                or facts.get("deleted_account")
                or facts.get("new_account")
                or facts.get("account_name")
                or event.user
            )

            if event.event_id == 4724:  # password reset attempt
                if not _is_admin_named(target):
                    continue
                evidence = (
                    f"Password reset attempted for administrative account '{target}' "
                    f"by '{event.user}'."
                )
            elif event.event_id == 4726:  # account deleted
                if not _is_admin_named(target):
                    continue
                evidence = f"Administrative account '{target}' was deleted by '{event.user}'."
            elif event.event_id in (4722, 4725):  # enabled / disabled
                if not _is_admin_named(target):
                    continue
                action = "enabled" if event.event_id == 4722 else "disabled"
                evidence = f"Administrative account '{target}' was {action} by '{event.user}'."
            elif not _is_admin_named(target):
                continue
            else:  # 4738 account modified
                message = event.message or ""
                if "user account control" not in message.lower() and "privileges" not in message.lower():
                    continue
                evidence = f"Administrative account '{target}' was modified by '{event.user}'."

            findings.append(
                self._result(evidence=evidence, event_ids=[event.id])
            )
        return findings