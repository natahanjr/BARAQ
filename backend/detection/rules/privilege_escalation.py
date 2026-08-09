"""Rule 3 - Privilege Escalation (MITRE T1068).

Detects new administrator accounts (4720 + 4732 to Administrators) and
suspicious privileged group membership changes (4728/4732 to admin SIDs).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

ADMIN_GROUP_SIDS = {"S-1-5-32-544", "S-1-5-32-551", "S-1-5-32-548"}
PRIV_GROUP_KEYWORDS = ("Administrators", "Domain Admins", "Enterprise Admins")


class PrivilegeEscalationRule(BaseRule):
    rule_id = "privilege_escalation"
    name = "Suspicious Privilege Escalation"
    description = (
        "New account creation or group membership changes that grant "
        "administrative privileges."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1068"
    recommendation = (
        "Verify the change request, disable or remove the unauthorized account, "
        "reset associated credentials and review all administrative group membership."
    )

    @staticmethod
    def _is_admin_group(facts: dict) -> bool:
        group = facts.get("group", "")
        group_sid = facts.get("group_sid", "")
        return group_sid in ADMIN_GROUP_SIDS or any(
            kw.lower() in group.lower() for kw in PRIV_GROUP_KEYWORDS
        )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        covered_event_ids: set[int] = set()
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        # 1) New account creation followed by addition to a privileged group.
        new_accounts = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id == 4720,
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all()

        for creation in new_accounts:
            facts = (creation.raw_json or {}).get("facts", {}) if creation.raw_json else {}
            account = facts.get("new_account") or facts.get("account_name") or creation.user

            evidence_bits = [f"account '{account}' created by '{creation.user}'"]
            ev_ids = [creation.id]

            admin_additions = self.session.scalars(
                select(NormalizedEvent).where(
                    NormalizedEvent.event_id.in_([4732, 4728]),
                    NormalizedEvent.timestamp >= since,
                    *self._org_conds(NormalizedEvent),
                )
            ).all()
            for add in admin_additions:
                g = (add.raw_json or {}).get("facts", {}) if add.raw_json else {}
                member = g.get("new_account", "") or g.get("member", "")
                if self._is_admin_group(g) and (member.lower() == account.lower() or not member):
                    evidence_bits.append(f"added to '{g.get('group', 'privileged group')}' via Event {add.event_id}")
                    ev_ids.append(add.id)
                    covered_event_ids.add(add.id)

            if len(ev_ids) > 1:
                covered_event_ids.add(creation.id)
                findings.append(
                    self._result(
                        evidence="; ".join(evidence_bits),
                        event_ids=ev_ids,
                    )
                )

        # 2) Direct membership changes in privileged groups not yet covered.
        for add in self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id.in_([4732, 4728]),
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all():
            if add.id in covered_event_ids:
                continue
            facts = (add.raw_json or {}).get("facts", {}) if add.raw_json else {}
            if not self._is_admin_group(facts):
                continue
            member = facts.get("new_account", "?")
            findings.append(
                self._result(
                    evidence=(
                        f"User '{member}' added to privileged group "
                        f"'{facts.get('group', '?')}' (Event {add.event_id}) by '{add.user}'."
                    ),
                    event_ids=[add.id],
                )
            )
        return findings
