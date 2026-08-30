"""Rules - Active Directory reconnaissance and policy abuse.

BloodHound/SharpHound collection (MITRE T1087 Account Discovery) and Group
Policy modification abuse (MITRE T1484.001, GPO deployment of malicious
configuration / SharpGPOAbuse).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult


def _facts(event) -> dict:
    return (event.raw_json or {}).get("facts", {}) if event.raw_json else {}


class BloodHoundReconRule(BaseRule):
    rule_id = "bloodhound_recon"
    name = "BloodHound / AD Recon Collection"
    description = (
        "Active Directory enumeration tooling (SharpHound, bloodhound-python, "
        "Invoke-BloodHound) - the attacker is mapping users, groups, trusts "
        "and attack paths before lateral movement."
    )
    severity = "medium"
    confidence = 0.7
    mitre_id = "T1087"
    recommendation = (
        "Investigate the origin host and account, review LDAP query volume on "
        "domain controllers, and restrict access to AD enumeration tooling."
    )

    _CMDLINE = re.compile(
        r"\bsharphound(?:\.exe|\.dll)?\b|"
        r"\bbloodhound-python\b|\binvoke-bloodhound\b|"
        r"\b--collectionmethod\b|\b-collectionmethod\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"BloodHound collection tooling by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class GpoAbuseRule(BaseRule):
    rule_id = "gpo_abuse"
    name = "Group Policy Modification / Abuse"
    description = (
        "A Group Policy Object was modified (Security 5136 on CN=Policies) or "
        "GPO tooling executed (SharpGPOAbuse, Set-GPLink, Invoke-GPOUpdate) - "
        "the attacker can push scripts, admin memberships and scheduled tasks "
        "domain-wide."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1484.001"
    recommendation = (
        "Audit who holds GPO-edit rights, restore the modified GPO from "
        "backup, inspect linked scripts/scheduled tasks, and review the "
        "privileged group membership that allowed the change."
    )

    _CMDLINE = re.compile(
        r"\bsharpgpoabuse\b|"
        r"\b(?:new|set|remove)-gplink\b|\bimport-gpo\b|\binvoke-gpoupdate\b|"
        r"\bntlmrelayx\b[^\n]*?--gpo\b|\bgpotarget\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"GPO abuse tooling by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )

        for event in self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id == 5136,
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all():
            facts = _facts(event)
            obj = facts.get("object_dn") or event.message or ""
            if "Policies" not in obj and "CN=Policies" not in event.message:
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Directory object under CN=Policies (GPO) modified by "
                        f"'{event.user}': {obj[:200]}"
                    ),
                    event_ids=[event.id],
                )
            )
        return findings
