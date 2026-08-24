"""Rules - Active Directory Kerberos attacks (MITRE T1558, T1550, T1003).

Kerberoasting / AS-REP Roasting / Golden & Silver Tickets (T1558.x),
Pass-the-Hash / Pass-the-Ticket (T1550.x) and DCSync replication-credential
dumping (T1003.006).

Each rule uses command-line indicators (4688 / 4104 / process snapshots) plus
the corresponding Windows Security log signals (4768 TGT requests, 4769 TGS
requests with ticket encryption type, 4662 directory-service replication
access, 4624 logon events with authentication package).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

_ADMIN_NAME = re.compile(r"(^|[\s_.-])(admin|administrator|sysadmin|root|krbtgt)([\s_.-]|$)", re.IGNORECASE)
_MACHINE_ACCOUNT = re.compile(r"\$$")
_SPN = re.compile(r"/")
_RC4 = "0x17"
_AES256 = "0x12"
_AES128 = "0x11"
_NO_PREAUTH_OPTIONS = ("0x40810000", "0x40800000")
_REPLICATION_MASKS = ("0x100", "0x200", "0x300", "0x101", "0x201", "0x301")


def _facts(event) -> dict:
    return (event.raw_json or {}).get("facts", {}) if event.raw_json else {}


def _events(session, since, event_ids, org_conds) -> list:
    return session.scalars(
        select(NormalizedEvent).where(
            NormalizedEvent.event_id.in_(event_ids),
            NormalizedEvent.timestamp >= since,
            *org_conds,
        )
    ).all()


class KerberoastingRule(BaseRule):
    rule_id = "kerberoasting"
    name = "Kerberoasting"
    description = (
        "Kerberos service tickets requested with RC4 (0x17) encryption for "
        "SPN accounts by a non-computer user, or Kerberoasting tooling "
        "(Rubeus, GetUserSPNs, Invoke-Kerberoast) - the attacker can crack "
        "the service account password offline."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1558.003"
    recommendation = (
        "Rotate the affected service-account password, enforce AES-256 "
        "Kerberos (disable RC4), prefer group-managed service accounts, and "
        "audit who requested the tickets."
    )

    _CMDLINE = re.compile(
        r"\brubeus(?:\.exe)?\s+kerberoast\b|"
        r"\bgetuserspns\b|\bgetuser\.spns\b|\bget\-user\s+spns\b|"
        r"\binvoke-kerberoast\b|\bkerberoast\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Kerberoasting tooling by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )

        for event in _events(self.session, since, [4769], self._org_conds(NormalizedEvent)):
            facts = _facts(event)
            req = facts.get("account_name") or event.user
            service = facts.get("service_name") or ""
            if facts.get("ticket_encryption_type") != _RC4:
                continue
            if _MACHINE_ACCOUNT.search(req):
                continue
            if not _SPN.search(service):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"RC4 (0x17) TGS request by '{req}' for service "
                        f"'{service}' - consistent with Kerberoasting."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings


class AsRepRoastingRule(BaseRule):
    rule_id = "as_rep_roasting"
    name = "AS-REP Roasting"
    description = (
        "AS-REQ without pre-authentication (Ticket Options 0x40810000) or "
        "AS-REP roasting tooling (Rubeus asreproast, GetNPUsers) - the "
        "account can have its TGT response cracked offline."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1558.004"
    recommendation = (
        "Disable 'Do not require pre-authentication' on the affected account, "
        "rotate its password, and enforce pre-authentication for all accounts."
    )

    _CMDLINE = re.compile(
        r"\brubeus(?:\.exe)?\s+asreproast\b|"
        r"\bgetnpusers\b|\bgetnpusers\.py\b|"
        r"\basreproast\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"AS-REP roasting tooling by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )

        for event in _events(self.session, since, [4768], self._org_conds(NormalizedEvent)):
            facts = _facts(event)
            options = facts.get("ticket_options") or ""
            account = facts.get("target_account_name") or event.user
            if not any(options.upper().startswith(opt.upper()) for opt in _NO_PREAUTH_OPTIONS):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"TGT request without pre-authentication for '{account}' "
                        f"(ticket options {options}) - AS-REP roasting candidate."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings


class DCSyncRule(BaseRule):
    rule_id = "dcsync"
    name = "DCSync Replication Attack"
    description = (
        "Directory replication (DRSUAPI) access requested by a non-DC "
        "account, or DCSync tooling (secretsdump, mimikatz lsadump::dcsync) "
        "- an attempt to sync password hashes for the whole domain."
    )
    severity = "critical"
    confidence = 0.85
    mitre_id = "T1003.006"
    recommendation = (
        "Treat as critical domain compromise: reset privileged and computer "
        "account credentials, rotate krbtgt twice with replication waits, and "
        "restrict replication rights to authorized DC accounts."
    )

    _CMDLINE = re.compile(
        r"\bsecretsdump\b|\bsecretsdump\.py\b|"
        r"lsadump::dcsync\b|\bdcsync\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"DCSync tooling by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )

        for event in _events(self.session, since, [4662], self._org_conds(NormalizedEvent)):
            facts = _facts(event)
            mask = (facts.get("access_mask") or "").lower()
            account = facts.get("account_name") or event.user
            if mask not in tuple(m.lower() for m in _REPLICATION_MASKS):
                continue
            if _MACHINE_ACCOUNT.search(account):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Account '{account}' requested directory replication "
                        f"access (access mask {facts.get('access_mask')}) - "
                        f"DCSync indicator."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings


class GoldenTicketRule(BaseRule):
    rule_id = "golden_ticket"
    name = "Golden Ticket Forged TGT"
    description = (
        "A TGT was requested for the krbtgt account (never legitimate) or "
        "Golden Ticket tooling (Rubeus golden, mimikatz kerberos::golden) "
        "was executed - the krbtgt hash is compromised."
    )
    severity = "critical"
    confidence = 0.85
    mitre_id = "T1558.001"
    recommendation = (
        "Reset the krbtgt account password twice (with replication wait "
        "between resets), invalidate all tickets, and treat the domain as "
        "compromised."
    )

    _CMDLINE = re.compile(
        r"\brubeus(?:\.exe)?\s+golden\b|"
        r"kerberos::golden\b|\btgt::krbtgt\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Golden Ticket tooling by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )

        for event in _events(self.session, since, [4768], self._org_conds(NormalizedEvent)):
            facts = _facts(event)
            account = (facts.get("target_account_name") or event.user).lower()
            if account != "krbtgt":
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"TGT requested for the krbtgt account by "
                        f"'{facts.get('account_name') or event.user}' - Golden "
                        f"Ticket indicator."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings


class SilverTicketRule(BaseRule):
    rule_id = "silver_ticket"
    name = "Silver Ticket Forged TGS"
    description = (
        "An administrative account requested an RC4 (0x17) TGS for an SPN "
        "service, or Silver Ticket tooling (Rubeus silver) executed - a "
        "forged service ticket using a compromised service account hash."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1558.002"
    recommendation = (
        "Rotate the forged service account password, enforce AES-only "
        "Kerberos encryption, and audit RC4 TGS usage."
    )

    _CMDLINE = re.compile(
        r"\brubeus(?:\.exe)?\s+silver\b|"
        r"\bkerberos::silver\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Silver Ticket tooling by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )

        for event in _events(self.session, since, [4769], self._org_conds(NormalizedEvent)):
            facts = _facts(event)
            req = facts.get("account_name") or event.user
            service = facts.get("service_name") or ""
            if facts.get("ticket_encryption_type") != _RC4:
                continue
            if not _ADMIN_NAME.search(req) or not _SPN.search(service):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"RC4 (0x17) TGS request by privileged account '{req}' "
                        f"for service '{service}' - Silver Ticket indicator."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings


class PassTheHashRule(BaseRule):
    rule_id = "pass_the_hash"
    name = "Pass-the-Hash"
    description = (
        "NTLM network logons using privileged accounts from remote hosts, or "
        "pass-the-hash tooling (sekurlsa::pth, psexec -hashes) - an attacker "
        "reusing a captured NT hash."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1550.002"
    recommendation = (
        "Enable Credential Guard, enforce Kerberos over NTLM where possible, "
        "restrict local admin usage, rotate affected credentials, and segment "
        "the network."
    )

    _CMDLINE = re.compile(
        r"sekurlsa::pth\b|"
        r"\bpsexec(?:\.exe|\.py)?\b[^\n]*?-hashes\b|"
        r"\b--pw-nt-hash\b|\b-pw-nt-hash\b|"
        r"\bxfreerdp\b[^\n]*?/pth:|\bevil-winrm\b[^\n]*?-H\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Pass-the-hash tooling by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )

        for event in _events(self.session, since, [4624], self._org_conds(NormalizedEvent)):
            facts = _facts(event)
            if str(facts.get("logon_type") or "") != "3":
                continue
            package = (facts.get("authentication_package") or "").lower()
            if "ntlm" not in package:
                continue
            account = facts.get("account_name") or event.user
            if not _ADMIN_NAME.search(account) or _MACHINE_ACCOUNT.search(account):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"NTLM network logon (type 3) as privileged account "
                        f"'{account}' from '{facts.get('source_ip', '?')}' - "
                        f"pass-the-hash indicator."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings


class PassTheTicketRule(BaseRule):
    rule_id = "pass_the_ticket"
    name = "Pass-the-Ticket"
    description = (
        "Kerberos logons of type 9/10 from a single user, or pass-the-ticket "
        "tooling (kerberos::ptt, Rubeus ptt) - an injected stolen Kerberos "
        "ticket being used for lateral movement."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1550.003"
    recommendation = (
        "Rotate the impersonated account's credentials, enforce AES Kerberos "
        "encryption, enable Credential Guard, and review the originating "
        "session for ticket-theft tools."
    )

    _CMDLINE = re.compile(
        r"kerberos::ptt\b|"
        r"\brubeus(?:\.exe)?\s+ptt\b|"
        r"\basktgt\b[^\n]*?/ptt\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Pass-the-ticket tooling by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )

        for event in _events(self.session, since, [4624], self._org_conds(NormalizedEvent)):
            facts = _facts(event)
            if str(facts.get("logon_type") or "") not in ("9", "10"):
                continue
            package = (facts.get("authentication_package") or "").lower()
            if "kerberos" not in package:
                continue
            account = facts.get("account_name") or event.user
            findings.append(
                self._result(
                    evidence=(
                        f"Kerberos logon (type {facts.get('logon_type')}) as "
                        f"'{account}' from '{facts.get('source_ip', '?')}' - "
                        f"pass-the-ticket indicator."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings
