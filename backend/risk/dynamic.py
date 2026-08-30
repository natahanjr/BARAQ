"""Dynamic Risk Scoring (Roadmap Phase 2 - Feature 6).

Adjusts the base (hybrid) risk score with additive deltas from live
context and evidence, then maps the result onto the roadmap risk scale:

    risk = base_risk
    developer_tool        -40   git / opencode / vscode / python / node / npm / docker
    signed_binary         -10   all observed processes are known system/trusted tooling
    known_user             -5   the account has prior activity history in the platform
    suspicious_network    +30   external IPs or C2-flavoured ports in the evidence
    persistence_detected  +25   service/scheduled-task/registry-run-key events
    credential_access     +35   logon-rights escalation / lsass access / logon bursts

Risk scale:  0-20 LOW · 21-40 MEDIUM · 41-70 HIGH · 71-100 CRITICAL

The final risk level drives the alert severity so the displayed severity and
risk never diverge (roadmap P0 - severity consistency).
"""

from __future__ import annotations

import logging
import re

from sqlalchemy import select

logger = logging.getLogger("baraq.risk.dynamic")

DEV_TOOL_PENALTY = 40
SIGNED_BINARY_PENALTY = 10
KNOWN_USER_PENALTY = 5
SUSPICIOUS_NETWORK_BONUS = 30
PERSISTENCE_BONUS = 25
CREDENTIAL_ACCESS_BONUS = 35

LEVEL_LOW = 21
LEVEL_MEDIUM = 41
LEVEL_HIGH = 71

#: Event IDs whose presence means persistence activity (service install,
#: scheduled task creation, sysmon registry-run-key writes).
PERSISTENCE_EVENT_IDS = {"7045", "4697", "4698", "4699", "12", "13", "14"}

#: Event IDs signalling privilege / credential activity.
CREDENTIAL_EVENT_IDS = {
    "4672",  # special privileges assigned to new logon
    "4648",  # explicit credential logon
    "4720",  # user account created
    "4732",  # member added to a security group
    "4738",  # user account changed
    "4740",  # account locked out
    "4756",  # member added to admin group
}

_SYSTEM_ACCOUNTS = {
    "system",
    "nt authority\\system",
    "local system",
    "network service",
    "nt authority\\network service",
    "local service",
    "nt authority\\local service",
    "-",
    "?",
}

#: C2 / shell-flavoured ports that make an outbound flow suspicious even
#: when the IP is otherwise innocuous.
SUSPICIOUS_PORTS = {"4444", "1337", "31337", "6667", "6697", "5555", "9001"}

_PORT_RE = re.compile(r"(?:dst_?port|port)\D{0,3}(\d{1,5})", re.IGNORECASE)
_RUNKEY_RE = re.compile(
    r"(run key|\\run\\|hklm[\\/]+software[\\/]+microsoft[\\/]+windows[\\/]+currentversion[\\/]+run|"
    r"hkc[uud][\\/]+software[\\/]+microsoft[\\/]+windows[\\/]+currentversion[\\/]+run)",
    re.IGNORECASE,
)
_LSASS_RE = re.compile(r"\blsass", re.IGNORECASE)


def roadmap_level(score: float) -> str:
    """Map a 0-100 score to the roadmap risk scale."""
    if score >= LEVEL_HIGH:
        return "CRITICAL"
    if score >= LEVEL_MEDIUM:
        return "HIGH"
    if score >= LEVEL_LOW:
        return "MEDIUM"
    return "LOW"


def severity_for_level(level: str) -> str:
    return {
        "LOW": "low",
        "MEDIUM": "medium",
        "HIGH": "high",
        "CRITICAL": "critical",
    }.get(str(level).upper(), "medium")


def _event_id(ev) -> str:
    return str(getattr(ev, "event_id", "") or "")


def _event_ids(events: list) -> list[str]:
    return [_event_id(ev) for ev in events or []]


def _external_ips(facts) -> list[str]:
    return [
        ip
        for ip in facts.ips
        if ip and not ip.startswith(("127.", "10.0.", "10.1.", "169.254."))
    ]


def _known_user(facts, session) -> bool:
    """The account has prior activity history in the platform."""
    users = [u for u in facts.users if u.lower() not in _SYSTEM_ACCOUNTS]
    if not users or session is None:
        return False
    try:
        from backend.database.models import NormalizedEvent

        row = session.scalars(
            select(NormalizedEvent.id).where(NormalizedEvent.user == users[0]).limit(1)
        ).first()
        return row is not None
    except Exception:
        logger.exception("known-user lookup failed for %s", users[0])
        return False


def adjust_risk(
    base_risk: float,
    facts,
    events: list | None = None,
    session=None,
) -> dict:
    """Apply the roadmap's dynamic deltas to a base risk score.

    ``facts`` is a ``backend.context.ContextFacts``; ``events`` the linked
    normalized events (optional, used for event-ID signals); ``session`` an
    optional DB session for the known-user lookup.

    Returns a dict: ``risk`` (0-100), ``level``, ``severity``,
    ``adjustments`` (list of ``{signal, delta, note}``) and
    ``developer_workflow`` (bool).
    """
    events = events or []
    event_ids = _event_ids(events)
    delta = 0
    adjustments: list[dict] = []

    def apply(signal: str, amount: int, note: str) -> None:
        nonlocal delta
        delta += amount
        adjustments.append({"signal": signal, "delta": amount, "note": note})

    # -- risk-reduction signals ----------------------------------------------
    dev = [p for p in facts.processes if facts.reputation.get(p.lower()) == "developer"]
    if dev or facts.dev_signals:
        tools = ", ".join((dev[:3] or ["toolchain CLI"]) + facts.dev_signals[:2])
        apply("developer_tool", -DEV_TOOL_PENALTY, f"developer toolchain ({tools})")
    elif facts.developer_workflow()["detected"]:
        apply(
            "developer_tool", -DEV_TOOL_PENALTY, "developer workflow signals detected"
        )

    if facts.signed_binaries and not facts.ips:
        apply(
            "signed_binary",
            -SIGNED_BINARY_PENALTY,
            "all processes are known system/trusted tooling",
        )

    if _known_user(facts, session):
        apply(
            "known_user",
            -KNOWN_USER_PENALTY,
            f"account '{facts.users[0]}' has prior activity history",
        )

    # -- risk-elevation signals ----------------------------------------------
    if _external_ips(facts):
        apply(
            "suspicious_network",
            SUSPICIOUS_NETWORK_BONUS,
            "external destination(s): " + ", ".join(_external_ips(facts)[:3]),
        )
    elif any(p in event_ids for p in SUSPICIOUS_PORTS):
        apply(
            "suspicious_network",
            SUSPICIOUS_NETWORK_BONUS,
            "suspicious port in evidence",
        )

    if any(eid in event_ids for eid in PERSISTENCE_EVENT_IDS) or _RUNKEY_RE.search(
        facts.evidence_text
    ):
        apply(
            "persistence_detected",
            PERSISTENCE_BONUS,
            "persistence activity (service/task/run-key) in evidence",
        )

    credential = any(eid in event_ids for eid in CREDENTIAL_EVENT_IDS)
    if "10" in event_ids and any(
        _LSASS_RE.search(facts.evidence_text) for _ in [facts]
    ):
        credential = True
    if event_ids.count("4625") >= 5:
        credential = True
    if credential:
        apply(
            "credential_access",
            CREDENTIAL_ACCESS_BONUS,
            "credential / privilege activity in evidence",
        )

    final = round(min(100.0, max(0.0, float(base_risk) + delta)), 2)
    level = roadmap_level(final)
    return {
        "risk": final,
        "level": level,
        "severity": severity_for_level(level),
        "adjustments": adjustments,
        "developer_workflow": facts.developer_workflow()["detected"],
    }
