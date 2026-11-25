"""Regression tests for dynamic risk scoring (backend/risk/dynamic.py).

Bugs fixed:
1. _external_ips used an incomplete private-prefix list (only 127., 10.0.,
   10.1., 169.254.), so internal IPs like 10.50.100.1, 172.16.100.1,
   192.168.1.1 were misclassified as external and wrongly flagged with
   +30 suspicious_network bonus.
2. SUSPICIOUS_PORTS was checked against Windows event IDs (4625, 4688,
   ...) instead of port numbers found in evidence text, so the check never
   matched. Fixed to scan facts.evidence_text for port numbers.
"""

from __future__ import annotations

from dataclasses import field
from typing import Any


class _FakeFacts:
    """Minimal stand-in for backend.context.engine.ContextFacts."""

    def __init__(
        self,
        ips: list[str] | None = None,
        processes: list[str] | None = None,
        reputation: dict[str, str] | None = None,
        dev_signals: list[str] | None = None,
        evidence_text: str = "",
    ):
        self.ips = ips or []
        self.processes = processes or []
        self.reputation = reputation or {}
        self.dev_signals = dev_signals or []
        self.evidence_text = evidence_text or ""

    def developer_workflow(self) -> dict:
        return {"detected": False, "signals": [], "strength": 0}


def _make_facts(
    ips: list[str] | None = None,
    evidence_text: str = "",
) -> _FakeFacts:
    return _FakeFacts(ips=ips, evidence_text=evidence_text)


def test_external_ips_excludes_full_rfc1918_range():
    """Internal RFC1918 addresses must NOT be treated as external.

    The old _external_ips only excluded 127., 10.0., 10.1., 169.254. —
    missing most of 10.0.0.0/8, all of 172.16.0.0/12, and 192.168.0.0/16.
    """
    from backend.risk.dynamic import _external_ips

    facts = _make_facts(
        ips=[
            "10.50.100.1",   # 10.0.0.0/8 (was missed by old code)
            "172.16.100.1",  # 172.16.0.0/12 (was missed)
            "172.31.255.255",  # 172.16.0.0/12 boundary (was missed)
            "192.168.1.1",   # 192.168.0.0/16 (was missed)
            "127.0.0.1",     # loopback (was correctly excluded)
            "169.254.169.254",  # link-local (was correctly excluded)
            "203.0.113.66",  # truly external (documentation range)
            "45.33.32.156",  # truly external
        ]
    )
    external = _external_ips(facts)
    external_ips = set(external)

    # These must NOT be in the external list
    assert "10.50.100.1" not in external_ips
    assert "172.16.100.1" not in external_ips
    assert "172.31.255.255" not in external_ips
    assert "192.168.1.1" not in external_ips
    assert "127.0.0.1" not in external_ips
    assert "169.254.169.254" not in external_ips

    # These SHOULD be in the external list
    assert "203.0.113.66" in external_ips
    assert "45.33.32.156" in external_ips


def test_suspicious_ports_detected_in_evidence_text():
    """Suspicious ports must be detected in evidence text, not event IDs.

    The old code checked any(p in event_ids for p in SUSPICIOUS_PORTS)
    where event_ids are Windows event IDs (4625, 4688, ...) — completely
    different from port numbers (4444, 1337, ...). Fixed to scan
    facts.evidence_text via _PORT_RE.
    """
    from backend.risk.dynamic import adjust_risk, SUSPICIOUS_PORTS

    facts = _make_facts(
        ips=["203.0.113.66"],  # external IP, but we want to test port detection
        evidence_text=(
            "connection to dst_port=4444 from host workstation-42; "
            "reverse shell on port 1337"
        ),
    )

    result = adjust_risk(
        base_risk=30.0,
        facts=facts,
        events=[],  # event IDs are Windows events, not ports
        session=None,
    )

    # +30 suspicious_network bonus should be applied for the suspicious port
    assert result["risk"] == 60.0, (
        f"Expected risk 60.0 (30 base + 30 suspicious_network), got {result['risk']}"
    )
    port_notes = [
        a["note"] for a in result["adjustments"] if a["signal"] == "suspicious_network"
    ]
    assert any("4444" in n or "1337" in n for n in port_notes), (
        f"Expected suspicious port 4444 or 1337 in notes, got: {port_notes}"
    )


def test_suspicious_ports_not_detected_when_absent():
    """No suspicious_network bonus when no suspicious ports are present."""
    from backend.risk.dynamic import adjust_risk

    facts = _make_facts(
        ips=["203.0.113.66"],
        evidence_text="normal connection to dst_port=443 on host workstation-42",
    )

    result = adjust_risk(
        base_risk=30.0,
        facts=facts,
        events=[],
        session=None,
    )

    # No suspicious port bonus; only external IP bonus (+30)
    assert result["risk"] == 60.0, (
        f"Expected risk 60.0 (30 base + 30 external_ip), got {result['risk']}"
    )
    port_notes = [
        a for a in result["adjustments"] if a["signal"] == "suspicious_network"
    ]
    assert len(port_notes) == 1, (
        f"Expected exactly one suspicious_network adjustment, got {len(port_notes)}"
    )


def test_suspicious_ports_intersection_with_event_ids_is_empty():
    """Document that SUSPICIOUS_PORTS never matches Windows event IDs.

    SUSPICIOUS_PORTS = {"4444", "1337", "31337", "6667", "6697", "5555", "9001"}
    while Windows event IDs are like "4625", "4688", "4720", etc. The old
    any(p in event_ids for p in SUSPICIOUS_PORTS) could never match.
    """
    from backend.risk.dynamic import SUSPICIOUS_PORTS

    event_ids = ["4625", "4688", "4720", "4732", "7045", "1", "10", "11"]
    matches = [p for p in SUSPICIOUS_PORTS if p in event_ids]
    assert matches == [], (
        f"SUSPICIOUS_PORTS should never match Windows event IDs, got {matches}"
    )