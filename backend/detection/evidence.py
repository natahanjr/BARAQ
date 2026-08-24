"""Detection evidence (Phase 2).

Every detection must answer "why did BARAQ create this detection?" with
structured, per-field evidence. A bare "Rule matched" reason is forbidden.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Evidence:
    """One piece of explainable evidence: field / observed value / reason."""

    field: str
    value: Any
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"field": self.field, "value": self.value, "reason": self.reason}


def ev(field: str, value: Any, reason: str) -> Evidence:
    """Convenience constructor."""
    return Evidence(field=field, value=value, reason=reason)


# --- IP classification ------------------------------------------------------

#: IPv4 networks considered internal (private) address space.
#: Documentation ranges (TEST-NET-1/2/3) are deliberately NOT included:
#: they are not corporate space, and detectors must treat them as external.
_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
)


def classify_ip(value: Any) -> str:
    """Deterministic IP classification.

    Returns ``external`` (public), ``private``, ``loopback``,
    ``link_local``, ``reserved`` or ``invalid``. Never raises.
    """
    if not isinstance(value, str) or not value.strip():
        return "invalid"
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return "invalid"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "reserved"
    if any(ip in net for net in _PRIVATE_NETS):
        return "private"
    return "external"


def is_external(value: Any) -> bool:
    return classify_ip(value) == "external"


def first_ip(*values: Any) -> str:
    """First valid-looking IP among candidate values (facts keys)."""
    for v in values:
        if classify_ip(v) != "invalid":
            return str(v)
    return ""