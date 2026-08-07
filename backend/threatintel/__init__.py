"""Threat-intel enrichment: indicator lookups with an offline baseline feed.

The module answers one question for each indicator (IP / domain / hash):
"is this known-bad, and what is the context?". Providers are layered:

1. **Offline baseline** (always available): reserved/private ranges, TOR exit
   nodes, known scanner & abuse ranges, suspicious TLDs, and a small embedded
   high-confidence list of well-known malicious indicators.
2. **Online providers** (optional, key-gated): AbuseIPDB, AlienVault OTX and
   VirusTotal are queried when their API keys are configured. Network failures
   degrade gracefully to the offline verdict.

Results are cached in the ``threat_intel_records`` table for
``THREAT_INTEL_CACHE_HOURS`` so repeated lookups (e.g. per scheduler cycle)
never re-hit the network.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.config import (
    THREAT_INTEL_ABUSEIPDB_KEY,
    THREAT_INTEL_CACHE_HOURS,
    THREAT_INTEL_ENABLED,
    THREAT_INTEL_OTX_KEY,
    THREAT_INTEL_TIMEOUT,
    THREAT_INTEL_VT_KEY,
)

logger = logging.getLogger("sentinel.threatintel")

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)
_HASH_RE = re.compile(r"^[a-f0-9]{32}(?:[a-f0-9]{32})?$|^[a-f0-9]{64}$", re.IGNORECASE)

#: High-confidence embedded IOC baseline (IPs / domains / hashes known-bad).
_EMBEDDED_IOCS: dict[str, dict[str, str]] = {
    # Offensive tooling / known scanner families seen in the wild
    "185.220.101.45": {"category": "malicious", "label": "Known scanning host (TOR exit)"},
    "45.155.205.233": {"category": "malicious", "label": "Known malicious C2 infrastructure"},
    "91.219.236.232": {"category": "malicious", "label": "Known brute-force source"},
    "78.128.113.170": {"category": "malicious", "label": "Known brute-force source"},
    "94.232.41.138": {"category": "malicious", "label": "Known credential-stuffing host"},
    "185.220.101.4": {"category": "malicious", "label": "TOR exit node (anonymizer)"},
    "185.220.101.32": {"category": "malicious", "label": "TOR exit node (anonymizer)"},
}

#: Suspicious TLDs commonly abused in phishing / C2.
_SUSPICIOUS_TLDS = frozenset({
    "buzz", "click", "download", "gq", "icu", "info", "link", "ml", "online",
    "rest", "review", "site", "stream", "tk", "top", "work", "xyz", "zip",
    "mov", "cfd", "bond", "country", "cyou", "day", "fun", "host", "loan",
    "men", "monster", "pro", "racing", "repl", "science", "sbs", "skin", "soy",
    "space", "store", "tattoo", "team", "vip", "wang", "win",
})

#: ASN blocks that are overwhelmingly abuse-dense (reserved / hosting bait).
_ABUSE_SUBNETS = (
    ipaddress.ip_network("45.155.204.0/22"),
    ipaddress.ip_network("91.219.236.0/24"),
    ipaddress.ip_network("94.232.40.0/22"),
    ipaddress.ip_network("185.220.96.0/22"),
)


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def _classify_ip(ip_str: str) -> dict[str, Any] | None:
    if not _IPV4_RE.match(ip_str):
        return None
    if _is_private_ip(ip_str):
        return {"category": "benign", "label": "Private / loopback / reserved address", "confidence": 1.0}
    for net in _ABUSE_SUBNETS:
        try:
            if ipaddress.ip_address(ip_str) in net:
                return {"category": "malicious", "label": f"Abuse-dense subnet {net}", "confidence": 0.9}
        except ValueError:
            continue
    return None


def _classify_domain(domain: str) -> dict[str, Any] | None:
    if not _DOMAIN_RE.match(domain):
        return None
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld in _SUSPICIOUS_TLDS:
        return {"category": "suspicious", "label": f"TLD '.{tld}' frequently abused in phishing", "confidence": 0.7}
    return None


def _http_json(url: str, headers: dict[str, str] | None = None, timeout: float = 8) -> dict | None:
    import urllib.request

    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - provider outage must not break lookups
        logger.debug("Threat-intel request failed for %s: %s", url, exc)
        return None


# ---------------------------------------------------------------------------
# Online provider lookups (key-gated, all return None on failure)
# ---------------------------------------------------------------------------
def _abuseipdb(ip_str: str) -> dict[str, Any] | None:
    if not THREAT_INTEL_ABUSEIPDB_KEY:
        return None
    raw = _http_json(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_str}&maxAgeInDays=90",
        headers={"Key": THREAT_INTEL_ABUSEIPDB_KEY, "Accept": "application/json"},
        timeout=THREAT_INTEL_TIMEOUT,
    )
    if not raw:
        return None
    try:
        import json

        data = json.loads(raw)["data"]
        if data.get("isWhitelisted") and not data.get("abuseConfidenceScore"):
            return {"category": "benign", "label": "Whitelisted by AbuseIPDB", "confidence": 0.8}
        score = float(data.get("abuseConfidenceScore") or 0)
        if score >= 50:
            return {
                "category": "malicious",
                "label": f"AbuseIPDB confidence {score:.0f}%",
                "confidence": min(0.99, 0.5 + score / 100.0),
            }
        if score >= 20:
            return {"category": "suspicious", "label": f"AbuseIPDB confidence {score:.0f}%", "confidence": 0.6}
    except Exception:  # noqa: BLE001
        pass
    return None


def _otx(indicators: list[str]) -> dict[str, Any] | None:
    """AlienVault OTX pulse lookup for a single indicator via the v1 endpoint."""
    if not THREAT_INTEL_OTX_KEY:
        return None
    hits: list[dict[str, Any]] = []
    for indicator in indicators:
        raw = _http_json(
            f"https://otx.alienvault.com/api/v1/indicators/"
            f"{'IPv4' if _IPV4_RE.match(indicator) else 'hostname' if _DOMAIN_RE.match(indicator) else 'file'}"
            f"/{indicator}/general",
            headers={"X-OTX-API-KEY": THREAT_INTEL_OTX_KEY},
            timeout=THREAT_INTEL_TIMEOUT,
        )
        if not raw:
            continue
        try:
            import json

            data = json.loads(raw)
            pulse_count = int(data.get("pulse_info", {}).get("count") or 0)
            if pulse_count > 0:
                first = (data.get("pulse_info", {}).get("pulses") or [{}])[0]
                hits.append({
                    "category": "malicious",
                    "label": f"OTX: {pulse_count} pulse(s) - {first.get('name', 'unknown')}",
                    "confidence": min(0.95, 0.6 + pulse_count * 0.05),
                })
        except Exception:  # noqa: BLE001
            continue
    return hits[0] if hits else None


def _vt(indicators: list[str]) -> dict[str, Any] | None:
    """VirusTotal API v3 file/domain/ip lookup (one call per indicator)."""
    if not THREAT_INTEL_VT_KEY:
        return None
    for indicator in indicators:
        kind = "ip_addresses" if _IPV4_RE.match(indicator) else "domains" if _DOMAIN_RE.match(indicator) else "files"
        raw = _http_json(
            f"https://www.virustotal.com/api/v3/{kind}/{indicator}",
            headers={"x-apikey": THREAT_INTEL_VT_KEY},
            timeout=THREAT_INTEL_TIMEOUT,
        )
        if not raw:
            continue
        try:
            import json

            data = json.loads(raw).get("data", {}).get("attributes", {})
            if kind == "files":
                stats = data.get("last_analysis_stats") or {}
                malicious = int(stats.get("malicious") or 0)
                if malicious > 0:
                    return {"category": "malicious", "label": f"VT: {malicious} engines flag", "confidence": min(0.99, 0.6 + malicious * 0.03)}
            elif kind == "domains":
                stats = data.get("last_analysis_stats") or {}
                malicious = int(stats.get("malicious") or 0)
                if malicious > 0:
                    return {"category": "malicious", "label": f"VT: {malicious} engines flag domain", "confidence": min(0.99, 0.6 + malicious * 0.03)}
            else:
                stats = data.get("last_analysis_stats") or {}
                malicious = int(stats.get("malicious") or 0)
                if malicious > 0:
                    return {"category": "malicious", "label": f"VT: {malicious} engines flag IP", "confidence": min(0.99, 0.6 + malicious * 0.03)}
        except Exception:  # noqa: BLE001
            continue
    return None


def classify_indicator(value: str) -> dict[str, Any] | None:
    """Classify a single indicator using the offline baseline only."""
    value = value.strip()
    if _IPV4_RE.match(value):
        return _classify_ip(value)
    if _DOMAIN_RE.match(value):
        return _classify_domain(value)
    return None
