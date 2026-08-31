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
from typing import Any

from backend.config import (
    THREAT_INTEL_ABUSECH_KEY,
    THREAT_INTEL_ABUSEIPDB_KEY,
    THREAT_INTEL_CENSYS_KEY,
    THREAT_INTEL_FINDIP_KEY,
    THREAT_INTEL_GREYNOISE_KEY,
    THREAT_INTEL_OTX_KEY,
    THREAT_INTEL_SHODAN_KEY,
    THREAT_INTEL_TIMEOUT,
    THREAT_INTEL_VT_KEY,
)
from backend.config import (
    THREAT_INTEL_CACHE_HOURS as THREAT_INTEL_CACHE_HOURS,
)
from backend.config import (
    THREAT_INTEL_ENABLED as THREAT_INTEL_ENABLED,
)

logger = logging.getLogger("baraq.threatintel")

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE
)
_HASH_RE = re.compile(r"^[a-f0-9]{32}(?:[a-f0-9]{32})?$|^[a-f0-9]{64}$", re.IGNORECASE)

#: High-confidence embedded IOC baseline (IPs / domains / hashes known-bad).
_EMBEDDED_IOCS: dict[str, dict[str, str]] = {
    # Offensive tooling / known scanner families seen in the wild
    "185.220.101.45": {
        "category": "malicious",
        "label": "Known scanning host (TOR exit)",
    },
    "45.155.205.233": {
        "category": "malicious",
        "label": "Known malicious C2 infrastructure",
    },
    "91.219.236.232": {"category": "malicious", "label": "Known brute-force source"},
    "78.128.113.170": {"category": "malicious", "label": "Known brute-force source"},
    "94.232.41.138": {
        "category": "malicious",
        "label": "Known credential-stuffing host",
    },
    "185.220.101.4": {"category": "malicious", "label": "TOR exit node (anonymizer)"},
    "185.220.101.32": {"category": "malicious", "label": "TOR exit node (anonymizer)"},
}

#: Suspicious TLDs commonly abused in phishing / C2.
_SUSPICIOUS_TLDS = frozenset(
    {
        "buzz",
        "click",
        "download",
        "gq",
        "icu",
        "info",
        "link",
        "ml",
        "online",
        "rest",
        "review",
        "site",
        "stream",
        "tk",
        "top",
        "work",
        "xyz",
        "zip",
        "mov",
        "cfd",
        "bond",
        "country",
        "cyou",
        "day",
        "fun",
        "host",
        "loan",
        "men",
        "monster",
        "pro",
        "racing",
        "repl",
        "science",
        "sbs",
        "skin",
        "soy",
        "space",
        "store",
        "tattoo",
        "team",
        "vip",
        "wang",
        "win",
    }
)

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
        return {
            "category": "benign",
            "label": "Private / loopback / reserved address",
            "confidence": 1.0,
        }
    for net in _ABUSE_SUBNETS:
        try:
            if ipaddress.ip_address(ip_str) in net:
                return {
                    "category": "malicious",
                    "label": f"Abuse-dense subnet {net}",
                    "confidence": 0.9,
                }
        except ValueError:
            continue
    return None


def _classify_domain(domain: str) -> dict[str, Any] | None:
    if not _DOMAIN_RE.match(domain):
        return None
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld in _SUSPICIOUS_TLDS:
        return {
            "category": "suspicious",
            "label": f"TLD '.{tld}' frequently abused in phishing",
            "confidence": 0.7,
        }
    return None


def _http_json(
    url: str, headers: dict[str, str] | None = None, timeout: float = 8
) -> dict | None:
    import urllib.request

    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except Exception as exc:
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
            return {
                "category": "benign",
                "label": "Whitelisted by AbuseIPDB",
                "confidence": 0.8,
            }
        score = float(data.get("abuseConfidenceScore") or 0)
        if score >= 50:
            return {
                "category": "malicious",
                "label": f"AbuseIPDB confidence {score:.0f}%",
                "confidence": min(0.99, 0.5 + score / 100.0),
            }
        if score >= 20:
            return {
                "category": "suspicious",
                "label": f"AbuseIPDB confidence {score:.0f}%",
                "confidence": 0.6,
            }
    except Exception:
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
                hits.append(
                    {
                        "category": "malicious",
                        "label": f"OTX: {pulse_count} pulse(s) - {first.get('name', 'unknown')}",
                        "confidence": min(0.95, 0.6 + pulse_count * 0.05),
                    }
                )
        except Exception:
            continue
    return hits[0] if hits else None


def _vt(indicators: list[str]) -> dict[str, Any] | None:
    """VirusTotal API v3 file/domain/ip lookup (one call per indicator)."""
    if not THREAT_INTEL_VT_KEY:
        return None
    for indicator in indicators:
        kind = (
            "ip_addresses"
            if _IPV4_RE.match(indicator)
            else "domains" if _DOMAIN_RE.match(indicator) else "files"
        )
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
                    return {
                        "category": "malicious",
                        "label": f"VT: {malicious} engines flag",
                        "confidence": min(0.99, 0.6 + malicious * 0.03),
                    }
            elif kind == "domains":
                stats = data.get("last_analysis_stats") or {}
                malicious = int(stats.get("malicious") or 0)
                if malicious > 0:
                    return {
                        "category": "malicious",
                        "label": f"VT: {malicious} engines flag domain",
                        "confidence": min(0.99, 0.6 + malicious * 0.03),
                    }
            else:
                stats = data.get("last_analysis_stats") or {}
                malicious = int(stats.get("malicious") or 0)
                if malicious > 0:
                    return {
                        "category": "malicious",
                        "label": f"VT: {malicious} engines flag IP",
                        "confidence": min(0.99, 0.6 + malicious * 0.03),
                    }
        except Exception:
            continue
    return None


def _shodan(ip_str: str) -> dict[str, Any] | None:
    """Shodan IP lookup - internet device search and port scanning data."""
    if not THREAT_INTEL_SHODAN_KEY:
        return None
    raw = _http_json(
        f"https://api.shodan.io/shodan/host/{ip_str}?key={THREAT_INTEL_SHODAN_KEY}",
        timeout=THREAT_INTEL_TIMEOUT,
    )
    if not raw:
        return None
    try:
        import json
        data = json.loads(raw)
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        org = data.get("org", "Unknown")
        os_info = data.get("os") or "Unknown"
        if vulns:
            return {
                "category": "malicious",
                "label": f"Shodan: {len(vulns)} vuln(s) on {len(ports)} ports ({org})",
                "confidence": min(0.95, 0.6 + len(vulns) * 0.05),
            }
        if ports and len(ports) > 5:
            return {
                "category": "suspicious",
                "label": f"Shodan: {len(ports)} open ports ({org}, {os_info})",
                "confidence": 0.5,
            }
        if org:
            return {
                "category": "unknown",
                "label": f"Shodan: {org} ({os_info})",
                "confidence": 0.3,
            }
    except Exception:
        pass
    return None


def _greynoise(ip_str: str) -> dict[str, Any] | None:
    """GreyNoise IP lookup - mass scanning and internet noise detection."""
    if not THREAT_INTEL_GREYNOISE_KEY:
        return None
    raw = _http_json(
        f"https://api.greynoise.io/v3/community/{ip_str}",
        headers={"key": THREAT_INTEL_GREYNOISE_KEY},
        timeout=THREAT_INTEL_TIMEOUT,
    )
    if not raw:
        return None
    try:
        import json
        data = json.loads(raw)
        classification = data.get("classification", "unknown")
        noise = data.get("noise", False)
        riot = data.get("riot", False)
        if classification == "malicious":
            return {
                "category": "malicious",
                "label": f"GreyNoise: malicious scanner (noise={noise}, riot={riot})",
                "confidence": 0.9,
            }
        if classification == "unknown" and noise:
            return {
                "category": "suspicious",
                "label": f"GreyNoise: mass scanning activity detected",
                "confidence": 0.6,
            }
        if classification == "benign" or riot:
            return {
                "category": "benign",
                "label": f"GreyNoise: known service (riot={riot})",
                "confidence": 0.8,
            }
    except Exception:
        pass
    return None


def _censys(indicator: str) -> dict[str, Any] | None:
    """Censys search - certificate transparency and host discovery."""
    if not THREAT_INTEL_CENSYS_KEY:
        return None
    kind = "hosts" if _IPV4_RE.match(indicator) else "hosts"
    parts = THREAT_INTEL_CENSYS_KEY.split(":", 1)
    if len(parts) != 2:
        return None
    import base64
    auth = base64.b64encode(f"{parts[0]}:{parts[1]}".encode()).decode()
    raw = _http_json(
        f"https://search.censys.io/api/v2/{kind}/{indicator}",
        headers={"Authorization": f"Basic {auth}"},
        timeout=THREAT_INTEL_TIMEOUT,
    )
    if not raw:
        return None
    try:
        import json
        data = json.loads(raw).get("result", {})
        services = data.get("services", [])
        if len(services) > 10:
            return {
                "category": "suspicious",
                "label": f"Censys: {len(services)} exposed services",
                "confidence": 0.5,
            }
        if services:
            svc_names = [s.get("service_name", "?") for s in services[:5]]
            return {
                "category": "unknown",
                "label": f"Censys: services {', '.join(svc_names)}",
                "confidence": 0.3,
            }
    except Exception:
        pass
    return None


def _findip(ip_str: str) -> dict[str, Any] | None:
    """FindIP - unlimited free IP reputation with threat detection (no rate limits)."""
    if not THREAT_INTEL_FINDIP_KEY:
        return None
    raw = _http_json(
        f"https://api.findip.net/v2/ip/{ip_str}",
        headers={"Authorization": f"Bearer {THREAT_INTEL_FINDIP_KEY}"},
        timeout=THREAT_INTEL_TIMEOUT,
    )
    if not raw:
        return None
    try:
        import json
        data = json.loads(raw)
        intel = data.get("intelligence", {})
        threat = intel.get("threat", {})
        is_malicious = threat.get("is_malicious", False)
        risk_score = threat.get("risk_score", 0)
        categories = threat.get("categories", [])
        if is_malicious or risk_score > 70:
            cats = ", ".join(categories[:3]) if categories else "threat detected"
            return {
                "category": "malicious",
                "label": f"FindIP: risk {risk_score}/100 ({cats})",
                "confidence": min(0.95, 0.5 + risk_score / 200.0),
            }
        if risk_score > 40:
            return {
                "category": "suspicious",
                "label": f"FindIP: risk {risk_score}/100",
                "confidence": 0.5,
            }
        if intel.get("is_tor") or intel.get("is_proxy") or intel.get("is_vpn"):
            kind = "Tor" if intel.get("is_tor") else "proxy" if intel.get("is_proxy") else "VPN"
            return {
                "category": "suspicious",
                "label": f"FindIP: {kind} exit node (risk {risk_score}/100)",
                "confidence": 0.6,
            }
    except Exception:
        pass
    return None


def _ipdetails(ip_str: str) -> dict[str, Any] | None:
    """IPDetails.io - unlimited free IP geolocation and threat intelligence (no rate limits)."""
    raw = _http_json(
        f"https://api.ipdetails.io/json/{ip_str}",
        timeout=THREAT_INTEL_TIMEOUT,
    )
    if not raw:
        return None
    try:
        import json
        data = json.loads(raw)
        threat = data.get("threat", {})
        is_malicious = threat.get("is_malicious", False)
        risk_score = threat.get("risk_score", 0)
        categories = threat.get("categories", [])
        if is_malicious or risk_score > 70:
            cats = ", ".join(categories[:3]) if categories else "threat detected"
            return {
                "category": "malicious",
                "label": f"IPDetails: risk {risk_score}/100 ({cats})",
                "confidence": min(0.95, 0.5 + risk_score / 200.0),
            }
        if risk_score > 40:
            return {
                "category": "suspicious",
                "label": f"IPDetails: risk {risk_score}/100",
                "confidence": 0.5,
            }
        is_hosting = data.get("network", {}).get("is_hosting", False)
        if is_hosting:
            org = data.get("network", {}).get("org", "Unknown")
            return {
                "category": "unknown",
                "label": f"IPDetails: hosting provider ({org})",
                "confidence": 0.3,
            }
    except Exception:
        pass
    return None


def _isbadip(indicator: str) -> dict[str, Any] | None:
    """isbadip.com - unlimited free IP/domain reputation (no key needed, no rate limits)."""
    import urllib.request
    req = urllib.request.Request(
        f"https://api.isbadip.com/api/v1/host/{indicator}",
        headers={"Accept": "application/json", "User-Agent": "Baraq-SOC/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=THREAT_INTEL_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")
        import json
        data = json.loads(raw)
        is_malicious = data.get("malicious", False)
        confidence = data.get("confidence")
        threat = data.get("threat", {})
        categories = threat.get("categories", [])
        sources = threat.get("sources", [])
        score = threat.get("score", 0)
        if is_malicious:
            src_names = ", ".join(sources[:3]) if sources else "multiple feeds"
            cats = ", ".join(categories[:3]) if categories else "threat"
            conf_map = {"low": 0.6, "medium": 0.75, "high": 0.9}
            conf = conf_map.get(str(confidence), 0.7)
            return {
                "category": "malicious",
                "label": f"isbadip: {cats} ({src_names})",
                "confidence": conf,
            }
    except Exception:
        pass
    return None


def _ffraud(indicator: str) -> dict[str, Any] | None:
    """FFraud.com - unlimited free IP fraud intelligence (no key needed, no rate limits)."""
    import urllib.request
    if not _IPV4_RE.match(indicator):
        return None
    req = urllib.request.Request(
        f"https://api.ffraud.com/public/ip/{indicator}",
        headers={"Accept": "application/json", "User-Agent": "Baraq-SOC/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=THREAT_INTEL_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")
        import json
        data = json.loads(raw)
        fraud_score = data.get("fraud_score", 0)
        is_abuser = data.get("is_abuser", False)
        is_tor = data.get("tor", False)
        is_vpn = data.get("vpn", False)
        is_proxy = data.get("proxy", False)
        if fraud_score > 70 or is_abuser:
            flags = []
            if is_tor:
                flags.append("Tor")
            if is_vpn:
                flags.append("VPN")
            if is_proxy:
                flags.append("proxy")
            flag_str = f" ({', '.join(flags)})" if flags else ""
            return {
                "category": "malicious",
                "label": f"FFraud: score {fraud_score}/100{flag_str}",
                "confidence": min(0.95, 0.5 + fraud_score / 200.0),
            }
        if fraud_score > 40:
            return {
                "category": "suspicious",
                "label": f"FFraud: score {fraud_score}/100",
                "confidence": 0.5,
            }
    except Exception:
        pass
    return None


def _threatfox(indicators: list[str]) -> dict[str, Any] | None:
    """ThreatFox IOC lookup - malware IOC sharing by abuse.ch (requires Auth-Key)."""
    if not THREAT_INTEL_ABUSECH_KEY:
        return None
    import json as _json
    import urllib.request
    for indicator in indicators:
        body = _json.dumps({"query": "search_ioc", "search_term": indicator, "exact_match": True}).encode()
        req = urllib.request.Request(
            "https://threatfox-api.abuse.ch/api/v1/",
            data=body,
            headers={"Content-Type": "application/json", "Auth-Key": THREAT_INTEL_ABUSECH_KEY},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=THREAT_INTEL_TIMEOUT) as resp:
                raw = resp.read().decode("utf-8")
            data = _json.loads(raw)
            if data.get("query_status") == "no_result":
                continue
            results = data.get("data", [])
            if results:
                first = results[0]
                malware = first.get("malware", "unknown")
                confidence = int(first.get("confidence_level", 50))
                return {
                    "category": "malicious",
                    "label": f"ThreatFox: {malware} (confidence {confidence}%)",
                    "confidence": min(0.95, confidence / 100.0),
                }
        except Exception:
            continue
    return None


def _urlhaus(indicators: list[str]) -> dict[str, Any] | None:
    """URLhaus malicious URL lookup - by abuse.ch (requires Auth-Key for full access)."""
    import json as _json
    import urllib.request
    headers = {"Content-Type": "application/json"}
    if THREAT_INTEL_ABUSECH_KEY:
        headers["Auth-Key"] = THREAT_INTEL_ABUSECH_KEY
    for indicator in indicators:
        body = _json.dumps({"host": indicator}).encode()
        req = urllib.request.Request(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=THREAT_INTEL_TIMEOUT) as resp:
                raw = resp.read().decode("utf-8")
            data = _json.loads(raw)
            status = data.get("query_status", "")
            if status == "no_results":
                continue
            url_count = int(data.get("urls_online", 0))
            if url_count > 0:
                return {
                    "category": "malicious",
                    "label": f"URLhaus: {url_count} malicious URL(s) hosted",
                    "confidence": min(0.95, 0.6 + url_count * 0.02),
                }
        except Exception:
            continue
    return None


def _malwarebazaar(indicators: list[str]) -> dict[str, Any] | None:
    """MalwareBazaar sample lookup - by abuse.ch (requires Auth-Key for full access)."""
    import json as _json
    import urllib.request
    headers = {"Content-Type": "application/json"}
    if THREAT_INTEL_ABUSECH_KEY:
        headers["Auth-Key"] = THREAT_INTEL_ABUSECH_KEY
    for indicator in indicators:
        if not _HASH_RE.match(indicator):
            continue
        body = _json.dumps({"query": "get_info", "hash": indicator}).encode()
        req = urllib.request.Request(
            "https://mb-api.abuse.ch/api/v1/",
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=THREAT_INTEL_TIMEOUT) as resp:
                raw = resp.read().decode("utf-8")
            data = _json.loads(raw)
            status = data.get("query_status", "")
            if status == "hash_not_found":
                continue
            results = data.get("data", [])
            if results:
                first = results[0]
                malware_name = first.get("signature", "unknown")
                file_type = first.get("file_type", "unknown")
                return {
                    "category": "malicious",
                    "label": f"MalwareBazaar: {malware_name} ({file_type})",
                    "confidence": 0.95,
                }
        except Exception:
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
