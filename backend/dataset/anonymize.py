"""Anonymization / pseudonymization for the research dataset.

When anonymization is enabled for a collection, sensitive identifiers
(usernames, hostnames, internal IPs, domains, emails, paths) are mapped
to stable pseudonyms with HMAC-SHA256 so the same source entity always
maps to the same pseudonym within the collection while relationships
stay useful for research.

Secrets (passwords, tokens, API keys, credentials) are never included -
command lines are sanitized with a redaction pass instead.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re

_SECRET_REGEX = re.compile(
    r"(?i)\b(?:password|passwd|pwd|token|api[_-]?key|secret|credential|authorization|"
    r"auth[_-]?key|client[_-]?secret|private[_-]?key|access[_-]?key)\s*"
    r"(?:=|\s*[:=]\s*|\s+)(?:\"|')?([A-Za-z0-9_.\\/@:+-]{3,64})"
)
_EMAIL_REGEX = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_DOMAIN_REGEX = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b"
)
_SECRET_VALUE_REGEX = re.compile(r"(?i)([A-Za-z0-9._\\/@:+-]{8,64})")


def _is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


class Pseudonymizer:
    """Stable, collection-scoped pseudonym mapping."""

    def __init__(self, collection_id: int, enabled: bool, salt: str = "baraq"):
        self.collection_id = int(collection_id or 0)
        self.enabled = bool(enabled)
        self._salt = salt

    # ------------------------------------------------------------------
    def _token(self, entity: str) -> int:
        key = f"{self._salt}::{self.collection_id}".encode()
        digest = hmac.new(key, entity.encode("utf-8"), hashlib.sha256).hexdigest()
        return int(digest[:12], 16)

    def pseudonym(self, kind: str, entity: str) -> str:
        """Deterministic pseudonym like ``HOST_017`` for a source entity."""
        entity = (entity or "").strip()
        if not entity or not self.enabled:
            return entity
        index = self._token(f"{kind}:{entity}") % 100_000
        prefix = {
            "user": "USR",
            "host": "HOST",
            "device": "HOST",
            "ip": "IP",
            "domain": "DOM",
            "email": "EML",
            "path": "PATH",
            "file": "FILE",
        }.get(kind, "ENT")
        return f"{prefix}_{index:04d}"

    def _map_ip(self, ip: str) -> str:
        if not self.enabled or not _is_internal_ip(ip):
            return ip
        index = self._token(f"ip:{ip}") % 100_000
        return f"10.{index // 65536}.{(index // 256) % 256}.{index % 256}"

    def _map_domain(self, domain: str) -> str:
        if not self.enabled:
            return domain
        index = self._token(f"domain:{domain}") % 100_000
        return f"domain-{index:05d}.research.local"

    def _map_email(self, email: str) -> str:
        if not self.enabled:
            return email
        index = self._token(f"email:{email}") % 100_000
        return f"user-{index:05d}@research.local"

    def _map_path(self, path: str) -> str:
        if not self.enabled:
            return path
        index = self._token(f"path:{path}") % 100_000
        return f"/dataset/path/{index:05d}"

    # ------------------------------------------------------------------
    def field(self, kind: str, value: str | None) -> str:
        """Anonymize a single field."""
        if not value:
            return ""
        if not self.enabled:
            return value
        if kind in ("user", "host", "device", "ip", "domain"):
            return self.pseudonym(kind, value)
        return value

    def text(self, text: str | None) -> str:
        """Redact secrets and pseudonymize emails/domains inside free text."""
        if not text:
            return ""
        if not self.enabled:
            return self._redact(text)
        text = self._redact(text)
        text = _EMAIL_REGEX.sub(lambda m: self._map_email(m.group(0)), text)
        text = _DOMAIN_REGEX.sub(
            lambda m: (
                self._map_domain(m.group(0))
                if not _is_internal_ip(m.group(0))
                else m.group(0)
            ),
            text,
        )
        return text

    def command_line(self, cmdline: str | None) -> str:
        """Sanitize a command line: redact secrets, keep structure."""
        return self.text(cmdline)

    def ips(self, value: str | None) -> str:
        """Map internal IPs (comma separated) to consistent pseudonyms."""
        if not value:
            return ""
        parts = [p.strip() for p in str(value).split(",") if p.strip()]
        mapped = [self._map_ip(p) for p in parts]
        return ", ".join(mapped)

    def file_path(self, value: str | None) -> str:
        if not value:
            return ""
        if not self.enabled:
            return value
        return self._map_path(value)

    def domain(self, value: str | None) -> str:
        if not value:
            return ""
        if not self.enabled:
            return value
        return self._map_domain(value)

    def email(self, value: str | None) -> str:
        if not value:
            return ""
        if not self.enabled:
            return value
        return self._map_email(value)

    @staticmethod
    def _redact(text: str) -> str:
        def _repl(match: re.Match) -> str:
            key = match.group(0).rsplit(match.group(1), 1)[0]
            return f"{key}<redacted>"

        return _SECRET_REGEX.sub(_repl, text)
