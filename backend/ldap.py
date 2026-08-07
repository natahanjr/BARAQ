"""LDAP / Active Directory SSO adapter (SC5b).

Authenticates operators against an external directory and maps group
membership onto SentinelSOC roles. The ``ldap3`` library is imported lazily:
deployments without LDAP configured never load (or need) it.

Flow (see ``_authenticate_impl``):
1. Bind with the optional service account (anonymous when ``SENTINEL_LDAP_BIND_DN``
   is empty) and locate the user's DN using ``SENTINEL_LDAP_USER_FILTER``.
2. Verify the operator's password by re-binding as that DN.
3. Read group membership (``memberOf``), map to a role, and return a profile
   that the login endpoint auto-provisions as a local operator account.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from backend.config import (
    LDAP_ADMIN_GROUPS,
    LDAP_BASE_DN,
    LDAP_BIND_DN,
    LDAP_BIND_PASSWORD,
    LDAP_ENABLED,
    LDAP_NAME_ATTRIBUTE,
    LDAP_SEARCH_TIMEOUT,
    LDAP_URL,
    LDAP_USER_FILTER,
)

logger = logging.getLogger("sentinel.ldap")


class LDAPError(Exception):
    """Directory unreachable or misconfigured (NOT a credentials failure).

    Raised so callers can distinguish "cannot reach the directory" from
    "credentials rejected" and avoid leaking whether a user exists.
    """


def ldap_enabled() -> bool:
    """True when LDAP auth is both enabled in config and fully configured."""
    return bool(LDAP_ENABLED and LDAP_URL and LDAP_BASE_DN)


def _group_names(member_of: list[str] | None) -> list[str]:
    """Normalise memberOf DNs to plain group names for role matching.

    Returns both the full DN and the leading CN, so admin groups can be
    configured either as ``CN=Sentinel Admins,OU=Groups,DC=corp,DC=local``
    or simply ``Sentinel Admins``.
    """
    names: list[str] = []
    for dn in member_of or []:
        dn = str(dn)
        names.append(dn)
        match = re.match(r"^CN=([^,]+)", dn, re.IGNORECASE)
        if match:
            names.append(match.group(1))
    return names


def _role_for(member_of: list[str] | None) -> str:
    """Map directory group membership to a SentinelSOC role."""
    names = [n.lower() for n in _group_names(member_of)]
    for admin_group in LDAP_ADMIN_GROUPS:
        if any(admin_group.lower() in n for n in names):
            return "admin"
    return "analyst"


def ldap_authenticate(username: str, password: str) -> dict[str, Any] | None:
    """Verify ``username``/``password`` against the directory.

    Returns a profile dict ``{"username", "full_name", "role", "groups"}`` on
    success, ``None`` when credentials are rejected, and raises
    ``LDAPError`` when the directory itself cannot be reached/queried.
    """
    if not ldap_enabled():
        raise LDAPError("LDAP authentication is not configured")
    return _authenticate_impl(username, password)


def _authenticate_impl(username: str, password: str) -> dict[str, Any] | None:
    """The real directory interaction. Extracted so tests can substitute a fake."""
    from ldap3 import SUBTREE, Connection, Server

    server = _server(LDAP_URL, LDAP_SEARCH_TIMEOUT)

    # 1. Service-account bind (anonymous when no bind DN configured).
    bind_conn = Connection(
        server,
        user=LDAP_BIND_DN or None,
        password=LDAP_BIND_PASSWORD or None,
        auto_bind=True,
        raise_exceptions=False,
        receive_timeout=LDAP_SEARCH_TIMEOUT,
    )
    if not bind_conn.bound:
        raise LDAPError(f"bind failed: {bind_conn.result}")

    # 2. Locate the user's DN.
    search_filter = LDAP_USER_FILTER.format(username=username)
    ok = bind_conn.search(
        search_base=LDAP_BASE_DN,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=[LDAP_NAME_ATTRIBUTE, "memberOf"],
        size_limit=5,
        time_limit=LDAP_SEARCH_TIMEOUT,
    )
    if not ok or not bind_conn.entries:
        bind_conn.unbind()
        return None  # No such user in the directory.

    entry = bind_conn.entries[0]
    user_dn = entry.entry_dn
    bind_conn.unbind()

    # 3. Verify the operator's password by binding as their DN.
    user_conn = Connection(
        server,
        user=user_dn,
        password=password,
        auto_bind=True,
        raise_exceptions=False,
        receive_timeout=LDAP_SEARCH_TIMEOUT,
    )
    if not user_conn.bound:
        return None  # Wrong password (or account locked/disabled).
    user_conn.unbind()

    attributes = entry.entry_attributes_as_dict
    display = attributes.get(LDAP_NAME_ATTRIBUTE)
    display = display[0] if display else entry_display_name(entry, username)
    member_of = list(attributes.get("memberOf", []))
    return {
        "username": username,
        "full_name": display,
        "role": _role_for(member_of),
        "groups": member_of,
    }


def _server(url: str, timeout: int):
    from ldap3 import Server

    use_ssl = url.lower().startswith("ldaps://")
    host = url.split("://", 1)[-1]
    return Server(host, use_ssl=use_ssl, connect_timeout=timeout)


def entry_display_name(entry, fallback: str) -> str:
    """Fall back to the entry's CN attribute when the configured display
    attribute is absent (e.g. POSIX/OpenLDAP without displayName)."""
    for attr in ("cn", "uid", "sAMAccountName"):
        values = entry.entry_attributes_as_dict.get(attr)
        if values:
            return values[0]
    return fallback
