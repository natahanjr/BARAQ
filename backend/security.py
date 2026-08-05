"""Authentication & RBAC dependencies for the SentinelSOC API.

Simple, dependency-free API-key auth:

- Every ``/api/*`` request (except health) must present ``X-API-Key``.
- Keys map to a role: ``analyst`` (read + standard operations) or ``admin``
  (privileged actions such as alert containment, collection, ML retraining).
- When auth is disabled (``SENTINEL_AUTH_ENABLED=0``) every caller is treated
  as ``admin`` so local development and the test suite keep working.
"""
from __future__ import annotations

import logging
from typing import Callable

from fastapi import Header, HTTPException

from backend.config import API_KEYS, AUTH_ENABLED

logger = logging.getLogger("sentinel.auth")

API_KEY_HEADER = "X-API-Key"


def authenticate(x_api_key: str | None = Header(default=None, alias=API_KEY_HEADER)) -> str:
    """Resolve the caller's role from the API key (or admin when disabled)."""
    if not AUTH_ENABLED:
        return "admin"
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key (X-API-Key header)")
    role = API_KEYS.get(x_api_key.strip())
    if not role:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return role


def require_role(*roles: str) -> Callable:
    """Return a FastAPI dependency enforcing one of the given roles."""

    def _dependency(role: str = Header(None, alias=API_KEY_HEADER)):
        caller = authenticate(role)
        if caller not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"Requires role(s): {', '.join(roles)}",
            )
        return caller

    return _dependency


#: Any authenticated caller (analyst or admin).
require_auth = require_role("analyst", "admin")
#: Admin-only operations.
require_admin = require_role("admin")
