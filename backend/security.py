"""Authentication & RBAC dependencies for the SentinelSOC API.

Supports two client credentials:

- ``Authorization: Bearer <token>`` - HMAC-signed sessions from ``/api/auth/login``
  (multi-user accounts; role is read from the ``users`` table on every call so
  role changes apply immediately).
- ``X-API-Key`` header - legacy shared key (``analyst`` / ``admin`` roles).

The agent channel uses its own ``X-Agent-Key`` scheme and is exempt from this
middleware. When auth is disabled (``SENTINEL_AUTH_ENABLED=0``) every caller is
treated as ``admin`` so local development and the test suite keep working.
"""
from __future__ import annotations

import logging
from typing import Callable

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select

from backend.auth import verify_token
from backend.config import API_KEYS, AUTH_ENABLED
from backend.database.connection import get_db
from backend.database.models import User

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


def _bearer_payload(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        # Session restored from the httpOnly cookie (set on login).
        session = request.cookies.get("sentinel_session", "")
        if session:
            auth = f"Bearer {session}"
    if not auth.lower().startswith("bearer "):
        return None
    return verify_token(auth[7:].strip())


def _bearer_key_role(request: Request) -> str | None:
    """Shared API key presented as a Bearer secret (Prometheus v3 scrape)."""
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    return API_KEYS.get(auth[7:].strip())


def tenant_scope(request: Request) -> str | None:
    """Tenant filter a caller may observe.

    Returns ``None`` for unrestricted (admin roles and disabled auth), a
    concrete org id for analysts (session users), and ``""`` for legacy API
    keys - the system/central scope, which sees only local-host data and
    nothing tagged with an organization.

    Admins may additionally narrow their view to a single organization by
    sending the ``X-Org`` header (used by the frontend org switcher); the
    header is ignored for everyone else so analysts can never widen scope.
    """
    if not AUTH_ENABLED:
        return None
    if getattr(request.state, "api_role", "") == "admin":
        return _admin_org_header(request)
    if getattr(request.state, "token_user", None):
        user = request.state.token_user
        role = user.get("role", "analyst")
        if role == "admin":
            return _admin_org_header(request)
        return str(user.get("org") or "")
    # Legacy X-API-Key / Bearer shared key: system scope only.
    return ""


def _admin_org_header(request: Request) -> str | None:
    """Optional org narrowing for admin callers (X-Org header).

    ``None`` means "all organizations"; an empty or oversized value is
    treated exactly like no header at all.
    """
    requested = (request.headers.get("X-Org") or "").strip()
    if not requested or len(requested) > 64:
        return None
    return requested


def actor_name(request: Request) -> str:
    """Shortcut for audit endpoints: username from token or the API key."""
    payload = _bearer_payload(request)
    if payload:
        return payload.get("sub", "unknown")
    return request.headers.get(API_KEY_HEADER, "unknown")


def resolve_user(request: Request, db) -> User | None:
    """Resolve the authenticated user row from a Bearer token (or None)."""
    if not AUTH_ENABLED:
        return None  # unrestricted dev mode is keyed, not user-keyed
    payload = _bearer_payload(request)
    if not payload:
        return None
    user = db.get(User, payload.get("uid"))
    if not user or not user.is_active:
        return None
    return user


def require_role(*roles: str) -> Callable:
    """Return a FastAPI dependency enforcing one of the given roles.

    Accepts a Bearer session token or the legacy X-API-Key header. Returns the
    actor identifier string (username or api key).
    """
    def _dependency(request: Request, db=Depends(get_db)):
        if not AUTH_ENABLED:
            return "admin"
        payload = _bearer_payload(request)
        if payload:
            user = db.get(User, payload.get("uid"))
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=401, detail="Invalid or expired session"
                )
            if user.role not in roles:
                raise HTTPException(
                    status_code=403,
                    detail=f"Requires role(s): {', '.join(roles)}",
                )
            return user.username
        key = request.headers.get(API_KEY_HEADER)
        role = API_KEYS.get((key or "").strip()) if key else None
        if not role:
            role = _bearer_key_role(request)
        if not role:
            raise HTTPException(status_code=401, detail="Missing or invalid API key")
        if role not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"Requires role(s): {', '.join(roles)}",
            )
        return key or "unknown"
    return _dependency


#: Any authenticated caller (analyst or admin).
require_auth = require_role("analyst", "admin")
#: Admin-only operations.
require_admin = require_role("admin")