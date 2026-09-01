"""Authentication core: PBKDF2 password hashing + HMAC-signed session tokens.

Kept dependency-free (stdlib only). A token is ``base64(payload).signature``
where the signature is an HMAC-SHA256 over the payload using a secret derived
from the same secret as the API keys; payload carries user id, username, role
and an expiry timestamp, so sessions are stateless and survive restarts.

Revocation:
  Every token carries a random ``jti``. ``revoke_token(jti, db)`` adds
  it to the ``token_revocations`` table; ``verify_token`` then rejects
  any token whose ``jti`` is present. This is what lets ``/api/auth/logout``
  invalidate an outstanding session immediately instead of waiting for
  the 12-hour TTL, and what gives admin disable / password change /
  role demotion a way to revoke open sessions.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select

from backend.config import AUTH_TOKEN_SECRET
from backend.database.connection import SessionLocal
from backend.database.models import TokenRevocation

logger = logging.getLogger("baraq.auth")

_PBKDF2_ITERATIONS = 260_000


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Return ``pbkdf2$iterations$salt_b64$hash_b64``."""
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS
    )
    return "pbkdf2${}${}${}".format(
        _PBKDF2_ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_b64, hash_b64 = stored.split("$", 3)
        if scheme != "pbkdf2":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            base64.b64decode(salt_b64),
            int(iterations),
        )
        return hmac.compare_digest(digest, base64.b64decode(hash_b64))
    except (ValueError, TypeError):
        return False


def _token_secret() -> bytes:
    return hashlib.sha256(AUTH_TOKEN_SECRET.encode("utf-8")).digest()


def create_token(
    user_id: int, username: str, role: str, org: str = "", ttl_seconds: int = 12 * 3600
) -> str:
    now = int(time.time())
    payload = {
        "uid": user_id,
        "sub": username,
        "role": role,
        "org": org,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": secrets.token_hex(8),
    }
    body = (
        base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
        .rstrip(b"=")
        .decode("ascii")
    )
    sig = hmac.new(_token_secret(), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def create_mfa_challenge(user_id: int, username: str, ttl_seconds: int = 300) -> str:
    """Short-lived token proving password verification passed.

    Carries ``mfa`` in the payload so the login endpoint can tell it apart
    from a full session token; it grants nothing until exchanged for a real
    token via ``/api/auth/mfa/verify``.
    """
    payload = {
        "uid": user_id,
        "sub": username,
        "role": "mfa-challenge",
        "mfa": True,
        "exp": int(time.time()) + ttl_seconds,
        "jti": secrets.token_hex(8),
    }
    body = (
        base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
        .rstrip(b"=")
        .decode("ascii")
    )
    sig = hmac.new(_token_secret(), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_token(token: str) -> dict | None:
    """Validate a session token; return its payload or None.

    Four failure paths, in order:
      1. signature mismatch (tampering)
      2. expiry (``exp`` field)
      3. ``iat`` in the future (clock skew > 5 min, or forged token)
      4. revocation (``jti`` present in token_revocations)
    """
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(
            _token_secret(), body.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        now = time.time()
        if int(payload.get("exp", 0)) < now:
            return None
        # Reject tokens whose ``iat`` is in the future by more than 5
        # minutes. A small skew window tolerates a real-time clock
        # adjustment, but a forged token that claims a future iat is
        # almost certainly hostile.
        iat = int(payload.get("iat", 0))
        if iat > now + 300:
            return None
        # Server-side revocation check. Done outside the HMAC path so a
        # revoked-but-otherwise-valid token is rejected. The cost is one
        # cheap SELECT on a unique index per request.
        jti = payload.get("jti")
        if jti and _is_token_revoked(jti):
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def _is_token_revoked(jti: str) -> bool:
    """True when ``jti`` is in the revocation table.

    Uses a fresh DB session so callers (including request middleware)
    do not have to manage one. Errors are swallowed and treated as
    'not revoked' -- a single transient DB error must not silently lock
    every operator out of the platform; the next request retries.
    """
    try:
        db = SessionLocal()
        try:
            row = db.scalar(
                select(TokenRevocation.id)
                .where(TokenRevocation.jti == jti)
                .limit(1)
            )
            return row is not None
        finally:
            db.close()
    except Exception as exc:
        logger.warning("Token revocation lookup failed (fail-open): %s", exc)
        return False


def revoke_token(
    jti: str,
    username: str = "",
    reason: str = "",
    ttl_seconds: int = 12 * 3600,
) -> bool:
    """Add ``jti`` to the revocation list.

    Idempotent: re-revoking the same ``jti`` is a no-op (the unique
    index on ``token_revocations.jti`` rejects the second insert).
    Returns True on a fresh revocation, False if the token was already
    revoked or the write failed.
    """
    if not jti:
        return False
    try:
        db = SessionLocal()
        try:
            existing = db.scalar(
                select(TokenRevocation.id)
                .where(TokenRevocation.jti == jti)
                .limit(1)
            )
            if existing is not None:
                return False
            db.add(
                TokenRevocation(
                    jti=jti,
                    username=username,
                    reason=reason,
                    revoked_at=datetime.now(UTC),
                    expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
                )
            )
            db.commit()
            return True
        finally:
            db.close()
    except Exception as exc:
        logger.warning("Token revocation write failed: %s", exc)
        return False


def prune_revoked_tokens() -> int:
    """Delete revocation rows whose ``expires_at`` is in the past.

    Called opportunistically (e.g. on logout) so the table does not
    grow without bound. Returns the number of rows deleted.
    """
    try:
        db = SessionLocal()
        try:
            now = datetime.now(UTC)
            result = db.execute(
                delete(TokenRevocation).where(TokenRevocation.expires_at < now)
            )
            db.commit()
            return int(result.rowcount or 0)
        finally:
            db.close()
    except Exception as exc:
        logger.warning("Token revocation prune failed: %s", exc)
        return 0
