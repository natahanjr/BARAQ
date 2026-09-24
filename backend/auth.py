"""Authentication core: PBKDF2 password hashing + HMAC-signed tokens.

Kept dependency-free (stdlib only). A token is ``base64(payload).signature``
where the signature is an HMAC-SHA256 over the payload using a secret derived
from the same secret as the API keys. Token types are explicit and are never
interchangeable: access and refresh tokens are sessions, while MFA and reset
tokens are short-lived capabilities accepted only by their dedicated endpoints.

Revocation:
  Every token carries a random ``jti``. ``revoke_token(jti, db)`` adds
  it to the ``token_revocations`` table; ``verify_token`` then rejects
  any token whose ``jti`` is present. A per-user session watermark invalidates
  all outstanding stateless tokens after a password, role, organization, or
  account-state change.
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

_PBKDF2_ITERATIONS = 600_000


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


ACCESS_TOKEN_TTL_SECONDS = 15 * 60
REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 3600
MFA_CHALLENGE_TTL_SECONDS = 5 * 60
RESET_TOKEN_TTL_SECONDS = 60 * 60

TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"
TOKEN_TYPE_MFA = "mfa"
TOKEN_TYPE_RESET = "reset"
TOKEN_TYPES = frozenset(
    {TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH, TOKEN_TYPE_MFA, TOKEN_TYPE_RESET}
)
NON_SESSION_TOKEN_TYPES = frozenset({TOKEN_TYPE_MFA, TOKEN_TYPE_RESET})


def _sign_token(payload: dict) -> str:
    body = (
        base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
        .rstrip(b"=")
        .decode("ascii")
    )
    sig = hmac.new(_token_secret(), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def create_token(
    user_id: int,
    username: str,
    role: str,
    org: str = "",
    ttl_seconds: int = ACCESS_TOKEN_TTL_SECONDS,
) -> str:
    """Create a short-lived access token (15 min default)."""
    now = int(time.time())
    return _sign_token(
        {
            "uid": user_id,
            "sub": username,
            "role": role,
            "org": org,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": secrets.token_hex(16),
            "type": TOKEN_TYPE_ACCESS,
        }
    )


def create_refresh_token(
    user_id: int,
    username: str,
    ttl_seconds: int = REFRESH_TOKEN_TTL_SECONDS,
) -> str:
    """Create a long-lived refresh token that rotates on use."""
    now = int(time.time())
    return _sign_token(
        {
            "uid": user_id,
            "sub": username,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": secrets.token_hex(16),
            "type": TOKEN_TYPE_REFRESH,
        }
    )


def create_mfa_challenge(
    user_id: int,
    username: str,
    ttl_seconds: int = MFA_CHALLENGE_TTL_SECONDS,
) -> str:
    """Create a password-verified challenge that is not a session token."""
    now = int(time.time())
    return _sign_token(
        {
            "uid": user_id,
            "sub": username,
            "role": "",
            "mfa": True,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": secrets.token_hex(16),
            "type": TOKEN_TYPE_MFA,
        }
    )


def create_reset_token(
    user_id: int,
    username: str,
    ttl_seconds: int = RESET_TOKEN_TTL_SECONDS,
) -> str:
    """Create a password-reset capability that is not a session token."""
    now = int(time.time())
    return _sign_token(
        {
            "uid": user_id,
            "sub": username,
            "role": "",
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": secrets.token_hex(16),
            "type": TOKEN_TYPE_RESET,
        }
    )


def verify_token(
    token: str,
    expected_type: str = TOKEN_TYPE_ACCESS,
) -> dict | None:
    """Validate a signed token of exactly ``expected_type``."""
    if expected_type not in TOKEN_TYPES:
        raise ValueError(f"unknown expected_type: {expected_type!r}")
    if not isinstance(token, str):
        return None
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(
            _token_secret(), body.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        token_type = payload.get("type")
        if token_type not in TOKEN_TYPES or token_type != expected_type:
            return None
        if token_type in NON_SESSION_TOKEN_TYPES and payload.get("role"):
            return None
        now = time.time()
        if int(payload.get("exp", 0)) < now:
            return None
        iat = int(payload.get("iat", 0) or 0)
        if iat <= 0 or iat > now + 300:
            return None
        jti = payload.get("jti")
        if jti and _is_token_revoked(jti):
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def verify_mfa_challenge(token: str) -> dict | None:
    return verify_token(token, expected_type=TOKEN_TYPE_MFA)


def verify_reset_token(token: str) -> dict | None:
    return verify_token(token, expected_type=TOKEN_TYPE_RESET)


def verify_refresh_token(token: str) -> dict | None:
    """Validate a refresh token. Same as verify_token but expects type='refresh'."""
    return verify_token(token, expected_type=TOKEN_TYPE_REFRESH)


def session_fresh_for_user(payload: dict | None, user) -> bool:
    """Return whether an access token is still valid for ``user``."""
    if not payload or user is None or payload.get("type") != TOKEN_TYPE_ACCESS:
        return False
    iat = int(payload.get("iat", 0) or 0)
    if iat <= 0:
        return False
    for attr in ("sessions_valid_after", "password_changed_at"):
        mark = getattr(user, attr, None)
        if mark is not None and iat <= int(mark.timestamp()):
            return False
    return True


def verify_session_for_user(token: str, user) -> dict | None:
    payload = verify_token(token, expected_type=TOKEN_TYPE_ACCESS)
    return payload if session_fresh_for_user(payload, user) else None


def verify_token_for_user(token: str, user) -> dict | None:
    """Backward-compatible alias for :func:`verify_session_for_user`."""
    return verify_session_for_user(token, user)


def revoke_all_sessions(user, reason: str) -> bool:
    """Invalidate all outstanding sessions for a user."""
    user.sessions_valid_after = datetime.now(UTC)
    logger.info("Revoked all sessions for %s (reason=%s)", user.username, reason)
    return True


def _is_token_revoked(jti: str) -> bool:
    """True when ``jti`` is in the revocation table.

    Uses a fresh DB session so callers (including request middleware)
    do not have to manage one. On DB error, returns True (fail-closed)
    to prevent revoked tokens from being accepted during outages.
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
        logger.warning("Token revocation lookup failed (fail-closed): %s", exc)
        return True


def revoke_token(
    jti: str,
    username: str = "",
    reason: str = "",
    ttl_seconds: int = REFRESH_TOKEN_TTL_SECONDS,
) -> bool:
    """Add ``jti`` to the revocation list.

    The retention period is never shorter than an access token so a revoked
    token cannot become usable again while it is still cryptographically
    valid. Re-revoking the same ``jti`` is a no-op.
    """
    if not jti:
        return False
    ttl_seconds = max(int(ttl_seconds or 0), ACCESS_TOKEN_TTL_SECONDS)
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
            return int(result.rowcount or 0)  # type: ignore[attr-defined]
        finally:
            db.close()
    except Exception as exc:
        logger.warning("Token revocation prune failed: %s", exc)
        return 0
