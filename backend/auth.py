"""Authentication core: PBKDF2 password hashing + HMAC-signed session tokens.

Kept dependency-free (stdlib only). A token is ``base64(payload).signature``
where the signature is an HMAC-SHA256 over the payload using a secret derived
from the same secret as the API keys; payload carries user id, username, role
and an expiry timestamp, so sessions are stateless and survive restarts.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from backend.config import AUTH_TOKEN_SECRET

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
    payload = {
        "uid": user_id,
        "sub": username,
        "role": role,
        "org": org,
        "exp": int(time.time()) + ttl_seconds,
        "jti": secrets.token_hex(8),
    }
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    sig = hmac.new(_token_secret(), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def create_mfa_challenge(
    user_id: int, username: str, ttl_seconds: int = 300
) -> str:
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
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    sig = hmac.new(_token_secret(), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_token(token: str) -> dict | None:
    """Validate a session token; return its payload or None."""
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(
            _token_secret(), body.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(
            base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        )
        if int(payload.get("exp", 0)) < time.time():
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
