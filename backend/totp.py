"""TOTP (RFC 6238) time-based one-time passwords — stdlib only.

Used for second-factor login. Secrets are 20 random bytes base32-encoded
(RFC 4648), codes are 6 digits with a 30-second step and a ±1-step
verification window. No third-party dependency (``pyotp`` not required).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time

TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1  # ±N steps accepted during verification


def generate_secret() -> str:
    """Return a fresh base32 TOTP secret (20 random bytes)."""
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    """HMAC-SHA1-based HOTP value (RFC 4226), formatted to 6 digits."""
    padded = secret.upper() + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 10 ** TOTP_DIGITS:0{TOTP_DIGITS}d}"


def current_code(secret: str, at: float | None = None) -> str:
    """The valid code for ``at`` (default: now)."""
    t = time.time() if at is None else at
    return _hotp(secret, int(t // TOTP_PERIOD))


def verify_code(secret: str, code: str, at: float | None = None) -> bool:
    """Return True when ``code`` matches within the ±window steps.

    Empty/None secrets (2FA not provisioned) always return False.
    """
    if not secret or not code:
        return False
    code = code.strip()
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return False
    t = time.time() if at is None else at
    counter = int(t // TOTP_PERIOD)
    return any(
        hmac.compare_digest(_hotp(secret, counter + delta), code)
        for delta in range(-TOTP_WINDOW, TOTP_WINDOW + 1)
    )


def provisioning_uri(username: str, secret: str, issuer: str = "SentinelSOC") -> str:
    """otpauth:// URI for authenticator apps (Google Authenticator etc.)."""
    from urllib.parse import quote

    label = quote(f"{issuer}:{username}", safe="")
    params = {
        "secret": secret.upper(),
        "issuer": issuer,
        "digits": str(TOTP_DIGITS),
        "period": str(TOTP_PERIOD),
        "algorithm": "SHA1",
    }
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    return f"otpauth://totp/{label}?{qs}"
