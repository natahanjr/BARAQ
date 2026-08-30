"""OpenID Connect SSO adapter (SC5c).

Implements the authorization-code flow with PKCE against any standard OpenID
Provider. The provider's discovery document is fetched from
<issuer>/.well-known/openid-configuration, the authorization URL is built per
request, and on callback the code is exchanged for tokens. The id_token
signature is verified against the provider's JWKS (RS256 / ES256) and every
issuer/audience/expiry/nonce check is enforced â€” nothing is accepted on
trust. Uses only stdlib + the already-required ``cryptography`` package, so no
extra runtime dependency is introduced.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
import urllib.parse
import urllib.request
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from backend.config import (
    LDAP_ADMIN_GROUPS,
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    OIDC_CLOCK_SKEW,
    OIDC_ENABLED,
    OIDC_GROUP_CLAIM,
    OIDC_ISSUER,
    OIDC_NAME_CLAIM,
    OIDC_REDIRECT_PATH,
    OIDC_SCOPES,
)

logger = logging.getLogger("baraq.oidc")


class OIDCError(Exception):
    """OIDC misconfiguration or provider failure (NOT a user rejection)."""


#: Cache of fetched discovery documents / JWKS, keyed by issuer.
_cached_docs: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------


def oidc_enabled() -> bool:
    return bool(OIDC_ENABLED and OIDC_ISSUER and OIDC_CLIENT_ID)


def redirect_url(base_url: str) -> str:
    """Absolute redirect_uri the provider must call back to."""
    return f"{base_url.rstrip('/')}{OIDC_REDIRECT_PATH}"


# ---------------------------------------------------------------------------
# Network helpers (TLS verification always on)
# ---------------------------------------------------------------------------


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _b64url_encode(byte_data: bytes) -> str:
    return base64.urlsafe_b64encode(byte_data).rstrip(b"=").decode("ascii")


def _http_json(url: str, timeout: int = 10) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        raise OIDCError(f"cannot reach provider endpoint {url}: {exc}") from exc


def discovery_document(issuer: str | None = None) -> dict:
    """Fetch and cache the provider's OpenID configuration document."""
    issuer = (issuer or OIDC_ISSUER).rstrip("/")
    if not issuer:
        raise OIDCError("OIDC issuer not configured")
    if issuer not in _cached_docs:
        _cached_docs[issuer] = _http_json(f"{issuer}/.well-known/openid-configuration")
    return _cached_docs[issuer]


# ---------------------------------------------------------------------------
# PKCE + authorization URL
# ---------------------------------------------------------------------------


def generate_pkce_pair() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge)``; challenge_S256 = S256(verifier)."""
    verifier = secrets.token_urlsafe(64)
    challenge = _b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def make_nonce() -> str:
    return secrets.token_urlsafe(24)


def build_authorization_url(
    state: str, nonce: str, code_challenge: str, base_url: str
) -> str:
    doc = discovery_document()
    endpoint = doc.get("authorization_endpoint")
    if not endpoint:
        raise OIDCError("provider has no authorization_endpoint")
    params = {
        "response_type": "code",
        "client_id": OIDC_CLIENT_ID,
        "redirect_uri": redirect_url(base_url),
        "scope": OIDC_SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    sep = "&" if "?" in endpoint else "?"
    return f"{endpoint}{sep}{urllib.parse.urlencode(params)}"


# ---------------------------------------------------------------------------
# Token exchange
# ---------------------------------------------------------------------------


def exchange_code(code: str, code_verifier: str, base_url: str) -> dict[str, Any]:
    """Exchange an authorization code for tokens at the token endpoint."""
    doc = discovery_document()
    endpoint = doc.get("token_endpoint")
    if not endpoint:
        raise OIDCError("provider has no token_endpoint")
    form = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_url(base_url),
            "client_id": OIDC_CLIENT_ID,
            "client_secret": OIDC_CLIENT_SECRET,
            "code_verifier": code_verifier,
        }
    ).encode("ascii")
    try:
        with urllib.request.urlopen(
            urllib.request.Request(
                endpoint,
                data=form,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
            timeout=10,
        ) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        raise OIDCError(f"token exchange failed: {exc}") from exc


# ---------------------------------------------------------------------------
# id_token validation
# ---------------------------------------------------------------------------


def _jwt_parts(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    parts = token.split(".")
    if len(parts) != 3:
        raise OIDCError("malformed id_token: expected 3 segments")
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        claims = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except Exception as exc:
        raise OIDCError(f"id_token not valid JSON: {exc}") from exc
    return header, claims


_EC_CURVES = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}


def _public_key_from_jwk(jwk: dict):
    kty = jwk.get("kty")
    if kty == "RSA":
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "EC":
        curve = _EC_CURVES.get(jwk.get("crv"))
        if curve is None:
            raise OIDCError(f"unsupported EC curve {jwk.get('crv')}")
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve()).public_key()
    raise OIDCError(f"unsupported JWK key type {kty}")


def _verify_signature(token: str, public_key) -> None:
    parts = token.split(".")
    header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
    alg = header.get("alg")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    signature = _b64url_decode(parts[2])
    try:
        if alg == "RS256":
            public_key.verify(
                signature, signing_input, padding.PKCS1v15(), hashes.SHA256()
            )
        elif alg == "ES256":
            public_key.verify(signature, signing_input, ec.ECDSA(hashes.SHA256()))
        else:
            raise OIDCError(f"unsupported id_token alg {alg}")
    except (InvalidSignature, OIDCError):
        raise OIDCError("id_token signature verification failed")


def _jwk_for_kid(doc: dict, kid: str):
    """Locate the signing key (by kid) from the provider's JWKS document."""
    jwks_uri = doc.get("jwks_uri")
    if not jwks_uri:
        raise OIDCError("provider has no jwks_uri")
    jwks = _http_json(jwks_uri)
    keys = jwks.get("keys", [])
    for jwk in keys:
        if jwk.get("kid") == kid:
            return _public_key_from_jwk(jwk)
    # One-key providers often omit kid entirely â€” fall back to the sole key.
    if len(keys) == 1:
        return _public_key_from_jwk(keys[0])
    raise OIDCError(f"no JWKS key matches kid={kid!r}")


def validate_id_token(
    token: str, nonce: str, issuer: str | None = None, client_id: str | None = None
) -> dict[str, Any]:
    """Cryptographically and claim-wise validate an id_token.

    Enforced: signature (JWKS), ``iss``, ``aud``, ``exp``/``iat``/``nbf``
    within clock skew, and the anti-replay ``nonce``. Returns the claims.
    """
    header, claims = _jwt_parts(token)
    now = time.time()
    skew = OIDC_CLOCK_SKEW

    expected_iss = issuer or OIDC_ISSUER
    expected_aud = client_id or OIDC_CLIENT_ID

    if int(claims.get("exp", 0)) < now - skew:
        raise OIDCError("id_token expired")
    if int(claims.get("iat", 0 or 0)) > now + skew:
        raise OIDCError("id_token issued in the future")
    if int(claims.get("nbf", 0) or 0) > now + skew:
        raise OIDCError("id_token not valid before its nbf")

    if claims.get("iss") != expected_iss.rstrip("/"):
        raise OIDCError(f"issuer mismatch: {claims.get('iss')!r}")
    aud = claims.get("aud")
    aud_list = aud if isinstance(aud, list) else [aud]
    if expected_aud not in aud_list:
        raise OIDCError(f"audience mismatch: {aud!r}")

    if claims.get("nonce") != nonce:
        raise OIDCError("id_token nonce mismatch")

    doc = discovery_document(expected_iss)
    public_key = _jwk_for_kid(doc, header.get("kid") or "")
    _verify_signature(token, public_key)
    return claims


# ---------------------------------------------------------------------------
# Profile mapping
# ---------------------------------------------------------------------------


def profile_from_claims(claims: dict[str, Any]) -> dict[str, Any]:
    """Map validated OIDC claims onto a BARAQ operator profile."""
    username = (
        claims.get("preferred_username") or claims.get("sub") or claims.get("email")
    )
    if not username:
        raise OIDCError("id_token carries no usable username claim")
    username = str(username).strip().lower()
    full_name = claims.get(OIDC_NAME_CLAIM) or claims.get("name") or ""
    groups = claims.get(OIDC_GROUP_CLAIM, [])
    if isinstance(groups, str):
        groups = [groups]
    role = (
        "admin"
        if any(
            str(group).lower() == admin.lower() or admin.lower() in str(group).lower()
            for admin in LDAP_ADMIN_GROUPS
            for group in groups
        )
        else "analyst"
    )
    return {
        "username": username,
        "full_name": str(full_name),
        "role": role,
        "groups": [str(g) for g in groups],
    }
