"""Commercial licensing: Ed25519-signed license keys with trial fallback.

Design
------
- License keys are signed with the vendor's Ed25519 *private* key; every
  deployed instance verifies with the embedded *public* key. A customer
  cannot forge keys without the private key.
- Key format: ``BARAQ1.<base64url(payload)>.<base64url(signature)>``
  where payload is a compact JSON object:
  ``{license_id, customer, edition, seats, issued_at, expires_at, features}``
- Editions: ``trial`` (grace period, no activation needed), ``standard``
  and ``professional`` (require a valid signed key).
- Trial: 30 days from the first run (persisted in the ``licenses`` table).
- Enforcement: fail-closed in production (refuse to boot when invalid),
  warn in development.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from backend.config import IS_PRODUCTION, LICENSE_PUBLIC_KEY, TRIAL_DAYS
from backend.database.models import LicenseRecord

logger = logging.getLogger("baraq.licensing")

KEY_PREFIX = "BARAQ1."
_ED25519 = None


def _ed25519():
    global _ED25519
    if _ED25519 is None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )

        _ED25519 = (Ed25519PrivateKey, Ed25519PublicKey)
    return _ED25519


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str | bytes) -> bytes:
    if isinstance(text, bytes):
        text = text.decode("ascii")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class LicenseInfo:
    license_id: str
    customer: str
    edition: str
    seats: int
    issued_at: str
    expires_at: str
    features: list[str] = field(default_factory=list)


def _payload_bytes(info: LicenseInfo) -> bytes:
    return json.dumps(
        {
            "license_id": info.license_id,
            "customer": info.customer,
            "edition": info.edition,
            "seats": int(info.seats),
            "issued_at": info.issued_at,
            "expires_at": info.expires_at,
            "features": list(info.features),
        },
        separators=(",", ":"),
    ).encode("utf-8")


def sign_license(info: LicenseInfo, private_key_pem: bytes | str) -> str:
    Ed25519PrivateKey, _ = _ed25519()
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode("ascii")
    raw = private_key_pem if len(private_key_pem) == 32 else _b64d(private_key_pem)
    key = Ed25519PrivateKey.from_private_bytes(raw)
    payload = _payload_bytes(info)
    sig = key.sign(payload)
    return f"{KEY_PREFIX}{_b64e(payload)}.{_b64e(sig)}"


def _parse_key(license_key: str) -> tuple[bytes, bytes]:
    if not license_key.startswith(KEY_PREFIX):
        raise ValueError("not a BARAQ license key")
    payload_b64, sig_b64 = license_key[len(KEY_PREFIX) :].split(".", 1)
    return _b64d(payload_b64), _b64d(sig_b64)


def verify_license(license_key: str, public_key_pem: str | None = None) -> LicenseInfo:
    _Ed25519PrivateKey, Ed25519PublicKey = _ed25519()
    try:
        pem = _b64d(public_key_pem or LICENSE_PUBLIC_KEY)
        key = Ed25519PublicKey.from_public_bytes(pem)
        payload, sig = _parse_key(license_key)
        key.verify(sig, payload)
        data = json.loads(payload.decode("utf-8"))
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid license key: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"invalid license key: {exc}") from exc
    return LicenseInfo(
        license_id=data["license_id"],
        customer=data["customer"],
        edition=data["edition"],
        seats=int(data.get("seats", 1)),
        issued_at=data["issued_at"],
        expires_at=data["expires_at"],
        features=list(data.get("features", [])),
    )


@dataclass(frozen=True)
class LicenseState:
    status: str
    edition: str = ""
    customer: str = ""
    seats: int = 0
    expires_at: str = ""
    license_id: str = ""
    reason: str = ""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _trial_start(db: Session) -> datetime:
    row = (
        db.query(LicenseRecord)
        .filter(LicenseRecord.edition == "trial")
        .order_by(LicenseRecord.activated_at)
        .first()
    )
    if row is not None:
        return row.activated_at
    row = LicenseRecord(
        license_id="trial",
        customer="",
        edition="trial",
        seats=1,
        expires_at=(datetime.now(UTC) + timedelta(days=TRIAL_DAYS)).isoformat(),
        activated_at=datetime.now(UTC),
        license_key="",
        payload_json="{}",
    )
    db.add(row)
    db.commit()
    return row.activated_at


def get_license_state(db: Session) -> LicenseState:
    row = (
        db.query(LicenseRecord)
        .filter(LicenseRecord.edition != "trial")
        .order_by(LicenseRecord.activated_at.desc())
        .first()
    )
    if row is not None:
        try:
            info = verify_license(row.license_key)
        except (ValueError, KeyError, TypeError):
            return LicenseState("invalid", reason="signature verification failed")
        try:
            expires = datetime.fromisoformat(info.expires_at)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires < datetime.now(UTC):
                return LicenseState("expired", reason="license expired")
        except (TypeError, ValueError):
            return LicenseState("invalid", reason="invalid expiry")
        return LicenseState(
            "active",
            edition=info.edition,
            customer=info.customer,
            seats=info.seats,
            expires_at=info.expires_at,
            license_id=info.license_id,
        )
    start = _trial_start(db)
    remaining = start + timedelta(days=TRIAL_DAYS) - datetime.now(UTC)
    if remaining <= timedelta(0):
        return LicenseState("expired", reason="trial period ended")
    return LicenseState(
        "trial",
        edition="trial",
        seats=1,
        expires_at=(start + timedelta(days=TRIAL_DAYS)).isoformat(),
        reason=f"{TRIAL_DAYS}-day trial",
    )


def activate_license(db: Session, license_key: str) -> LicenseState:
    info = verify_license(license_key)
    existing = (
        db.query(LicenseRecord)
        .filter(LicenseRecord.license_id == info.license_id)
        .first()
    )
    if existing is not None:
        db.delete(existing)
        db.commit()
    db.add(
        LicenseRecord(
            license_id=info.license_id,
            customer=info.customer,
            edition=info.edition,
            seats=info.seats,
            expires_at=info.expires_at,
            activated_at=datetime.now(UTC),
            license_key=license_key,
            payload_json=json.dumps(
                {"issued_at": info.issued_at, "features": info.features}
            ),
        )
    )
    db.commit()
    logger.info(
        "License activated: %s / %s / %d seat(s) until %s",
        info.license_id,
        info.customer,
        info.seats,
        info.expires_at,
    )
    return get_license_state(db)


def enforce_license(db: Session) -> None:
    state = get_license_state(db)
    if state.status in ("active", "trial"):
        if state.status == "trial":
            logger.warning(
                "License: running in %s trial mode (expires %s)",
                state.edition,
                state.expires_at,
            )
        return
    if not IS_PRODUCTION and os.environ.get("BARAQ_LICENSE_BYPASS", "") == "1":
        logger.critical(
            "License %r - BARAQ_LICENSE_BYPASS=1 overrides development boot",
            state.status,
        )
        return
    if IS_PRODUCTION:
        raise RuntimeError(
            f"License check failed ({state.status}: {state.reason}). "
            "Activate a license key via /api/system/license/activate."
        )
    logger.warning(
        "License check failed (%s: %s) - running unlicensed in development",
        state.status,
        state.reason,
    )
