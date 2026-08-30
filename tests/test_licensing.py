"""Licensing module tests: key signing/verification, tamper detection,
trial fallback, activation flow, and production fail-closed behaviour."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest

# A test-only keypair: private key signs, public key verifies via the module.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from backend.database.models import LicenseRecord
from backend.licensing import (
    LicenseInfo,
    activate_license,
    enforce_license,
    get_license_state,
    sign_license,
    verify_license,
)

_TEST_PRIVATE = Ed25519PrivateKey.generate()
_TEST_PUBLIC = (
    base64.urlsafe_b64encode(_TEST_PRIVATE.public_key().public_bytes_raw())
    .rstrip(b"=")
    .decode("ascii")
)


def _sign(**overrides) -> str:
    info = LicenseInfo(
        license_id=overrides.get("license_id", "test-license-1"),
        customer=overrides.get("customer", "Test University"),
        edition=overrides.get("edition", "professional"),
        seats=overrides.get("seats", 10),
        issued_at=overrides.get("issued_at", datetime.now(UTC).isoformat()),
        expires_at=overrides.get(
            "expires_at", (datetime.now(UTC) + timedelta(days=365)).isoformat()
        ),
        features=overrides.get("features", ["sigma", "tls"]),
    )
    return sign_license(info, _TEST_PRIVATE.private_bytes_raw())


def test_sign_verify_roundtrip(monkeypatch):
    monkeypatch.setattr("backend.licensing.LICENSE_PUBLIC_KEY", _TEST_PUBLIC)
    key = _sign()
    info = verify_license(key)
    assert info.customer == "Test University"
    assert info.edition == "professional"
    assert info.seats == 10
    assert "sigma" in info.features


def test_tampered_key_rejected(monkeypatch):
    monkeypatch.setattr("backend.licensing.LICENSE_PUBLIC_KEY", _TEST_PUBLIC)
    key = _sign()
    tampered = key[:-2] + ("AA" if not key.endswith("AA") else "BB")
    with pytest.raises(ValueError):
        verify_license(tampered)


def test_wrong_public_key_rejected():
    other = Ed25519PrivateKey.generate()
    other_pub = (
        base64.urlsafe_b64encode(other.public_key().public_bytes_raw())
        .rstrip(b"=")
        .decode("ascii")
    )
    key = _sign()
    with pytest.raises(ValueError):
        verify_license(key, other_pub)


def test_not_a_license_key_rejected(monkeypatch):
    monkeypatch.setattr("backend.licensing.LICENSE_PUBLIC_KEY", _TEST_PUBLIC)
    with pytest.raises(ValueError):
        verify_license("BARAQ1.bogus")
    with pytest.raises(ValueError):
        verify_license("hello-world")


def test_trial_state_without_license(db):
    state = get_license_state(db)
    assert state.status == "trial"
    assert state.edition == "trial"
    assert state.expires_at


def test_activate_and_status(db, monkeypatch):
    monkeypatch.setattr("backend.licensing.LICENSE_PUBLIC_KEY", _TEST_PUBLIC)
    key = _sign(customer="Lab Alpha", seats=25)
    state = activate_license(db, key)
    assert state.status == "active"
    assert state.customer == "Lab Alpha"
    assert state.seats == 25
    state2 = get_license_state(db)
    assert state2.status == "active"
    assert state2.license_id == "test-license-1"


def test_activate_invalid_key_rejected(db, monkeypatch):
    monkeypatch.setattr("backend.licensing.LICENSE_PUBLIC_KEY", _TEST_PUBLIC)
    with pytest.raises(ValueError):
        activate_license(db, "BARAQ1.invalid.invalid")


def test_expired_license_reported(db, monkeypatch):
    monkeypatch.setattr("backend.licensing.LICENSE_PUBLIC_KEY", _TEST_PUBLIC)
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    key = _sign(expires_at=past)
    activate_license(db, key)
    state = get_license_state(db)
    assert state.status == "expired"


def test_trial_expiry_after_grace(db, monkeypatch):
    monkeypatch.setattr("backend.licensing.TRIAL_DAYS", 0)
    start = datetime.now(UTC) - timedelta(hours=1)
    row = LicenseRecord(
        license_id="trial",
        customer="",
        edition="trial",
        seats=1,
        expires_at="",
        license_key="",
        payload_json="{}",
        activated_at=start,
    )
    db.add(row)
    db.commit()
    state = get_license_state(db)
    assert state.status == "expired"


def test_enforce_license_fail_closed_production(db, monkeypatch):
    monkeypatch.setattr("backend.licensing.LICENSE_PUBLIC_KEY", _TEST_PUBLIC)
    monkeypatch.setattr("backend.licensing.IS_PRODUCTION", True)
    monkeypatch.setattr("backend.licensing.TRIAL_DAYS", -1)
    start = datetime.now(UTC) - timedelta(days=2)
    db.add(
        LicenseRecord(
            license_id="trial",
            customer="",
            edition="trial",
            seats=1,
            expires_at="",
            license_key="",
            payload_json="{}",
            activated_at=start,
        )
    )
    db.commit()
    with pytest.raises(RuntimeError, match="License check failed"):
        enforce_license(db)


def test_enforce_license_ok_with_valid_key(db, monkeypatch):
    monkeypatch.setattr("backend.licensing.LICENSE_PUBLIC_KEY", _TEST_PUBLIC)
    monkeypatch.setattr("backend.licensing.IS_PRODUCTION", True)
    activate_license(db, _sign())
    enforce_license(db)  # must not raise


def test_license_json_roundtrip(db, monkeypatch):
    monkeypatch.setattr("backend.licensing.LICENSE_PUBLIC_KEY", _TEST_PUBLIC)
    activate_license(db, _sign(features=["sigma", "reporting"]))
    payload = json.loads(
        db.query(LicenseRecord)
        .filter(LicenseRecord.license_id == "test-license-1")
        .first()
        .payload_json
    )
    assert payload["features"] == ["sigma", "reporting"]
