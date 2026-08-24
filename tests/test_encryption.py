"""Tests for field-level AES-256-GCM encryption at rest (backend.crypto)."""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="DPAPI vault is Windows-only"
)


@pytest.fixture()
def encryption_on(monkeypatch, tmp_path):
    """Force encryption on and redirect the vault to a temp file."""
    monkeypatch.setenv("BARAQ_ENCRYPT_AT_REST", "1")
    import backend.crypto as crypto_mod
    from backend.vault import SecretVault

    tmp_vault = tmp_path / "secrets.dat"

    def _fake_vault():
        return SecretVault(tmp_vault)

    monkeypatch.setattr(crypto_mod, "_open_vault", _fake_vault)
    crypto_mod._cached_key = None
    yield crypto_mod
    crypto_mod._cached_key = None


def test_roundtrip(encryption_on):
    from backend.crypto import decrypt_text, encrypt_text

    secret = "Failed logon for 'adm in'; password: s3cr3t!"
    enc = encrypt_text(secret)
    assert enc is not None
    assert enc.startswith("baraq-v1:")
    assert secret not in enc
    assert decrypt_text(enc) == secret


def test_encryption_disabled_passthrough(monkeypatch):
    from backend.crypto import decrypt_text, encrypt_text

    monkeypatch.setenv("BARAQ_ENCRYPT_AT_REST", "0")
    import importlib

    crypto = importlib.import_module("backend.crypto")
    importlib.reload(crypto)
    assert crypto.encrypt_text("plain") == "plain"
    assert crypto.decrypt_text("plain") == "plain"


def test_legacy_plaintext_passthrough():
    from backend.crypto import decrypt_text

    assert decrypt_text("old legacy value") == "old legacy value"
    assert decrypt_text(None) is None
    assert decrypt_text("") == ""


def test_corrupt_blob_returns_none():
    from backend.crypto import decrypt_text

    assert decrypt_text("baraq-v1:AAAA:BBBB") is None
    assert decrypt_text("baraq-v1:not-base64!!:not-base64!!") is None


def test_key_persists_in_vault(encryption_on, tmp_path):
    from backend.config import ENCRYPTION_KEY_NAME
    from backend.vault import SecretVault

    import backend.crypto as crypto

    crypto._cached_key = None
    k1 = crypto._load_key()
    vault = SecretVault(tmp_path / "secrets.dat")
    assert vault.get(ENCRYPTION_KEY_NAME) is not None
    # Loading again returns the same key.
    assert crypto._load_key() == k1


def test_column_roundtrip_via_orm(encryption_on, tmp_path):
    from datetime import datetime, timezone

    from sqlalchemy import text

    from backend.database.connection import SessionLocal, engine
    from backend.database.models import AuditLog, NormalizedEvent

    db = SessionLocal()
    try:
        db.add(NormalizedEvent(
            event_id=4625, category="Login", source="Security", user="bob",
            host="h1", risk="Medium", severity="medium",
            message="Failed logon for ADM\\bob using password s3cr3t+",
            timestamp=datetime.now(timezone.utc),
        ))
        db.add(AuditLog(actor="admin", action="config.set", detail="password rotated"))
        db.commit()

        ev = db.query(NormalizedEvent).first()
        assert ev.message == "Failed logon for ADM\\bob using password s3cr3t+"
        au = db.query(AuditLog).first()
        assert au.detail == "password rotated"
    finally:
        db.close()  # release the session so the next test's TRUNCATE is not blocked

    with engine.begin() as conn:
        raw = conn.execute(text("SELECT message FROM events")).scalar_one()
    assert "s3cr3t" not in raw
    assert raw.startswith("baraq-v1:")


def test_key_round_trip_across_vault_reload(encryption_on):
    """Key survives decrypting with a fresh vault instance (same DPAPI user)."""
    import backend.crypto as crypto_mod

    crypto_mod._cached_key = None
    key1 = crypto_mod._load_key()
    crypto_mod._cached_key = None
    key2 = crypto_mod._load_key()
    assert key1 == key2