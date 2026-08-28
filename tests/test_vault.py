"""Cross-platform secret vault: DPAPI (Windows) + Fernet (others) backends."""
import json
import os

import pytest

import backend.vault as vault


@pytest.fixture
def tmp_vault(tmp_path):
    """A vault path with no pre-existing file."""
    return tmp_path / "secrets.dat"


@pytest.mark.parametrize("backend", ["fernet", "plain"])
def test_non_windows_backend_roundtrip(tmp_vault, backend, monkeypatch):
    monkeypatch.setattr(vault, "_FORCE_BACKEND", backend)
    # The plaintext backend is fail-closed unless explicitly opted in.
    if backend == "plain":
        monkeypatch.setattr(vault, "VAULT_ALLOW_PLAINTEXT", True)
    v = vault.SecretVault(tmp_vault, backend=backend)
    assert v._backend == backend
    v.set_many({"BARAQ_ADMIN_PASSWORD": "s3cret", "TOKEN": "abc"})
    v2 = vault.SecretVault(tmp_vault, backend=backend)
    assert v2.get("BARAQ_ADMIN_PASSWORD") == "s3cret"
    assert v2.all() == {"BARAQ_ADMIN_PASSWORD": "s3cret", "TOKEN": "abc"}
    assert v2.has("TOKEN")
    v2.delete("TOKEN")
    v3 = vault.SecretVault(tmp_vault, backend=backend)
    assert not v3.has("TOKEN")
    assert v3.get("MISSING", "default") == "default"


def test_fernet_key_file_created(tmp_vault, monkeypatch):
    monkeypatch.setattr(vault, "_FORCE_BACKEND", "fernet")
    v = vault.SecretVault(tmp_vault, backend="fernet")
    v.set("K", "v")
    key_path = vault._fernet_key_path(tmp_vault)
    assert key_path.is_file()
    # re-opening with the same key decrypts the prior blob
    v2 = vault.SecretVault(tmp_vault, backend="fernet")
    assert v2.get("K") == "v"


def test_missing_file_is_empty(tmp_vault, monkeypatch):
    monkeypatch.setattr(vault, "_FORCE_BACKEND", "fernet")
    v = vault.SecretVault(tmp_vault, backend="fernet")
    assert v.get("NOPE") is None
    assert v.all() == {}


def test_corrupt_vault_does_not_crash(tmp_vault, monkeypatch):
    monkeypatch.setattr(vault, "_FORCE_BACKEND", "fernet")
    tmp_vault.write_bytes(b"not-valid-encrypted-bytes")
    v = vault.SecretVault(tmp_vault, backend="fernet")
    assert v.all() == {}


def test_vault_enforced_refuses_plain(tmp_vault, monkeypatch):
    monkeypatch.setattr(vault, "_FORCE_BACKEND", "plain")
    monkeypatch.setenv("BARAQ_VAULT_ENFORCED", "1")
    vault.VAULT_ENFORCED = True
    try:
        with pytest.raises(RuntimeError):
            vault.SecretVault(tmp_vault, backend="plain")
    finally:
        vault.VAULT_ENFORCED = False


def test_vault_layout_is_json_object(tmp_vault, monkeypatch):
    monkeypatch.setattr(vault, "_FORCE_BACKEND", "fernet")
    v = vault.SecretVault(tmp_vault, backend="fernet")
    v.set("A", "1")
    # The on-disk blob must decrypt to {"version":1,"secrets":{...}}
    raw = vault._fernet_unprotect(tmp_vault.read_bytes(), tmp_vault)
    parsed = json.loads(raw.decode("utf-8"))
    assert parsed["version"] == 1
    assert parsed["secrets"]["A"] == "1"
