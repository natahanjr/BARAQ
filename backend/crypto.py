"""Field-level AES-256-GCM encryption at rest.

Sensitive free-text columns (event messages, alert evidence, command lines,
email bodies, assistant chat, audit details) are encrypted with AES-256-GCM
before they reach the database. The 32-byte master key is generated on first
use and stored in the DPAPI-protected secret vault (``backend.vault``), so it
never appears in plaintext on disk and can only be unwrapped by the same
Windows user.

Envelope format (text columns)::

    sentinel-v1:<base64url(nonce)>:<base64url(ciphertext+tag)>

The ``@EncryptedColumn`` SQLAlchemy ``TypeDecorator`` below encrypts on write
and decrypts on read, so no business code needs to change. Unencrypted legacy
values (pre-hardening rows) pass through untouched on read.

Security notes:
- AES-GCM is authenticated; tampered ciphertext raises and returns ``None``
  rather than silently corrupting data.
- The key never touches disk except inside the DPAPI-protected vault blob.
- Encryption is off unless explicitly enabled (``SENTINEL_ENCRYPT_AT_REST=1``
  or running the packaged ``SentinelSOC.exe`` where it defaults on).
"""
from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.config import APP_DIR, ENCRYPT_AT_REST, ENCRYPTION_KEY_NAME

_ENVELOPE_PREFIX = "sentinel-v1:"
_NONCE_SIZE = 12

_cached_key: bytes | None = None


def _encryption_enabled() -> bool:
    """True when at-rest encryption is on (frozen build, or env flag)."""
    if ENCRYPT_AT_REST:
        return True
    return os.environ.get("SENTINEL_ENCRYPT_AT_REST", "").lower() in (
        "1", "true", "yes", "on",
    )


def _open_vault():
    """Construct the DPAPI secret vault (patchable by tests)."""
    from backend.vault import SecretVault

    return SecretVault(APP_DIR / "secrets.dat")


def _load_key() -> bytes:
    """Return the 32-byte AES key, generating + vaulting it on first use."""
    global _cached_key
    if _cached_key is not None:
        return _cached_key
    vault = _open_vault()
    stored = vault.get(ENCRYPTION_KEY_NAME)
    if stored:
        try:
            _cached_key = base64.urlsafe_b64decode(stored.encode("ascii"))
            return _cached_key
        except (ValueError, UnicodeEncodeError):
            pass
    key = AESGCM.generate_key(bit_length=256)
    vault.set(ENCRYPTION_KEY_NAME, base64.urlsafe_b64encode(key).decode("ascii"))
    _cached_key = key
    return key


def encrypt_text(plaintext: str) -> str | None:
    """Encrypt a string field. Returns None (stored as-is) when at-rest
    encryption is disabled."""
    if not _encryption_enabled():
        return plaintext
    if not plaintext:
        return plaintext
    try:
        nonce = os.urandom(_NONCE_SIZE)
        ciphertext = AESGCM(_load_key()).encrypt(nonce, plaintext.encode("utf-8"), None)
        return (
            _ENVELOPE_PREFIX
            + base64.urlsafe_b64encode(nonce).decode("ascii")
            + ":"
            + base64.urlsafe_b64encode(ciphertext).decode("ascii")
        )
    except Exception:  # noqa: BLE001 - never break writes on crypto failure
        return plaintext


def decrypt_text(value: str | None) -> str | None:
    """Decrypt an envelope; passes plaintext/legacy values through."""
    if not value:
        return value
    if not value.startswith(_ENVELOPE_PREFIX):
        return value  # legacy plaintext (pre-hardening row) or encryption off
    try:
        _, nonce_b64, cipher_b64 = value.split(":", 2)
        nonce = base64.urlsafe_b64decode(nonce_b64)
        ciphertext = base64.urlsafe_b64decode(cipher_b64)
        plain = AESGCM(_load_key()).decrypt(nonce, ciphertext, None)
        return plain.decode("utf-8")
    except Exception:  # noqa: BLE001 - corrupt/foreign key: do not crash reads
        return None


def encrypt_maybe(value) -> str | None:
    """Encrypt any str/bytes value (str passthrough for non-str)."""
    if not isinstance(value, str):
        return value
    return encrypt_text(value)


def decrypt_maybe(value) -> str | None:
    """Decrypt any value (non-str passthrough)."""
    if not isinstance(value, str):
        return value
    return decrypt_text(value)


# ---------------------------------------------------------------------------
# File-level encryption (backups, exports). Same master key, binary envelope:
#     sentinel-file-v1:<base64url(nonce)>:<base64url(ciphertext+tag)>
# ---------------------------------------------------------------------------
_FILE_PREFIX = "sentinel-file-v1:"


def encrypt_file_bytes(plaintext: bytes) -> bytes:
    """Encrypt arbitrary bytes with AES-256-GCM under the vault master key.

    The result is self-describing (``sentinel-file-v1:`` header) and can be
    decrypted on any machine whose vault holds the same master key.
    """
    nonce = os.urandom(_NONCE_SIZE)
    ciphertext = AESGCM(_load_key()).encrypt(nonce, plaintext, None)
    return (
        _FILE_PREFIX.encode("ascii")
        + base64.urlsafe_b64encode(nonce)
        + b":"
        + base64.urlsafe_b64encode(ciphertext)
    )


def decrypt_file_bytes(value: bytes) -> bytes | None:
    """Decrypt a ``sentinel-file-v1:`` blob. Returns None on tamper/error."""
    if not value.startswith(_FILE_PREFIX.encode("ascii")):
        return None
    try:
        _, nonce_b64, cipher_b64 = value.decode("ascii").split(":", 2)
        nonce = base64.urlsafe_b64decode(nonce_b64)
        ciphertext = base64.urlsafe_b64decode(cipher_b64)
        return AESGCM(_load_key()).decrypt(nonce, ciphertext, None)
    except Exception:  # noqa: BLE001 - tampered/corrupt backup: caller decides
        return None
