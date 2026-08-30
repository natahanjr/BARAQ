"""Encrypted secret vault with a cross-platform backend.

Sensitive values (admin password, API keys, token secret) are stored in a
single encrypted blob (`secrets.dat`):

* **Windows** — protected by the current user's DPAPI key (crypt32) so only
  the same user account on the same machine can decrypt it. Zero third-party
  dependencies.
* **Other platforms** — protected with AES-256-GCM via ``cryptography``
  (Fernet), keyed by a machine-local key file (`secrets.key`) generated once
  next to the vault. This closes the previously-open gap where the vault
  raised ``RuntimeError`` off-Windows and silently stored nothing.

Storage layout: the file is one encrypted JSON object:
    {"version": 1, "secrets": {"BARAQ_ADMIN_PASSWORD": "...", ...}}

Set ``BARAQ_VAULT_ENFORCED=1`` to refuse to boot when no encryption backend is
available (fail-closed) instead of degrading to plaintext.
"""

from __future__ import annotations

import ctypes
import json
import os
import stat
from ctypes import wintypes
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Windows DPAPI primitives (crypt32)
# ---------------------------------------------------------------------------
_CRYPTPROTECT_UI_FORBIDDEN = 0x1
_crypt32 = None
_is_windows = os.name == "nt"


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _load_crypt32():
    """Load crypt32.dll once; returns None on non-Windows platforms."""
    global _crypt32
    if _crypt32 is None and _is_windows:
        try:
            _crypt32 = ctypes.windll.crypt32
        except (AttributeError, OSError):
            _crypt32 = False
    return _crypt32


def _to_blob(data: bytes) -> _DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _from_blob(blob: _DATA_BLOB) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        if blob.pbData:
            ctypes.windll.kernel32.LocalFree(blob.pbData)


def dpapi_protect(data: bytes) -> bytes:
    """Encrypt bytes with DPAPI (current user scope)."""
    if not isinstance(data, bytes):
        raise TypeError("dpapi_protect expects bytes")
    crypt = _load_crypt32()
    if not crypt:
        raise RuntimeError("DPAPI is only available on Windows")
    blob_in = _to_blob(data)
    blob_out = _DATA_BLOB()
    ok = crypt.CryptProtectData(
        ctypes.byref(blob_in),
        None,  # description
        None,  # optional entropy
        None,  # reserved
        None,  # prompt struct
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(blob_out),
    )
    if not ok:
        raise OSError(f"CryptProtectData failed (error {ctypes.get_last_error()})")
    return _from_blob(blob_out)


def dpapi_unprotect(blob: bytes) -> bytes:
    """Decrypt a DPAPI blob created by the same Windows user."""
    crypt = _load_crypt32()
    if not crypt:
        raise RuntimeError("DPAPI is only available on Windows")
    blob_in = _to_blob(blob)
    blob_out = _DATA_BLOB()
    ok = crypt.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,  # description
        None,  # entropy
        None,  # reserved
        None,  # prompt struct
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(blob_out),
    )
    if not ok:
        raise OSError(f"CryptUnprotectData failed (error {ctypes.get_last_error()})")
    return _from_blob(blob_out)


# ---------------------------------------------------------------------------
# Cross-platform fallback: AES-256-GCM (Fernet) keyed by a machine-local key
# ---------------------------------------------------------------------------
#: Force a specific backend ("dpapi" | "fernet" | "plain"). Used by tests and
#: to pin behaviour regardless of platform auto-detection.
_FORCE_BACKEND: str | None = None


def _load_fernet():
    """Import Fernet lazily so Windows installs never pay the import cost."""
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import serialization  # noqa: F401
    except Exception:  # pragma: no cover - cryptography is a hard dependency
        return None
    return Fernet


#: Raised by Fernet.decrypt on a corrupt / tampered / foreign-key blob. It is
#: NOT an OSError, so the empty-vault fallback must list it explicitly.
try:
    from cryptography.fernet import InvalidToken
except Exception:  # pragma: no cover - cryptography is a required dependency

    class InvalidToken(Exception):  # type: ignore[no-redef]
        """Fallback so the except tuple stays valid if cryptography is missing."""


def _fernet_key_path(vault_path: Path) -> Path:
    return vault_path.with_name("secrets.key")


def _restrict_key_file(key_path: Path) -> None:
    """Lock the Fernet key file to the current user only.

    On Windows we set an explicit DACL granting just the owner SID (via the
    Win32 API) so the encryption key is never readable by other accounts - the
    previous ``os.chmod(0o600)`` was a no-op there, and ``icacls
    /inheritance:r`` proved too aggressive (it could strip the owner's own
    access). On other platforms a 0o600 chmod is sufficient. Any failure is
    best-effort: the default file ACL (user + admins on a normal profile) is
    left intact rather than being torn down.
    """
    try:
        if os.name == "nt":
            import ntsecuritycon as ntc  # type: ignore[import-untyped]
            import win32api  # type: ignore[import-untyped]
            import win32security  # type: ignore[import-untyped]

            username = win32api.GetUserNameEx(win32api.NameSamCompatible)
            sid, _domain, _type = win32security.LookupAccountName(None, username)
            dacl = win32security.ACL()
            dacl.Initialize()
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                ntc.FILE_ALL_ACCESS,
                sid,
            )
            sd = win32security.SECURITY_DESCRIPTOR()
            sd.Initialize()
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                str(key_path),
                win32security.DACL_SECURITY_INFORMATION,
                sd,
            )
        else:
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as exc:
        import logging

        logging.getLogger("baraq.vault").warning(
            "Could not restrict vault key file permissions (%s): %s", key_path, exc
        )


def _load_or_create_fernet_key(vault_path: Path) -> bytes:
    """Return the Fernet key, generating and ACL-locking it on first use."""
    key_path = _fernet_key_path(vault_path)
    if key_path.is_file():
        return key_path.read_bytes().strip()
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    key_path.write_bytes(key)
    _restrict_key_file(key_path)
    return key


def _fernet_protect(data: bytes, vault_path: Path) -> bytes:
    from cryptography.fernet import Fernet

    key = _load_or_create_fernet_key(vault_path)
    return Fernet(key).encrypt(data)


def _fernet_unprotect(blob: bytes, vault_path: Path) -> bytes:
    from cryptography.fernet import Fernet

    key = _load_or_create_fernet_key(vault_path)
    return Fernet(key).decrypt(blob)


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------
#: "plain" backend stores secrets unencrypted (only when no crypto is
#: available and the operator has not enforced the vault).
def _select_backend() -> str:
    if _FORCE_BACKEND:
        return _FORCE_BACKEND
    if os.name == "nt" and _load_crypt32():
        return "dpapi"
    if _load_fernet():
        return "fernet"
    return "plain"


# ---------------------------------------------------------------------------
# Vault (file-backed)
# ---------------------------------------------------------------------------
DEFAULT_VAULT_FILE = "secrets.dat"

#: When "1", the vault refuses to operate without an encryption backend.
VAULT_ENFORCED = os.environ.get("BARAQ_VAULT_ENFORCED", "0").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
#: Opt-in escape hatch: when "1", allow the (unsafe) plaintext backend to
#: actually persist secrets. Default is fail-closed - the plaintext backend
#: raises rather than writing cleartext to disk.
VAULT_ALLOW_PLAINTEXT = os.environ.get("BARAQ_VAULT_ALLOW_PLAINTEXT", "0").lower() in (
    "1",
    "true",
    "yes",
    "on",
)


class SecretVault:
    """Encrypted on-disk secret store, backend chosen by platform.

    - Windows (+crypt32): DPAPI (current user scope)
    - Other platforms (+cryptography): Fernet AES-256-GCM with a local key file
    - No crypto available: plaintext (warning unless ``VAULT_ENFORCED``)
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        readonly: bool = False,
        backend: str | None = None,
    ):
        self.path = Path(path)
        self._readonly = readonly
        self._cache: dict[str, Any] | None = None
        self._backend = backend or _select_backend()
        if self._backend == "plain" and (VAULT_ENFORCED or not VAULT_ALLOW_PLAINTEXT):
            raise RuntimeError(
                "Secret vault is not encrypted (no DPAPI or cryptography backend) "
                "and will not store secrets in plaintext. Install 'cryptography' "
                "(non-Windows) or run on Windows for DPAPI, or set "
                "BARAQ_VAULT_ALLOW_PLAINTEXT=1 to override this fail-closed default."
            )

    # -- crypto primitives per backend -------------------------------------
    def _protect(self, data: bytes) -> bytes:
        if self._backend == "dpapi":
            return dpapi_protect(data)
        if self._backend == "fernet":
            return _fernet_protect(data, self.path)
        return data  # plain

    def _unprotect(self, blob: bytes) -> bytes:
        if self._backend == "dpapi":
            return dpapi_unprotect(blob)
        if self._backend == "fernet":
            return _fernet_unprotect(blob, self.path)
        return blob  # plain

    # -- reading ------------------------------------------------------------
    def _load(self) -> dict[str, Any]:
        if self._cache is not None:
            return self._cache
        if not self.path.is_file():
            self._cache = {"version": 1, "secrets": {}}
            return self._cache
        try:
            raw = self._unprotect(self.path.read_bytes())
            self._cache = json.loads(raw.decode("utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError, InvalidToken):
            # Corrupt/foreign/tampered vault: treat as empty so the app never
            # crashes on startup (the operator can regenerate credentials).
            self._cache = {"version": 1, "secrets": {}}
        return self._cache

    def get(self, name: str, default: str | None = None) -> str | None:
        secrets = self._load().get("secrets", {})
        value = secrets.get(name)
        return str(value) if value is not None else default

    def all(self) -> dict[str, str]:
        return dict(self._load().get("secrets", {}))

    def has(self, name: str) -> bool:
        return name in self._load().get("secrets", {})

    # -- writing ------------------------------------------------------------
    def set_many(self, values: dict[str, Any]) -> None:
        """Encrypt and persist a batch of secrets (atomic via temp file)."""
        if self._readonly:
            raise RuntimeError("vault is opened read-only")
        payload = self._load()
        payload["secrets"].update(values)
        blob = self._protect(json.dumps(payload).encode("utf-8"))
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        tmp.replace(self.path)
        self._cache = payload

    def set(self, name: str, value: Any) -> None:
        self.set_many({name: value})

    def delete(self, name: str) -> None:
        if self._readonly:
            raise RuntimeError("vault is opened read-only")
        payload = self._load()
        payload["secrets"].pop(name, None)
        blob = self._protect(json.dumps(payload).encode("utf-8"))
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        tmp.replace(self.path)
        self._cache = payload


def get_vault_path() -> Path:
    """Vault lives next to the app's .env (project root in dev, exe dir when frozen)."""
    if getattr(__import__("sys"), "frozen", False):
        root = Path(getattr(__import__("sys"), "executable", "")).resolve().parent
    else:
        root = Path(__file__).resolve().parent.parent
    return root / DEFAULT_VAULT_FILE
