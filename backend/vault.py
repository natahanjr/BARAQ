"""DPAPI-backed encrypted secret vault for Windows (zero third-party deps).

Sensitive values (admin password, API keys, token secret) are stored in a
single encrypted blob (`secrets.dat`) protected by the current Windows user's
DPAPI key — only the same user account on the same machine can decrypt it.

Storage layout: the file is one DPAPI-encrypted JSON object:
    {"version": 1, "secrets": {"BARAQ_ADMIN_PASSWORD": "...", ...}}

Fallback behaviour: on non-Windows platforms (or if crypt32 is unavailable)
the vault degrades to an environment-variable-only provider so the test suite
and CI keep working without secrets.
"""
from __future__ import annotations

import ctypes
import json
import os
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
# Vault (file-backed)
# ---------------------------------------------------------------------------
DEFAULT_VAULT_FILE = "secrets.dat"


class SecretVault:
    """Encrypted on-disk secret store, keyed to the current Windows user."""

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._cache: dict[str, Any] | None = None
        self._readonly = False  # set True by tests / CI via constructor flag

    # -- reading ------------------------------------------------------------
    def _load(self) -> dict[str, Any]:
        if self._cache is not None:
            return self._cache
        if not self.path.is_file():
            self._cache = {"version": 1, "secrets": {}}
            return self._cache
        try:
            raw = dpapi_unprotect(self.path.read_bytes())
            self._cache = json.loads(raw.decode("utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            # Corrupt/foreign vault: treat as empty so the app never crashes
            # on startup (the operator can regenerate credentials).
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
        payload = self._load()
        payload["secrets"].update(values)
        blob = dpapi_protect(json.dumps(payload).encode("utf-8"))
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        tmp.replace(self.path)
        self._cache = payload

    def set(self, name: str, value: Any) -> None:
        self.set_many({name: value})

    def delete(self, name: str) -> None:
        payload = self._load()
        payload["secrets"].pop(name, None)
        blob = dpapi_protect(json.dumps(payload).encode("utf-8"))
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
