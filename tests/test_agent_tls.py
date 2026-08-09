"""Agent TLS transport tests: certificate pinning and lab-mode skip."""
from __future__ import annotations

import shutil
import ssl
from pathlib import Path

import pytest

from scripts.agent import make_tls_context

ROOT = Path(__file__).resolve().parent.parent


def test_default_context_no_tls_for_http():
    assert make_tls_context() is None


def test_tls_ca_pins_certificate(tmp_path):
    src = ROOT / "certs" / "sentinel.crt"
    if not src.exists():
        pytest.skip("certs/sentinel.crt not present")
    pem = tmp_path / "sentinel.crt"
    shutil.copyfile(src, pem)
    ctx = make_tls_context(tls_ca=str(pem))
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_no_verify_disables_verification():
    ctx = make_tls_context(no_verify=True)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_missing_ca_file_raises():
    with pytest.raises(FileNotFoundError):
        make_tls_context(tls_ca="does-not-exist.pem")