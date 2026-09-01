"""Regression test: AUTH_TOKEN_SECRET auto-generation is observable.

The previous behaviour silently generated a random 32-byte token
secret in non-production when BARAQ_TOKEN_SECRET was unset. Every
restart invalidated all outstanding session tokens, but the operator
had no log line to tell them why their browser session dropped.

This test pins two contracts:

* the module exposes ``AUTH_TOKEN_SECRET_AUTO_GENERATED`` as a public
  boolean so other modules (e.g. a future /api/system/health
  endpoint) can surface the issue
* the auto-generation path emits a WARNING log line that names the
  two env vars the operator must set
"""

from __future__ import annotations

import inspect

from backend import config


def test_auth_token_secret_auto_generated_is_exported():
    """The flag must be a public module attribute."""
    assert hasattr(config, "AUTH_TOKEN_SECRET_AUTO_GENERATED")
    assert isinstance(config.AUTH_TOKEN_SECRET_AUTO_GENERATED, bool)


def test_auth_token_secret_is_set():
    """Even when auto-generated, the secret is a non-empty string."""
    assert isinstance(config.AUTH_TOKEN_SECRET, str)
    assert len(config.AUTH_TOKEN_SECRET) > 0


def test_config_source_warns_on_auto_generation():
    """The auto-generation path must include a WARNING log call.

    Inspect the source to confirm the warning is wired in -- a future
    'tidy the config module' pass must not silently drop it.
    """
    src = inspect.getsource(config)
    # The auto-generation path with the warning.
    assert "AUTH_TOKEN_SECRET_AUTO_GENERATED" in src
    assert "_logging.getLogger" in src or "getLogger" in src
    assert "BARAQ_TOKEN_SECRET" in src
    assert "WARNING" in src.upper()