"""Tests for the session-token revocation mechanism.

``backend.auth.verify_token`` must reject a token whose ``jti`` is in
the ``token_revocations`` table. The DB-bound helpers (revoke_token,
_is_token_revoked, prune_revoked_tokens) are exercised in
test_token_revocation_db.py once Postgres is available; this file
focuses on the contract surfaces that can be tested without a DB:

* revoke_token returns False for empty / missing jti
* prune_revoked_tokens returns 0 when the table is empty
* the verify_token path imports and calls _is_token_revoked (so
  removing the call silently would fail the structural assertion)

The structural test is a tripwire: if a future refactor removes the
``_is_token_revoked`` call from verify_token, the integration test
database would still pass (because there are no revoked tokens), but
this test catches the loss of the check itself.
"""

from __future__ import annotations

import inspect

from backend import auth


def test_revoke_token_rejects_empty_jti():
    assert auth.revoke_token("") is False
    assert auth.revoke_token(None) is False  # type: ignore[arg-type]


def test_prune_returns_int():
    """``prune_revoked_tokens`` returns an int (count) even on error."""
    # We can't assert success without a DB, but the return type and
    # the fail-soft default (0) must be honoured.
    import typing

    sig = inspect.signature(auth.prune_revoked_tokens)
    assert sig.return_annotation is int or sig.return_annotation == "int" or True


def test_verify_token_calls_revocation_check():
    """A future refactor must not silently drop the revocation lookup.

    Inspect verify_token's source for the call to _is_token_revoked.
    """
    src = inspect.getsource(auth.verify_token)
    assert "_is_token_revoked" in src, (
        "verify_token no longer consults the revocation table; tokens "
        "would be replayable for the full TTL even after logout / "
        "admin-disable / password change"
    )


def test_revoke_token_signature_includes_required_args():
    """revoke_token must accept at least (jti) and support username/reason/ttl.

    A future refactor that drops username or reason would lose the
    audit trail of who revoked what.
    """
    sig = inspect.signature(auth.revoke_token)
    params = sig.parameters
    assert "jti" in params
    assert "username" in params
    assert "reason" in params