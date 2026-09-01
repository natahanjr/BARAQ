"""Unit tests for ``backend.api.events._is_private_remote_ip``.

The helper replaces a fragile SQL LIKE-based direction filter that
misclassified public address space as private. Pinning the behaviour
here protects against future regressions.

These tests are pure (no DB, no app startup) so they can run in CI
without a Postgres service.
"""

from __future__ import annotations

from backend.api.events import _is_private_remote_ip


def test_rfc1918_v4_is_private():
    for ip in ("10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
               "192.168.0.1", "192.168.255.255"):
        assert _is_private_remote_ip(ip) is True, ip


def test_public_v4_is_not_private():
    # 172.32.0.0/11 is a PUBLIC allocation that the legacy LIKE filter
    # falsely flagged as private (it matched the '172.3%' prefix). The
    # stdlib ipaddress module gives the correct answer here.
    for ip in ("172.32.0.1", "172.40.0.1", "172.63.255.254",
               "8.8.8.8", "1.1.1.1"):
        assert _is_private_remote_ip(ip) is False, ip


def test_documentation_prefix_is_internal():
    # 203.0.113.0/24 is TEST-NET-3 (RFC5737) - not routable, treat as
    # internal even though it is not RFC1918.
    assert _is_private_remote_ip("203.0.113.1") is True


def test_loopback_is_private():
    assert _is_private_remote_ip("127.0.0.1") is True
    assert _is_private_remote_ip("127.255.255.254") is True


def test_ipv6_loopback_and_unique_local_are_private():
    assert _is_private_remote_ip("::1") is True
    assert _is_private_remote_ip("fd00::1") is True
    assert _is_private_remote_ip("fe80::1") is True


def test_invalid_inputs_return_false():
    assert _is_private_remote_ip("") is False
    assert _is_private_remote_ip("not-an-ip") is False
    assert _is_private_remote_ip("999.999.999.999") is False


def test_zero_network_is_treated_as_reserved():
    # 0.0.0.0/8 is "this network" (RFC1122) - bucket as internal.
    assert _is_private_remote_ip("0.0.0.0") is True