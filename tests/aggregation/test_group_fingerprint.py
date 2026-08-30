"""Phase 4 fingerprint tests (spec 4.7)."""

import uuid

from backend.aggregation.fingerprint import (
    group_fingerprint,
    normalized_source,
    primary_host,
    primary_user,
)
from tests.alerting.helpers import detection


def test_fingerprint_is_deterministic():
    a = detection(host="ml-host", user="ml-online-user", source_ip="185.100.1.5")
    b = detection(host="ml-host", user="ml-online-user", source_ip="185.100.1.5")
    assert group_fingerprint(a, "authentication") == group_fingerprint(
        b, "authentication"
    )


def test_fingerprint_depends_on_host_user_source_family():
    a = detection(host="ml-host", user="u", source_ip="1.1.1.1")
    base = group_fingerprint(a, "authentication")
    assert (
        group_fingerprint(
            detection(host="other", user="u", source_ip="1.1.1.1"), "authentication"
        )
        != base
    )
    assert (
        group_fingerprint(
            detection(host="ml-host", user="v", source_ip="1.1.1.1"), "authentication"
        )
        != base
    )
    assert (
        group_fingerprint(
            detection(host="ml-host", user="u", source_ip="2.2.2.2"), "authentication"
        )
        != base
    )
    assert (
        group_fingerprint(
            detection(host="ml-host", user="u", source_ip="1.1.1.1"), "execution"
        )
        != base
    )


def test_fingerprint_is_never_a_random_uuid():
    fp = group_fingerprint(detection(), "authentication")
    assert len(fp) == 64
    assert not any(fp == uuid.uuid4().hex for _ in range(5))


def test_primary_identity_extraction():
    a = detection(host="ml-host", user="ml-online-user")
    assert primary_host(a) == "ml-host"
    assert primary_user(a) == "ml-online-user"
    assert normalized_source(a) == "203.0.113.5"


def test_missing_identity_collapses_to_none():
    a = detection(host="", user="", source_ip="")
    assert primary_host(a) == "none"
    assert primary_user(a) == "none"
    assert normalized_source(a) == "none"
