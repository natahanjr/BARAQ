"""The reported build version must match the released version.

``/api/version`` reported ``0.13.0`` while the project was at 1.0.8. A stale
version endpoint is worse than none: an operator checking a deployment is told
it is running a build that old, and a support conversation starts from a false
premise. This test parses ``CHANGELOG.md`` so the two cannot drift apart again.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"

#: `## [1.0.8] - 2026-09-27 - "Production readiness hardening"`
_RELEASE_HEADER = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.MULTILINE)


def _latest_released_version() -> str:
    """Highest version in the changelog, by numeric tuple rather than string.

    String ordering would put ``1.0.9`` above ``1.0.10`` and, worse, ``0.13.0``
    above ``1.0.8``.
    """
    versions = _RELEASE_HEADER.findall(CHANGELOG.read_text(encoding="utf-8"))
    assert versions, "no release headers found in CHANGELOG.md"
    return max(versions, key=lambda v: tuple(int(p) for p in v.split(".")))


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app) as c:
        yield c


def test_version_endpoint_matches_changelog(client):
    reported = client.get("/api/version").json()["version"]
    expected = _latest_released_version()
    assert reported == expected, (
        f"/api/version reports {reported} but CHANGELOG.md's latest release is "
        f"{expected}. Update the endpoint in backend/main.py when cutting a "
        f"release, or the two will drift."
    )


def test_changelog_parser_is_numeric():
    """Guard the guard: 0.13.0 must sort below 1.0.8, not above it."""
    assert _latest_released_version() == "1.0.8"
