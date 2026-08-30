"""Safe dotted-version comparison for CVE range matching."""

from __future__ import annotations

import re

_TOKEN_RE = re.compile(r"(\d+|[a-zA-Z]+)")


def _tokens(version: str) -> list[tuple[int, int | str]]:
    parts: list[tuple[int, int | str]] = []
    for token in _TOKEN_RE.findall(version.lower()):
        if token.isdigit():
            parts.append((1, int(token)))
        else:
            parts.append((0, token))
    return parts


def compare_versions(a: str, b: str) -> int:
    """Return -1 / 0 / 1 for a < b, a == b, a > b (numeric-aware)."""
    ta = _tokens(a)
    tb = _tokens(b)
    for left, right in zip(ta, tb):
        if left != right:
            return -1 if left < right else 1
    return (len(ta) > len(tb)) - (len(ta) < len(tb))


def version_lt(installed: str, upper_exclusive: str) -> bool:
    return compare_versions(installed, upper_exclusive) < 0


def version_in(installed: str, lower_inclusive: str, upper_exclusive: str) -> bool:
    return (
        compare_versions(installed, lower_inclusive) >= 0
        and compare_versions(installed, upper_exclusive) < 0
    )
