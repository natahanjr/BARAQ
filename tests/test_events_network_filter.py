"""Structural test: /api/network direction filter does not pull ``limit*4`` rows.

The previous implementation fetched ``limit * 4`` candidate rows from
PostgreSQL and dropped up to 75 % of them in Python. This test pins the
new behaviour by reading ``backend/api/events.py`` as plain text and
asserting on the literal source of ``list_network``.

We deliberately do NOT import backend.api.events -- importing it pulls
in the database engine (create_engine) which fails without Postgres.
This structural test runs anywhere, in any CI slice, with no DB.
"""

from __future__ import annotations

from pathlib import Path

_SRC = (Path(__file__).resolve().parents[1] / "backend" / "api" / "events.py").read_text(
    encoding="utf-8"
)


def _list_network_source() -> str:
    """Return the source of the list_network function only, comments stripped.

    We strip # comments so a future contributor who references the old
    behaviour in a comment does not break the regression test.
    """
    start = _SRC.find("def list_network(")
    assert start >= 0, "list_network not found"
    lines = _SRC[start:].splitlines()
    out: list[str] = []
    base_indent: int | None = None
    for line in lines:
        if base_indent is None and line.strip():
            base_indent = len(line) - len(line.lstrip())
        if (
            base_indent is not None
            and line
            and not line.startswith(" " * base_indent)
            and line.strip()
        ):
            # Dedented below base_indent -- the function ended.
            break
        # Drop inline / full-line comments so the test inspects code only.
        if "#" in line:
            # Naive strip: only the first '#' if not inside a string.
            code = line.split("#", 1)[0]
            if code.strip():
                out.append(code)
        else:
            out.append(line)
    return "\n".join(out)


def test_list_network_does_not_overfetch_limit_times_4():
    """The function body must not call ``.limit(limit * 4)``."""
    src = _list_network_source()
    assert "limit * 4" not in src, (
        "list_network still over-fetches; expected a paging loop, not a single "
        "limit * 4 query"
    )


def test_list_network_uses_iterative_paging():
    """Confirm the new implementation pages through results in batches."""
    src = _list_network_source()
    assert ".offset(" in src, "list_network must use SQL OFFSET to page"
    assert "max_pages" in src, (
        "list_network must bound the number of DB round-trips with max_pages"
    )


def test_list_network_does_not_use_like_substring():
    """The old SQL LIKE '172.2%' filters are gone.

    Replacement: Python-side classification via ``_is_private_remote_ip``
    (which uses ``ipaddress.is_global``).
    """
    src = _list_network_source()
    assert ".like(" not in src, (
        "list_network should not use SQL LIKE; classify in Python instead"
    )


def test_list_network_signature_unchanged():
    """Endpoint signature must keep ``limit``, ``remote_ip``, ``since``, ``direction``."""
    src = _list_network_source()
    assert "limit: int = Query(" in src
    assert "remote_ip: str | None = None" in src
    assert "since: str | None = None" in src
    assert "direction: str | None = None" in src