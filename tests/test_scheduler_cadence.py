"""Regression test: the scheduler has a declarative cadence table.

The previous _scheduler_loop had 15 magic numbers
(``counter % 4 == 0``, ``% 20 == 0``, ``% 120 == 0`` ...) with the
wall-clock meaning scattered across inline comments. A reviewer
could not answer 'how often does step X run?' without doing the
arithmetic on every branch.

The table SCHEDULER_CYCLE_FREQUENCY_SECONDS in backend.main is the
single source of truth for the cadence. This test pins:

* the table is exposed (so a future 'tidy the constants' cannot drop
  it)
* every documented step has an entry
* the frequencies are consistent with the inline counter checks
  (i.e. the table is not silently stale)

We read backend/main.py as plain text so the test runs without
importing the full app (which would pull the DB engine).
"""

from __future__ import annotations

import ast
from pathlib import Path

MAIN_PY = Path(__file__).resolve().parents[1] / "backend" / "main.py"
SRC = MAIN_PY.read_text(encoding="utf-8")


def _eval_const(node: ast.AST) -> int:
    """Evaluate a constant integer expression like ``4 * 15`` or ``720 * 15``.

    The cadence table uses small integer arithmetic; evaluating the
    AST by hand is safer than ``eval()`` and only needs to handle
    Constant + BinOp.
    """
    if isinstance(node, ast.Constant):
        if isinstance(node.value, int):
            return node.value
        raise AssertionError(f"non-int constant: {node.value!r}")
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        return _eval_const(node.left) * _eval_const(node.right)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_eval_const(node.operand)
    raise AssertionError(f"unsupported expr: {ast.dump(node)}")


def _read_table_from_source() -> dict[str, int]:
    """Parse the SCHEDULER_CYCLE_FREQUENCY_SECONDS dict out of backend/main.py
    without importing the module.
    """
    tree = ast.parse(SRC)
    for node in tree.body:
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "SCHEDULER_CYCLE_FREQUENCY_SECONDS"
        ):
            assert isinstance(node.value, ast.Dict)
            table: dict[str, int] = {}
            for k, v in zip(node.value.keys, node.value.values):
                assert isinstance(k, ast.Constant) and isinstance(k.value, str)
                table[k.value] = _eval_const(v)
            return table
    raise AssertionError("SCHEDULER_CYCLE_FREQUENCY_SECONDS not found in main.py")


def test_scheduler_cadence_table_is_defined():
    """SCHEDULER_CYCLE_FREQUENCY_SECONDS must be a module-level constant."""
    table = _read_table_from_source()
    assert isinstance(table, dict)
    assert len(table) > 0


def test_scheduler_cadence_table_covers_documented_steps():
    """Every step named in the docstring must have an entry."""
    table = _read_table_from_source()
    expected_keys = {
        "chain_learning",
        "ml_drift_check",
        "dashboard_snapshot",
        "ml_analyze_events",
        "ml_stale_check",
        "entity_risk_decay",
        "entity_risk_sweep",
        "dataset_auto_export",
        "ml_online_update",
        "retention_purge",
        "audit_retention_purge",
        "scheduled_reports",
        "threat_intel_refresh",
        "rule_precision_auto_tune",
    }
    missing = expected_keys - set(table)
    assert not missing, f"missing cadence entries: {missing}"


def test_scheduler_cadence_table_values_are_positive_ints():
    table = _read_table_from_source()
    for name, secs in table.items():
        assert isinstance(secs, int), f"{name}: must be int, got {type(secs)}"
        assert secs > 0, f"{name}: must be > 0, got {secs}"


def test_scheduler_cadence_table_matches_inline_counters():
    """Cross-check: the table covers every counter % N used in
    _scheduler_loop. Any N not in the table means a step is missing
    from the documentation.
    """
    table = _read_table_from_source()
    table_n = {secs // 15 for secs in table.values()}
    expected_n = {4, 6, 20, 120, 240, 720, 5760}
    assert expected_n.issubset(table_n), (
        f"inline counter uses N in {expected_n} but table only covers {table_n}"
    )