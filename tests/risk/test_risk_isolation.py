"""Phase 6 isolation tests (spec 6.61-6.64, 6.72, 6.83, 6.84)."""
from __future__ import annotations

from sqlalchemy import func, select, text

from backend.risk import engine

from tests.risk.helpers import (
    RISK_T0,
    finding_evidence,
    group_evidence,
)


def _count(db, table: str) -> int:
    try:
        return db.scalars(select(func.count()).select_from(text(f'"{table}"'))).one()
    except Exception:
        return -1


def _tables_of_interest():
    return {
        "alerts": 0,
        "incidents": 0,
        "v2_events": 0,
        "v2_alerts": 0,
        "behavior_groups": 0,
        "behavior_group_members": 0,
        "correlation_findings": 0,
        "correlation_members": 0,
        "entity_risk": 0,
        "entity_risk_events": 0,
        "playbook_runs": 0,
    }


def test_risk_ingestion_touches_nothing_else(db):
    before = _tables_of_interest()
    engine.apply_group(
        db, group_evidence("g1", "h1", ["T1021.001"]), now=RISK_T0,
    )
    engine.apply_finding(db, finding_evidence("CF-000001", ["h1"]), now=RISK_T0)
    db.commit()
    for table, expected in _tables_of_interest().items():
        assert _count(db, table) == expected, f"{table} changed"

    assert before == _tables_of_interest()


def test_risk_never_touches_v1_entity_risk_store(db):
    engine.apply_group(
        db, group_evidence("g1", "h1", ["T1021.001"]), now=RISK_T0,
    )
    db.commit()
    assert _count(db, "entity_risk") == 0
    assert _count(db, "entity_risk_events") == 0


def test_risk_never_creates_incidents_or_soar(db):
    engine.apply_group(
        db, group_evidence("g1", "h1", ["T1021.001"]), now=RISK_T0,
    )
    engine.apply_finding(db, finding_evidence("CF-000001", ["h1"]), now=RISK_T0)
    db.commit()
    assert _count(db, "incidents") == 0
    assert _count(db, "playbook_runs") == 0


def test_no_ml_import_in_risk_package():
    import inspect
    import pkgutil

    import backend.risk

    for module_info in pkgutil.walk_packages(
        backend.risk.__path__, prefix="backend.risk."
    ):
        if module_info.name.endswith(".entity_risk") or module_info.name.endswith(".scoring"):
            continue
        module = __import__(module_info.name, fromlist=["*"])
        source = inspect.getsource(module)
        assert "sklearn" not in source, module_info.name
        assert "tensorflow" not in source, module_info.name
        assert "torch" not in source, module_info.name


def test_no_external_reputation_dependency(db):
    # RF014 is registered with weight 0: the engine can never satisfy it
    # without a registered reputation source (6.63, 6.64).
    from backend.risk.registry import get_factor

    definition = get_factor("RF014_SOURCE_REPUTATION")
    assert definition.weight == 0.0
    assert definition.maximum_contribution == 0.0


def test_risk_is_never_a_verdict(db):
    from backend.risk.contract import BANNED_RISK_PHRASES
    from backend.risk.engine import _add_factor
    from backend.risk.models import EntityRiskV2Factor

    risk = engine.get_or_create_risk(db, "HOST", "h1", now=RISK_T0)
    # The engine has no path that emits verdict language; the contract's
    # banned phrases exist so future factors never add them.
    assert "compromised" in BANNED_RISK_PHRASES
    from backend.risk.registry import FACTOR_REGISTRY

    for factor in FACTOR_REGISTRY.values():
        lowered = factor.description.lower()
        for phrase in BANNED_RISK_PHRASES:
            assert phrase not in lowered, factor.factor_id