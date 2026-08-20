"""Phase 6 risk evaluation (spec 6.56-6.58).

Runs the labeled corpus through the real risk engine with a fixed clock and
verifies every expected score/severity/state/trend/factor set. No accuracy
percentage is ever fabricated - the corpus measures the risk layer against
hand-computed expectations.
"""
from __future__ import annotations

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from backend.risk import engine
from backend.risk.evaluation_data import SCENARIOS
from backend.risk.metrics import risk_metrics
from backend.risk.models import (
    EntityRiskV2,
    EntityRiskV2AuditEvent,
    EntityRiskV2Factor,
)


def _table_count(db: Session, table: str) -> int:
    try:
        return db.scalars(
            select(func.count()).select_from(text(f'"{table}"'))
        ).one()
    except Exception:
        return -1


def _apply_step(db: Session, step: dict) -> None:
    """Apply one scenario step; evidence/replay/expire/recalculate/propagate."""
    at = step["at"]
    evidence = step.get("evidence") or []
    if step.get("replay"):
        for item in evidence:
            engine.ingest_evidence(db, [item], now=at, actor="evaluation")
    elif evidence:
        engine.ingest_evidence(db, evidence, now=at, actor="evaluation")

    if step.get("expire"):
        engine.expire_factors(db, now=at, actor="evaluation")

    for entity_key in step.get("recalculate_entities") or []:
        entity_type, entity_id = entity_key.split(":", 1)
        risk = engine.risk_for_entity(db, entity_type, entity_id)
        if risk is not None:
            engine.recalculate_entity(db, risk.risk_id, now=at, actor="evaluation")
            db.commit()

    propagate = step.get("propagate")
    if propagate:
        try:
            engine.apply_propagation(
                db,
                propagate["target_entity_type"],
                propagate["target_entity_id"],
                from_entity=propagate["from_entity"],
                relationship_type=propagate["relationship_type"],
                reason=propagate.get("reason", ""),
                now=at,
                actor="evaluation",
            )
        except ValueError:
            if not propagate.get("expect_error"):
                raise
        else:
            if propagate.get("expect_error"):
                raise AssertionError(
                    "expected propagation to reject an unregistered relationship"
                )


def _factors_of(db: Session, risk_id: str) -> list[str]:
    return list(
        db.scalars(
            select(EntityRiskV2Factor.factor_id)
            .where(EntityRiskV2Factor.risk_id == risk_id)
            .order_by(EntityRiskV2Factor.id)
        ).all()
    )


def _audit_actions(db: Session, risk_id: str) -> list[str]:
    return list(
        db.scalars(
            select(EntityRiskV2AuditEvent.action)
            .where(EntityRiskV2AuditEvent.risk_id == risk_id)
            .order_by(EntityRiskV2AuditEvent.id)
        ).all()
    )


def _check_scenario(db: Session, scenario: dict) -> dict:
    before = None
    if "metrics_delta" in scenario["expected"]:
        before = risk_metrics(db)
    for step in scenario["steps"]:
        _apply_step(db, step)
    db.commit()

    checks: dict[str, object] = {}
    for entity_key, expected in scenario["expected"].items():
        if ":" not in entity_key:
            continue
        entity_type, entity_id = entity_key.split(":", 1)
        risk = engine.risk_for_entity(db, entity_type, entity_id)
        if risk is None:
            raise AssertionError(
                f"{scenario['id']}: no risk record for {entity_key}"
            )
        if "score" in expected:
            checks["score"] = True
            actual = round(risk.score, 4)
            if abs(actual - expected["score"]) > 0.0001:
                raise AssertionError(
                    f"{scenario['id']}: {entity_key} score {actual} != "
                    f"{expected['score']}"
                )
        if "severity" in expected and risk.severity != expected["severity"]:
            raise AssertionError(
                f"{scenario['id']}: {entity_key} severity {risk.severity} != "
                f"{expected['severity']}"
            )
        if "state" in expected and risk.state != expected["state"]:
            raise AssertionError(
                f"{scenario['id']}: {entity_key} state {risk.state} != "
                f"{expected['state']}"
            )
        if "trend" in expected and risk.trend != expected["trend"]:
            raise AssertionError(
                f"{scenario['id']}: {entity_key} trend {risk.trend} != "
                f"{expected['trend']}"
            )
        if "confidence" in expected:
            checks["confidence"] = True
            if abs(risk.confidence - expected["confidence"]) > 0.0001:
                raise AssertionError(
                    f"{scenario['id']}: {entity_key} confidence "
                    f"{risk.confidence} != {expected['confidence']}"
                )
        if "peak_score" in expected and abs(risk.peak_score - expected["peak_score"]) > 0.0001:
            raise AssertionError(
                f"{scenario['id']}: {entity_key} peak {risk.peak_score} != "
                f"{expected['peak_score']}"
            )
        if "alert_count" in expected and risk.alert_count != expected["alert_count"]:
            raise AssertionError(
                f"{scenario['id']}: {entity_key} alert_count "
                f"{risk.alert_count} != {expected['alert_count']}"
            )
        if "group_count" in expected and risk.group_count != expected["group_count"]:
            raise AssertionError(
                f"{scenario['id']}: {entity_key} group_count "
                f"{risk.group_count} != {expected['group_count']}"
            )
        if "correlation_count" in expected and risk.correlation_count != expected["correlation_count"]:
            raise AssertionError(
                f"{scenario['id']}: {entity_key} correlation_count "
                f"{risk.correlation_count} != {expected['correlation_count']}"
            )
        if "model_version" in expected and risk.risk_model_version != expected["model_version"]:
            raise AssertionError(
                f"{scenario['id']}: {entity_key} model version "
                f"{risk.risk_model_version} != {expected['model_version']}"
            )
        factors = _factors_of(db, risk.risk_id)
        if "factor_count" in expected and len(factors) != expected["factor_count"]:
            raise AssertionError(
                f"{scenario['id']}: {entity_key} factor count {len(factors)} != "
                f"{expected['factor_count']}"
            )
        if "repetition_count" in expected:
            repetition = [
                f for f in factors if f == "RF007_REPETITION"
            ]
            if len(repetition) != expected["repetition_count"]:
                raise AssertionError(
                    f"{scenario['id']}: {entity_key} repetition count "
                    f"{len(repetition)} != {expected['repetition_count']}"
                )
        if "factors" in expected:
            if set(factors) != set(expected["factors"]):
                raise AssertionError(
                    f"{scenario['id']}: {entity_key} factors {factors} != "
                    f"{expected['factors']}"
                )
        if "crossed" in expected:
            crossed = list(
                db.scalars(
                    select(EntityRiskV2AuditEvent.details)
                    .where(
                        EntityRiskV2AuditEvent.risk_id == risk.risk_id,
                        EntityRiskV2AuditEvent.action == "RISK_THRESHOLD_CROSSED",
                    )
                    .order_by(EntityRiskV2AuditEvent.id)
                ).all()
            )
            severities = []
            for details in crossed:
                if details:
                    severities.extend(details.get("severities", []))
            if severities != expected["crossed"]:
                raise AssertionError(
                    f"{scenario['id']}: {entity_key} crossed {severities} != "
                    f"{expected['crossed']}"
                )
        if "audit_actions" in expected:
            actions = _audit_actions(db, risk.risk_id)
            for action in expected["audit_actions"]:
                if action not in actions:
                    raise AssertionError(
                        f"{scenario['id']}: {entity_key} missing audit action "
                        f"{action} (have {actions})"
                    )
        if "isolation" in expected:
            for table in expected["isolation"]:
                count = _table_count(db, table)
                if count != 0:
                    raise AssertionError(
                        f"{scenario['id']}: isolation broken - {table} has "
                        f"{count} rows after risk ingestion"
                    )
        if "metrics" in expected:
            metrics = risk_metrics(db)
            for key, value in expected["metrics"].items():
                if metrics.get(key) != value:
                    raise AssertionError(
                        f"{scenario['id']}: metric {key} = {metrics.get(key)} "
                        f"!= {value}"
                    )
        if "metrics_delta" in expected:
            after = risk_metrics(db)
            for key, delta in expected["metrics_delta"].items():
                actual = after.get(key, 0) - before.get(key, 0)
                if actual != delta:
                    raise AssertionError(
                        f"{scenario['id']}: metric delta {key} = {actual} "
                        f"!= {delta}"
                    )
        if entity_key == "HOST:h022":
            required = {
                "risk_id", "entity_type", "entity_id", "entity_name", "score",
                "severity", "state", "confidence", "trend", "first_seen",
                "last_seen", "active_factor_count", "evidence_count",
                "alert_count", "group_count", "correlation_count",
                "created_at", "updated_at", "last_calculated_at",
                "peak_score", "peak_at", "risk_model_version",
            }
            payload = risk.to_dict()
            missing = required - set(payload)
            if missing:
                raise AssertionError(
                    f"{scenario['id']}: to_dict missing {sorted(missing)}"
                )
    return checks


def run_evaluation(db: Session) -> dict:
    """Run every labeled scenario; raise on the first mismatch."""
    passed = 0
    for scenario in SCENARIOS:
        _check_scenario(db, scenario)
        passed += 1
    return {
        "scenarios": len(SCENARIOS),
        "passed": passed,
        "failed": len(SCENARIOS) - passed,
    }