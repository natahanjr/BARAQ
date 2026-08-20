"""Phase 7 incident evaluation runner (spec 7.40)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from backend.incidents import engine
from backend.incidents.contract import INCIDENT_STATES
from backend.incidents.models import IncidentV2Evidence, IncidentV2
from backend.incidents.evaluation_data import SCENARIOS, EVAL_T0


def _run_step(db, step: dict, now: datetime) -> list[str]:
    groups = step.get("groups", [])
    findings = step.get("findings", [])
    risks = step.get("risks", [])
    alerts = step.get("alerts", [])
    policy_id = step.get("policy_id", "I001")
    created_ids: list[str] = []

    if step.get("concurrent"):
        def _ingest(_idx: int) -> str | None:
            from backend.database.connection import SessionLocal
            session = SessionLocal()
            try:
                res = engine.create_incident(
                    session,
                    groups=groups,
                    findings=findings,
                    risks=risks,
                    alerts=alerts,
                    policy_id=policy_id,
                    now=now,
                )
                session.commit()
                return res.get("incident_id")
            except Exception:  # noqa: BLE001
                session.rollback()
                return None
            finally:
                session.close()

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(_ingest, range(4)))
        return [r for r in results if r]

    repeat = step.get("repeat", 1)
    for _ in range(repeat):
        res = engine.create_incident(
            db,
            groups=groups,
            findings=findings,
            risks=risks,
            alerts=alerts,
            policy_id=policy_id,
            now=now,
        )
        iid = res.get("incident_id")
        if iid:
            created_ids.append(iid)
            if step.get("close_after"):
                engine.transition_incident(db, iid, "CLOSED", actor="evaluation", reason="close for reopen test")
            if step.get("suppress_after"):
                engine.suppress_incident(
                    db,
                    iid,
                    reason="evaluation suppression",
                    scope="incident",
                    expires_at=now + timedelta(days=30),
                    created_by="evaluation",
                )
    return created_ids


def run_evaluation(db) -> dict[str, Any]:
    passed = 0
    for scenario in SCENARIOS:
        db.rollback()
        created_ids: list[str] = []
        for step in scenario.get("steps", []):
            now = step.get("at", EVAL_T0)
            created_ids.extend(_run_step(db, step, now))
        db.commit()

        expected = scenario.get("expected", {})
        try:
            if expected.get("incident_created") is False:
                if created_ids:
                    raise AssertionError(f"{scenario['id']}: expected no incident, got {created_ids}")
            elif expected.get("incidents_created") is not None:
                if len(set(created_ids)) != expected["incidents_created"]:
                    raise AssertionError(
                        f"{scenario['id']}: expected {expected['incidents_created']} incidents, got {len(set(created_ids))}"
                    )
            else:
                if not created_ids:
                    raise AssertionError(f"{scenario['id']}: expected incident, got none")
                incident = db.scalars(
                    select(IncidentV2).where(IncidentV2.incident_id == created_ids[0])
                ).first()
                if incident is None:
                    raise AssertionError(f"{scenario['id']}: incident not found")
                if "policy_id" in expected and incident.policy_id != expected["policy_id"]:
                    raise AssertionError(
                        f"{scenario['id']}: policy {incident.policy_id} != {expected['policy_id']}"
                    )
                if "severity" in expected and incident.severity != expected["severity"]:
                    raise AssertionError(
                        f"{scenario['id']}: severity {incident.severity} != {expected['severity']}"
                    )
                if "priority" in expected and incident.priority != expected["priority"]:
                    raise AssertionError(
                        f"{scenario['id']}: priority {incident.priority} != {expected['priority']}"
                    )
                if "status" in expected and incident.status != expected["status"]:
                    raise AssertionError(
                        f"{scenario['id']}: status {incident.status} != {expected['status']}"
                    )
                if expected.get("entity_count") is not None:
                    actual = len(incident.entity_ids or [])
                    if actual != expected["entity_count"]:
                        raise AssertionError(
                            f"{scenario['id']}: entity_count {actual} != {expected['entity_count']}"
                        )
                if expected.get("evidence_count") is not None:
                    actual = db.scalars(
                        select(func.count()).select_from(IncidentV2Evidence).where(
                            IncidentV2Evidence.incident_id == incident.incident_id
                        )
                    ).one()
                    if actual != expected["evidence_count"]:
                        raise AssertionError(f"{scenario['id']}: evidence_count {actual} != {expected['evidence_count']}")
            passed += 1
        except AssertionError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(f"{scenario['id']}: {exc}") from exc
    return {"scenarios": len(SCENARIOS), "passed": passed, "failed": len(SCENARIOS) - passed}


