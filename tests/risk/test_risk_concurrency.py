"""Phase 6 concurrency safety (spec 6.35, 6.59, 6.60, 6.87).

Concurrent ingestion - through separate sessions against the same
database - must never corrupt the risk store: exactly one risk row per
entity, no duplicate events/factors, and no unique-violation crashes even
when parallel inserts race for the same public id sequence.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import func, select

from backend.database.connection import SessionLocal
from backend.risk import engine
from backend.risk.models import EntityRiskV2Event, EntityRiskV2Factor

from tests.risk.helpers import alert_evidence, stored_risks


def test_concurrent_ingest_same_entity_is_safe(db):
    def ingest(index: int):
        session = SessionLocal()
        try:
            engine.apply_alert(
                session,
                alert_evidence(
                    f"ALR-CONC-{index:04d}",
                    "h-conc",
                    detector="D900",
                    severity="high",
                ),
            )
            session.commit()
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(ingest, range(16)))

    db.expire_all()
    risks = [
        r for r in stored_risks(db)
        if r.entity_type == "HOST" and r.entity_id == "h-conc"
    ]
    assert len(risks) == 1
    risk = risks[0]
    assert 1 <= risk.alert_count <= 16

    events = db.scalars(
        select(func.count()).select_from(EntityRiskV2Event).where(
            EntityRiskV2Event.risk_id == risk.risk_id
        )
    ).one()
    assert events == 16

    factors = db.scalars(
        select(EntityRiskV2Factor).where(
            EntityRiskV2Factor.risk_id == risk.risk_id
        )
    ).all()
    keys = {(f.factor_id, f.source_type, f.source_id) for f in factors}
    assert len(keys) == len(factors)

    db.expire(risk)
    assert 0.0 <= risk.score <= 100.0
    assert risk.severity in ("MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_concurrent_distinct_entities_no_collision(db):
    def ingest(index: int):
        session = SessionLocal()
        try:
            engine.apply_alert(
                session,
                alert_evidence(
                    f"ALR-DIST-{index:04d}",
                    f"h-{index:02d}",
                    severity="medium",
                ),
            )
            session.commit()
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(ingest, range(8)))

    db.expire_all()
    hosts = {
        r.entity_id for r in stored_risks(db) if r.entity_type == "HOST"
    }
    assert hosts == {f"h-{i:02d}" for i in range(8)}
    risks = stored_risks(db)
    assert {r.entity_type for r in risks} == {"HOST", "USER", "SOURCE_IP"}
    ids = [r.risk_id for r in risks]
    assert len(set(ids)) == len(ids)