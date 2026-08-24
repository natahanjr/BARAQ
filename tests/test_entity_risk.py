"""Tests for the Entity Risk-Based Alerting (RBA) engine."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from backend.database.models import Alert, EntityRisk, EntityRiskEvent
from backend.risk.entity_risk import EntityRiskManager, risk_level


def _mk_alert(
    db,
    rule: str = "brute_force",
    host: str = "WS-01",
    risk_score: float = 55.0,
    mitre_id: str = "T1110",
    severity: str = "high",
    evidence: str = "User 'admin' failed to log on",
) -> Alert:
    alert = Alert(
        name=f"{rule} detection",
        description="test",
        severity=severity,
        status="open",
        confidence=0.8,
        score=7,
        evidence=evidence,
        rule=rule,
        host=host,
        org="",
        event_count=1,
        risk_score=risk_score,
        risk_level="HIGH",
        mitre_id=mitre_id,
        mitre_tactic="Credential Access",
    )
    db.add(alert)
    db.flush()
    return alert


def test_apply_alert_accumulates_on_entities(db):
    manager = EntityRiskManager(db)
    alert = _mk_alert(db, risk_score=55.0, evidence="User 'admin' failed to log on from 10.0.0.9")
    touched = manager.apply_alert(alert)

    assert len(touched) == 3  # host + user + ip
    by_kind = {e.entity_kind: e for e in touched}
    assert by_kind["host"].score == 55.0
    assert by_kind["user"].score == 55.0
    assert by_kind["ip"].score == 55.0
    events = db.query(EntityRiskEvent).all()
    assert len(events) == 3
    db.commit()


def test_accumulation_adds_across_alerts(db):
    manager = EntityRiskManager(db)
    a1 = _mk_alert(db, risk_score=30.0, evidence="User 'admin' failed to log on")
    a2 = _mk_alert(db, rule="persistence", risk_score=45.0, evidence="User 'admin' created run key")
    manager.apply_alert(a1)
    manager.apply_alert(a2)

    row = db.query(EntityRisk).filter_by(entity_kind="user", entity_name="admin").one()
    assert row.score == 75.0
    assert row.alerts_count == 2
    assert row.risk_level == "HIGH"
    db.commit()


def test_rule_risk_weights_modify_contribution(db, monkeypatch):
    from backend.config import RULE_RISK_WEIGHTS

    monkeypatch.setitem(RULE_RISK_WEIGHTS, "brute_force", 2.0)
    manager = EntityRiskManager(db)
    alert = _mk_alert(db, rule="brute_force", risk_score=20.0, evidence="User 'bob'")
    touched = manager.apply_alert(alert)
    assert touched[0].score == 40.0  # 20 x 2.0
    monkeypatch.setitem(RULE_RISK_WEIGHTS, "brute_force", 1.0)
    db.commit()


def test_decay_halves_score_after_half_life(db):
    manager = EntityRiskManager(db)
    alert = _mk_alert(db, risk_score=90.0, evidence="User 'carol'")
    manager.apply_alert(alert)
    row = db.query(EntityRisk).filter_by(entity_kind="user", entity_name="carol").one()

    # Half-life is 7 days (ENTITY_RISK_DECAY_DAYS): simulate 7 days elapsed.
    row.last_updated = datetime.now(timezone.utc) - timedelta(days=7)
    db.flush()
    manager.decay()
    db.refresh(row)
    assert row.score == 45.0  # 90 * 0.5^1

    # Another half-life -> 22.5
    row.last_updated = datetime.now(timezone.utc) - timedelta(days=7)
    db.flush()
    manager.decay()
    db.refresh(row)
    assert row.score == pytest.approx(22.5)
    db.commit()


def test_decay_resets_level(db):
    manager = EntityRiskManager(db)
    alert = _mk_alert(db, risk_score=90.0, evidence="User 'dave'")
    manager.apply_alert(alert)
    row = db.query(EntityRisk).filter_by(entity_kind="user", entity_name="dave").one()
    assert row.risk_level == "CRITICAL"
    row.last_updated = datetime.now(timezone.utc) - timedelta(days=28)
    db.flush()
    manager.decay()
    db.refresh(row)
    assert row.score < 10
    assert row.risk_level == "LOW"
    db.commit()


def test_escalate_creates_notable_alert(db):
    manager = EntityRiskManager(db)
    alert = _mk_alert(db, host="", risk_score=95.0, evidence="User 'erin'")
    manager.apply_alert(alert)
    created = manager.escalate(org="")
    assert len(created) == 1
    notable = created[0]
    assert notable.rule == "entity_risk"
    assert notable.name == "Entity Risk Escalation: erin"
    assert notable.severity == "critical"
    assert "erin" in notable.evidence

    # Re-escalation within the window refreshes, does not duplicate.
    alert2 = _mk_alert(db, host="", rule="lsass_dump", risk_score=50.0, evidence="User 'erin'")
    manager.apply_alert(alert2)
    again = manager.escalate(org="")
    assert again == []
    assert (
        db.query(Alert)
        .filter_by(rule="entity_risk", name="Entity Risk Escalation: erin")
        .count()
        == 1
    )
    db.commit()


def test_escalate_skips_low_risk(db):
    manager = EntityRiskManager(db)
    alert = _mk_alert(db, risk_score=10.0, evidence="User 'frank'")
    manager.apply_alert(alert)
    assert manager.escalate(org="") == []
    db.commit()


def test_leaderboard_sorted_and_filtered(db):
    manager = EntityRiskManager(db)
    for name, score in (("low_user", 20.0), ("high_user", 90.0), ("mid_user", 50.0)):
        manager.apply_alert(
            _mk_alert(db, host="", risk_score=score, evidence=f"User '{name}'")
        )
    rows = manager.leaderboard(org="", limit=10)
    assert [r.entity_name for r in rows] == ["high_user", "mid_user", "low_user"]
    highs = manager.leaderboard(org="", min_level="HIGH", limit=10)
    assert [r.entity_name for r in highs] == ["high_user"]
    users = manager.leaderboard(org="", kind="user", limit=10)
    assert all(r.entity_kind == "user" for r in users)
    db.commit()


def test_profile_and_timeline(db):
    manager = EntityRiskManager(db)
    a1 = _mk_alert(db, risk_score=30.0, evidence="User 'grace'")
    a2 = _mk_alert(db, rule="wmi_execution", risk_score=40.0, evidence="User 'grace'")
    manager.apply_alert(a1)
    manager.apply_alert(a2)

    profile = manager.profile("user", "grace")
    assert profile is not None and profile.score == 70.0
    timeline = manager.timeline("user", "grace")
    assert [e.delta for e in timeline] == [30.0, 40.0]
    assert timeline[1].score_after == 70.0
    db.commit()


def test_risk_level_helper():
    assert risk_level(0) == "LOW"
    assert risk_level(39.9) == "LOW"
    assert risk_level(40) == "MEDIUM"
    assert risk_level(65) == "HIGH"
    assert risk_level(85) == "CRITICAL"


# ---------------------------------------------------------------------------
# analyst-feedback fixes: idempotency, level-gated escalation, MITRE truth
# ---------------------------------------------------------------------------

def test_apply_alert_is_idempotent_per_alert(db):
    """P0: the same alert must never contribute risk twice - repeated calls
    (dedup refresh, backfill sweep, scheduler re-run) are no-ops."""
    manager = EntityRiskManager(db)
    alert = _mk_alert(db, risk_score=55.0, evidence="User 'idem' failed to log on from 10.0.0.9")

    first = manager.apply_alert(alert)
    again = manager.apply_alert(alert)
    third = manager.apply_alert(alert)

    assert len(first) == 3  # host + user + ip
    assert again == []
    assert third == []
    row = db.query(EntityRisk).filter_by(entity_kind="user", entity_name="idem").one()
    assert row.score == 55.0
    assert row.alerts_count == 1
    events = db.query(EntityRiskEvent).filter(
        EntityRiskEvent.alert_id == alert.id
    ).all()
    assert len(events) == 3  # one contribution per entity, never more
    db.commit()


def test_sweep_is_idempotent(db):
    """P0: the backfill sweep must not double-count alerts already folded."""
    manager = EntityRiskManager(db)
    _mk_alert(db, risk_score=40.0, evidence="User 'sweep'")
    db.commit()

    assert manager.sweep_entities_from_events(hours=24, org="") == 2  # host + user
    assert manager.sweep_entities_from_events(hours=24, org="") == 0
    assert manager.sweep_entities_from_events(hours=24, org="") == 0
    row = db.query(EntityRisk).filter_by(entity_kind="user", entity_name="sweep").one()
    assert row.score == 40.0
    assert row.alerts_count == 1
    db.commit()


def test_escalation_new_alert_only_on_level_change(db):
    """P0: same-level climbs refresh, a level CROSS creates exactly one new
    alert - no pile of identical escalation alerts for one entity."""
    manager = EntityRiskManager(db)
    manager.apply_alert(_mk_alert(db, risk_score=70.0, evidence="User 'lev'"))  # HIGH

    def notables():
        return (
            db.query(Alert)
            .filter_by(rule="entity_risk", name="Entity Risk Escalation: lev")
            .all()
        )

    created1 = manager.escalate(org="")
    assert len(notables()) == 1  # host + user both escalate, but only one 'lev'
    assert created1[0].severity == "high" or any(a.name.endswith("lev") for a in created1)

    # Same level, more detections: refresh, never duplicate.
    manager.apply_alert(_mk_alert(db, rule="persistence", risk_score=10.0, evidence="User 'lev'"))
    assert manager.escalate(org="") == []
    assert len(notables()) == 1

    # Crosses into CRITICAL: exactly one new alert for the climb.
    manager.apply_alert(_mk_alert(db, rule="lsass_dump", risk_score=30.0, evidence="User 'lev'"))
    created2 = manager.escalate(org="")
    assert created2, "level cross must create a fresh notable"
    assert len(notables()) == 2
    assert notables()[-1].severity == "critical"
    db.commit()


def test_escalation_reopens_when_no_open_notable(db):
    """The level-gate keeps a single alert per level band even when the
    previous notable was closed by triage."""
    manager = EntityRiskManager(db)
    manager.apply_alert(_mk_alert(db, risk_score=95.0, evidence="User 'reopen'"))
    created = manager.escalate(org="")
    assert created
    for alert in created:  # host and user both escalate; close all for the entity
        if alert.name.endswith("reopen"):
            alert.status = "closed"
    db.commit()

    # Level unchanged, notable closed: refresh it back to open, no duplicate.
    manager.apply_alert(_mk_alert(db, rule="persistence", risk_score=5.0, evidence="User 'reopen'"))
    assert manager.escalate(org="") == []
    notables = (
        db.query(Alert)
        .filter_by(rule="entity_risk", name="Entity Risk Escalation: reopen")
        .all()
    )
    assert len(notables) == 1
    assert notables[0].status == "open"
    db.commit()


def test_escalation_mitre_derived_from_contributions(db):
    """P0: the notable's MITRE technique comes from the contributions that
    actually built the risk, never a hardcoded default."""
    manager = EntityRiskManager(db)
    manager.apply_alert(_mk_alert(db, risk_score=40.0, mitre_id="T1110", evidence="User 'mitre'"))
    manager.apply_alert(_mk_alert(db, rule="kerberoast", risk_score=30.0, mitre_id="T1558.003", evidence="User 'mitre'"))
    manager.apply_alert(_mk_alert(db, rule="kerberoast", risk_score=30.0, mitre_id="T1558.003", evidence="User 'mitre'"))

    created = manager.escalate(org="")
    notable = next(a for a in created if a.name == "Entity Risk Escalation: mitre")
    assert notable.mitre_id == "T1558.003"  # most frequent contributor technique
    assert notable.mitre_name  # resolved from MITRE data, not placeholder
    assert "T1110" in notable.evidence
    assert "T1558.003" in notable.evidence
    assert notable.mitre_id != "T1071"
    db.commit()


def test_demo_propagation_through_risk_store(db):
    """Demo alerts must tag their entities, events and notables so production
    views can exclude them; a production alert must not inherit demo."""
    manager = EntityRiskManager(db)
    demo_alert = _mk_alert(db, risk_score=95.0, evidence="User 'demo-user'")
    demo_alert.demo = True
    manager.apply_alert(demo_alert)
    db.commit()

    row = db.query(EntityRisk).filter_by(entity_kind="user", entity_name="demo-user").one()
    assert row.demo is True
    ev = db.query(EntityRiskEvent).filter_by(entity_kind="user", entity_name="demo-user").one()
    assert ev.demo is True

    created = manager.escalate(org="")
    assert any(a.name == "Entity Risk Escalation: demo-user" for a in created)
    demo_notable = next(a for a in created if a.name == "Entity Risk Escalation: demo-user")
    assert demo_notable.demo is True
    assert demo_notable.correlation_id.startswith("CORR-")
    db.commit()


def test_correlation_ids_are_unique_and_traceable(db):
    manager = EntityRiskManager(db)
    ids = set()
    for name in ("c1", "c2", "c3"):
        manager.apply_alert(_mk_alert(db, risk_score=90.0, evidence=f"User '{name}'"))
        created = manager.escalate(org="")
        user_notable = next(a for a in created if a.name == f"Entity Risk Escalation: {name}")
        cid = user_notable.correlation_id
        assert cid.startswith("CORR-")
        ids.add(cid)
    assert len(ids) == 3
    db.commit()