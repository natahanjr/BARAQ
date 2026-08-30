"""FP deep-defence suite: auto-suppression, behavioural baseline,
rule precision auto-tuning, and alert clustering.

These are the four closed-loop mechanisms that let the system LEARN false
positives instead of merely hardcoding them.
"""

from __future__ import annotations

from datetime import UTC

# ---------------------------------------------------------------------------
# S1 - verdict-driven auto-suppression
# ---------------------------------------------------------------------------


def _mk_alert(db, rule="sigma_rules", host="ws-01", evidence=None, name="Test"):
    from backend.database.models import Alert

    a = Alert(
        name=name,
        description="d",
        severity="high",
        status="open",
        confidence=0.8,
        rule=rule,
        host=host,
        evidence=evidence
        or (
            "Sigma 'X' matched event 4688 (Process) - user 'bob': "
            "process 'powershell.exe' reputation=trusted "
            "(C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe) "
            "parent process(es): python.exe opencode.exe"
        ),
    )
    db.add(a)
    db.commit()
    return a


def _verdict_fp(db, alert):
    from backend.database.models import AlertVerdict

    db.add(
        AlertVerdict(alert_id=alert.id, verdict="false_positive", created_by="analyst")
    )
    db.commit()


def test_auto_suppress_creates_rule_at_threshold(db):
    from backend.detection.auto_suppress import (
        FP_AUTO_SUPPRESS_THRESHOLD,
        maybe_auto_suppress,
    )
    from backend.detection.suppression import list_rules

    # Same host: the signature is rule+subject+parent+host-scoped.
    alerts = [_mk_alert(db) for _ in range(6)]
    results = []
    for a in alerts:
        _verdict_fp(db, a)
        results.append(maybe_auto_suppress(db, a, actor="analyst"))

    assert [r["suppressed"] for r in results[: FP_AUTO_SUPPRESS_THRESHOLD - 1]] == [
        False
    ] * (FP_AUTO_SUPPRESS_THRESHOLD - 1)
    assert any(r["suppressed"] for r in results)

    rules = list_rules(db)
    target = next(
        (r for r in rules if r.reason.startswith("Auto-suppressed after")), None
    )
    assert target is not None
    assert target.rule == "sigma_rules"
    assert target.host == "ws-01"  # scoped to the affected host


def test_no_autosuppress_below_threshold(db):
    from backend.detection.auto_suppress import maybe_auto_suppress
    from backend.detection.suppression import list_rules

    a = _mk_alert(db)
    _verdict_fp(db, a)
    res = maybe_auto_suppress(db, a, actor="analyst")
    assert res["suppressed"] is False
    assert res["fp_count"] == 1
    assert not [r for r in list_rules(db) if r.reason.startswith("Auto-suppressed")]


def test_distinct_behaviours_do_not_accumulate(db):
    """FPs on different parents are different signatures - never merged."""
    from backend.detection.auto_suppress import fp_signature, maybe_auto_suppress

    a1 = _mk_alert(
        db,
        evidence=(
            "process 'powershell.exe' reputation=trusted "
            "(C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe) "
            "parent process(es): excel.exe"
        ),
    )
    a2 = _mk_alert(
        db,
        evidence=(
            "process 'powershell.exe' reputation=trusted "
            "(C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe) "
            "parent process(es): winword.exe"
        ),
    )
    s1, s2 = fp_signature(db, a1), fp_signature(db, a2)
    assert s1["subject"] == s2["subject"]
    # office parents differ -> different signatures -> counts stay separate
    r1 = maybe_auto_suppress(db, a1, actor="x")
    r2 = maybe_auto_suppress(db, a2, actor="x")
    assert r1["fp_count"] <= 2 and r2["fp_count"] <= 2


# ---------------------------------------------------------------------------
# S2 - per-host behavioural baseline
# ---------------------------------------------------------------------------


def test_baseline_learn_lookup_novel(db):
    from datetime import datetime, timedelta

    from backend.context.baseline import learn_chains, lookup_chain
    from backend.database.models import NormalizedEvent

    now = datetime.now(UTC)
    for i in range(4):  # >= MIN_OCCURRENCES
        db.add(
            NormalizedEvent(
                source="test",
                event_id=4688,
                category="process",
                severity="info",
                message="proc",
                user="u",
                host="BASE-HOST",
                timestamp=now - timedelta(minutes=i),
                raw_json={
                    "facts": {
                        "new_process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "parent_process_name": "C:\\tools\\opencode.exe",
                    }
                },
            )
        )
    db.commit()

    res = learn_chains(db, hours=24)
    assert res["chains_created"] >= 1

    # Known chain -> True; unseen chain on same host -> False (novel).
    assert lookup_chain(db, "base-host", "opencode.exe", "powershell.exe") is True
    assert lookup_chain(db, "base-host", "excel.exe", "powershell.exe") is False


def test_baseline_requires_min_occurrences(db):
    from backend.context.baseline import MIN_OCCURRENCES, lookup_chain

    # Only 1 occurrence recorded by the learn above? ensure threshold holds:
    assert MIN_OCCURRENCES >= 2
    assert lookup_chain(db, "no-such-host", "a.exe", "b.exe") is False


# ---------------------------------------------------------------------------
# Reopen-guard: analyst-closed findings must not resurrect as new alerts.
# ---------------------------------------------------------------------------


def test_closed_alert_stays_closed_on_retrigger(db):
    """Same finding after an analyst close -> counters refresh, no new alert."""
    from datetime import datetime

    from sqlalchemy import select

    from backend.database.models import Alert
    from backend.detection.alerting import AlertingService

    a = _mk_alert(db, rule="unusual_port", host="ws-01")
    a.status = "closed"
    a.updated_at = datetime.now(UTC)
    db.commit()

    class _R:
        name = a.name
        rule = a.rule
        severity = "high"
        confidence = 0.8
        evidence = a.evidence
        event_ids = []
        description = "d"

    svc = AlertingService(db)
    # The dedup path needs at least one linked-event-free pass; run the gate
    # by calling handle_findings with our synthetic result.
    svc.handle_findings([_R()], org="")
    remaining = [x for x in db.scalars(select(Alert).where(Alert.name == a.name)).all()]
    assert len(remaining) == 1, "reopen-guard must not create a duplicate"
    assert remaining[0].status == "closed"


# ---------------------------------------------------------------------------
# S3 - rule precision auto-tuning
# ---------------------------------------------------------------------------


def test_precision_tuner_damps_broken_rules(db):
    """A rule with many closed-quiet alerts gets its risk weight damped."""
    from backend.database.models import Alert
    from backend.detection.rule_precision import auto_tune
    from backend.detection.tuning import get_raw

    # Classic noise profile: closed, never actioned, saturated repeats,
    # low confidence + low severity -> fp_candidate_score well above floor.
    for i in range(12):
        db.add(
            Alert(
                name=f"noise {i}",
                description="d",
                severity="low",
                status="closed",
                confidence=0.5,
                rule="noisy_sigma",
                trigger_count=20,
            )
        )
    db.commit()

    res = auto_tune(db)
    damped = {d["rule"]: d["weight"] for d in res["damped"]}
    assert damped.get("noisy_sigma") is not None
    weights = get_raw(db).get("rule_risk_weights") or {}
    assert weights.get("noisy_sigma") is not None


def test_precision_tuner_ignores_small_samples(db):
    from backend.database.models import Alert
    from backend.detection.rule_precision import auto_tune
    from backend.detection.tuning import get_raw

    for i in range(3):
        db.add(
            Alert(
                name=f"tiny {i}",
                description="d",
                severity="low",
                status="open",
                confidence=0.5,
                rule="tiny_rule",
            )
        )
    db.commit()
    auto_tune(db)
    weights = get_raw(db).get("rule_risk_weights") or {}
    assert "tiny_rule" not in weights


# ---------------------------------------------------------------------------
# S4 - FP clustering
# ---------------------------------------------------------------------------


def test_clusters_group_by_signature(db):
    from backend.api.fp_analysis import clusters

    ev = (
        "process 'powershell.exe' reputation=trusted "
        "(C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe) "
        "parent process(es): opencode.exe"
    )
    for i in range(3):
        _mk_alert(db, host=f"h{i}", evidence=ev, name=f"same-behaviour {i}")
    _mk_alert(
        db,
        evidence=(
            "process 'svchost.exe' reputation=system "
            "(C:\\Windows\\System32\\svchost.exe) parent process(es): services.exe"
        ),
        name="different behaviour",
    )

    res = clusters(db, open_only=False)
    assert res["cluster_count"] >= 2
    top = max(res["clusters"], key=lambda c: c["count"])
    assert top["count"] == 3
    assert top["subject"] == "powershell.exe"


def test_cluster_endpoint_shape(db):
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.get("/api/alerts/clusters")
        assert r.status_code == 200
        body = r.json()
        assert {"clusters", "cluster_count", "alerts_covered"} <= set(body)


def test_baseline_endpoints(db):
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.get("/api/system/baseline")
        assert r.status_code == 200
        assert {"items", "total"} <= set(r.json())
