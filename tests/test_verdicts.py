"""Analyst verdict (feedback loop) tests: label overrides, staleness, API."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from backend.analyzers.normalizer import Normalizer
from backend.database.models import NormalizedEvent, Verdict
from backend.ml.anomaly import MLAnomalyDetector, _load_behavior_features, _verdict_map
from backend.config import ML_RETRAIN_MIN_NEW_VERDICTS
from tests.fixtures import benign_baseline, ml_credential_spray, suspicious_powershell


@pytest.fixture
def v_session():
    """Isolated session for verdict/ML tests (PostgreSQL test database)."""
    from backend.database.connection import SessionLocal

    session = SessionLocal()
    yield session
    session.close()


def _seed(v_session, records):
    for r in records:
        v_session.add(NormalizedEvent(**Normalizer().normalize(r)))
    v_session.commit()


class TestVerdictLabels:
    def test_verdict_map_empty(self, v_session):
        assert _verdict_map(v_session) == {}

    def test_verdict_map_overrides(self, v_session):
        records = ml_credential_spray()
        _seed(v_session, records)
        ids = [e.id for e in v_session.scalars(select(NormalizedEvent)).all()]
        v_session.add(Verdict(event_id=ids[0], verdict="false_positive", created_by="tester"))
        v_session.add(Verdict(event_id=ids[1], verdict="true_positive", created_by="tester"))
        v_session.commit()
        mapping = _verdict_map(v_session)
        assert mapping[ids[0]] == 0
        assert mapping[ids[1]] == 1

    def test_labels_follow_verdict_not_heuristic(self, v_session):
        """Heuristic-attack events labelled false_positive must train as benign."""
        _seed(v_session, ml_credential_spray() + benign_baseline(30))
        ids_4625 = [
            e.id for e in v_session.scalars(select(NormalizedEvent)).all()
            if e.event_id == 4625
        ]
        assert ids_4625
        for eid in ids_4625:
            v_session.add(Verdict(event_id=eid, verdict="false_positive", created_by="tester"))
        v_session.commit()

        X, y = _load_behavior_features(
            v_session, datetime.now(timezone.utc) - timedelta(hours=24), {4625}, with_labels=True
        )
        rows = list(zip(X.tolist(), y.tolist()))
        assert len(rows) == len(ids_4625)
        assert all(yi == 0 for _, yi in rows), (
            "every verdict false_positive must override the heuristic attack label"
        )

    def test_train_accepts_verdict_labels(self, v_session):
        """Retraining with verdicts must complete and stay supervised."""
        _seed(v_session, ml_credential_spray() + suspicious_powershell() + benign_baseline(40))
        detector = MLAnomalyDetector()
        first = detector.train(v_session, hours=24, persist=False)
        assert first["trained"]

        ids = [e.id for e in v_session.scalars(select(NormalizedEvent).where(NormalizedEvent.event_id == 4625))]
        for eid in ids[:2]:
            v_session.add(Verdict(event_id=eid, verdict="false_positive", created_by="tester"))
        v_session.commit()

        second = MLAnomalyDetector()
        result = second.train(v_session, hours=24, persist=False)
        assert result["trained"]
        assert second.supervised_name
        assert set(second.supervised_name_by_stream).issubset({"login", "process", "network"})

    def test_cutoff_excludes_post_cutoff_events(self, v_session):
        """Baseline fits must not see events at/after the campaign cutoff."""
        now = datetime.now(timezone.utc)
        records = benign_baseline(20)
        _seed(v_session, records)
        later = suspicious_powershell()
        for r in later:
            r["timestamp"] = (now + timedelta(minutes=5)).isoformat()
        _seed(v_session, later)

        X, y = _load_behavior_features(
            v_session, now - timedelta(hours=24), {4104}, with_labels=True, cutoff=now + timedelta(minutes=1)
        )
        assert len(X) == 0, "events after cutoff must be excluded"

        X_all, _ = _load_behavior_features(v_session, now - timedelta(hours=24), {4104}, with_labels=True)
        assert len(X_all) == len(later)


class TestVerdictStaleness:
    def test_new_verdicts_trigger_retrain(self, v_session):
        _seed(v_session, benign_baseline(60) + suspicious_powershell())
        detector = MLAnomalyDetector()
        result = detector.train(v_session, hours=24, persist=False)
        assert result["trained"]

        # No new events are added - only ANALYST VERDICTS on already-seen
        # rows, so the verdict path (not the event-volume path) must fire.
        ids = [e.id for e in v_session.scalars(select(NormalizedEvent))][:ML_RETRAIN_MIN_NEW_VERDICTS]
        for eid in ids:
            v_session.add(Verdict(
                event_id=eid, verdict="true_positive",
                created_by="tester",
                created_at=datetime.now(timezone.utc) + timedelta(minutes=1),
            ))
        v_session.commit()

        stale, reason = detector.is_stale(v_session)
        assert stale
        assert "verdicts" in reason


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as test_client:
        yield test_client


class TestVerdictAPI:
    def test_record_and_list_verdicts(self, client):
        from backend.database.connection import SessionLocal

        db = SessionLocal()
        event_id = None
        try:
            record = suspicious_powershell()[0]
            event = NormalizedEvent(**Normalizer().normalize(record))
            db.add(event)
            db.commit()
            db.refresh(event)
            event_id = event.id

            resp = client.post("/api/ml/verdicts", json={
                "event_id": event_id,
                "verdict": "true_positive",
                "note": "confirmed via campaign",
            })
            assert resp.status_code == 200
            assert resp.json()["verdict"] == "true_positive"

            resp = client.post("/api/ml/verdicts", json={
                "event_id": event_id,
                "verdict": "false_positive",
                "note": "reconsidered",
            })
            assert resp.status_code == 200
            assert resp.json()["verdict"] == "false_positive"

            items = client.get("/api/verdicts").json()["items"]
            mine = [i for i in items if i["event_id"] == event_id]
            assert mine and mine[0]["verdict"] == "false_positive"
            assert mine[0]["event_type"] == event.event_id
        finally:
            if event_id is not None:
                for v in db.scalars(select(Verdict).where(Verdict.event_id == event_id)):
                    db.delete(v)
                event = db.get(NormalizedEvent, event_id)
                if event is not None:
                    db.delete(event)
            db.commit()
            db.close()

    def test_verdict_requires_existing_event(self, client):
        resp = client.post("/api/ml/verdicts", json={
            "event_id": 999_999_999,
            "verdict": "true_positive",
        })
        assert resp.status_code == 404

    def test_verdict_requires_valid_class(self, client):
        resp = client.post("/api/ml/verdicts", json={
            "event_id": 1,
            "verdict": "maybe",
        })
        assert resp.status_code == 422
