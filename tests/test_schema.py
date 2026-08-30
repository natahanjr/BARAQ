"""Database migration + default-value regression tests.

Covers the additive in-place migrations (so an older schema upgrades
cleanly), the verdict->event foreign key, and the entity-graph upsert
semantics (accumulating counters, preserving first_seen).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import inspect


def _column_names(engine, table: str) -> set[str]:
    return {c["name"] for c in inspect(engine).get_columns(table)}


class TestAdditiveMigrations:
    def test_events_migrates_analytics_columns(self, db):
        """Old DBs lacking ml_* / is_anomaly columns must be upgraded in place."""
        from backend.database.connection import _ADDITIVE_MIGRATIONS, init_db

        expected = {c for c, _ in _ADDITIVE_MIGRATIONS.get("events", [])}
        assert {"risk_score", "is_anomaly", "ml_score"} <= expected
        init_db()
        cols = _column_names(db.get_bind(), "events")
        assert {"risk_score", "is_anomaly", "ml_score"} <= cols

    def test_users_migrates_last_login(self, db):
        from backend.database.connection import _ADDITIVE_MIGRATIONS, init_db

        expected = {c for c, _ in _ADDITIVE_MIGRATIONS.get("users", [])}
        assert "last_login_at" in expected
        init_db()
        cols = _column_names(db.get_bind(), "users")
        assert "last_login_at" in cols
        assert "totp_secret" in cols


class TestVerdictForeignKey:
    def test_verdict_reference_exists(self, db):
        """Verdicts must declare a FK to events so pruning cascades."""
        from backend.database.connection import init_db

        init_db()
        ins = inspect(db.get_bind())
        fks = {
            (fk["constrained_columns"][0], fk["referred_table"])
            for fk in ins.get_foreign_keys("verdicts")
        }
        assert ("event_id", "events") in fks

    def test_delete_event_cascades_verdict(self, db):
        from backend.database.models import NormalizedEvent, Verdict

        event = NormalizedEvent(
            event_id=4625,
            category="authentication",
            user="alice",
            host="HOST",
            risk_score=10,
            timestamp=datetime.now(UTC) - timedelta(minutes=5),
        )
        db.add(event)
        db.flush()
        db.add(
            Verdict(event_id=event.id, verdict="false_positive", created_by="tester")
        )
        db.commit()
        verdict_id = db.query(Verdict).first().id

        db.delete(event)
        db.commit()

        assert db.get(Verdict, verdict_id) is None


class TestGraphUpsertSemantics:
    def test_counts_accumulate_and_first_seen_preserved(self, db):
        from backend.database.models import EntityNode
        from backend.graph.postgres import PostgresStore

        store = PostgresStore()
        t0 = datetime.now(UTC) - timedelta(hours=2)
        t1 = datetime.now(UTC) - timedelta(hours=1)
        t2 = datetime.now(UTC)

        store.upsert_entities(
            db,
            [
                {
                    "kind": "user",
                    "name": "alice",
                    "display_name": "User: alice",
                    "risk_score": 10.0,
                    "alerts_count": 1,
                    "events_count": 5,
                    "first_seen": t0,
                    "last_seen": t1,
                }
            ],
        )
        store.upsert_entities(
            db,
            [
                {
                    "kind": "user",
                    "name": "alice",
                    "display_name": "User: alice",
                    "risk_score": 10.0,
                    "alerts_count": 2,
                    "events_count": 3,
                    "first_seen": t1,
                    "last_seen": t2,
                }
            ],
            accumulate=True,
        )

        def as_utc(dt):  # some drivers return naive UTC datetimes
            return dt.replace(tzinfo=UTC) if dt and dt.tzinfo is None else dt

        node = db.query(EntityNode).filter_by(kind="user", name="alice").one()
        assert node.events_count == 8, "counts must accumulate across batches"
        assert node.alerts_count == 3
        assert as_utc(node.first_seen) == t0, "first_seen must never move forward"
        assert as_utc(node.last_seen) == t2

    def test_edge_weight_accumulates(self, db):
        from backend.database.models import EntityEdge
        from backend.graph.postgres import PostgresStore

        store = PostgresStore()
        store.upsert_edges(
            db,
            [
                {
                    "src_kind": "user",
                    "src_name": "alice",
                    "rel": "LOGON_ON",
                    "dst_kind": "device",
                    "dst_name": "WS-1",
                    "weight": 4,
                }
            ],
            accumulate=True,
        )
        store.upsert_edges(
            db,
            [
                {
                    "src_kind": "user",
                    "src_name": "alice",
                    "rel": "LOGON_ON",
                    "dst_kind": "device",
                    "dst_name": "WS-1",
                    "weight": 1,
                }
            ],
            accumulate=True,
        )

        edge = (
            db.query(EntityEdge)
            .filter_by(
                src_kind="user",
                src_name="alice",
                rel="LOGON_ON",
                dst_kind="device",
                dst_name="WS-1",
            )
            .one()
        )
        assert edge.weight == 5

    def test_sync_replaces_totals(self, db):
        """Full sync (accumulate=False) replaces counters like a rebuild."""
        from backend.database.models import EntityNode
        from backend.graph.postgres import PostgresStore

        store = PostgresStore()
        store.upsert_entities(
            db,
            [
                {
                    "kind": "user",
                    "name": "bob",
                    "alerts_count": 1,
                    "events_count": 9,
                }
            ],
            accumulate=True,
        )
        store.upsert_entities(
            db,
            [
                {
                    "kind": "user",
                    "name": "bob",
                    "alerts_count": 4,
                    "events_count": 20,
                }
            ],
        )

        node = db.query(EntityNode).filter_by(kind="user", name="bob").one()
        assert node.events_count == 20
