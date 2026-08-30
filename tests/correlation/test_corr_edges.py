"""Phase 5 relationship detection tests (spec 5.20-5.22)."""

from datetime import UTC, datetime

from backend.correlation.edges import edge_strength, meets_minimum, pair_relationships
from backend.correlation.windows import within_window

T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=UTC)


def _summary(**overrides):
    base = {
        "id": "BG-000001",
        "family": "authentication",
        "hosts": ["host-a"],
        "users": ["alice"],
        "sources": ["203.0.113.5"],
        "destinations": ["10.0.0.9"],
        "techniques": ["T1110"],
        "first_seen": T0,
        "last_seen": T0,
    }
    base.update(overrides)
    return base


def test_same_host_user_source_and_temporal():
    a = _summary(id="BG-000001", first_seen=T0)
    b = _summary(
        id="BG-000002", first_seen=T0 + __import__("datetime").timedelta(minutes=5)
    )
    rel = pair_relationships(a, b, window_key="multi_stage", within_window=None)
    assert "SAME_HOST" in rel["types"]
    assert "SAME_USER" in rel["types"]
    assert "SAME_SOURCE" in rel["types"]
    assert "TEMPORAL" in rel["types"]
    assert meets_minimum(rel)


def test_destination_relation_and_network_relation():
    a = _summary(id="BG-000001", destinations=["10.0.0.9"], first_seen=T0)
    b = _summary(
        id="BG-000002",
        hosts=["10.0.0.9"],
        destinations=["10.0.0.9"],
        first_seen=T0 + __import__("datetime").timedelta(minutes=5),
    )
    rel = pair_relationships(a, b, window_key="multi_stage", within_window=None)
    assert "DESTINATION_RELATION" in rel["types"]
    assert "NETWORK_RELATION" in rel["types"]


def test_no_relationship_without_shared_context():
    a = _summary(
        id="BG-000001",
        hosts=["host-a"],
        users=["alice"],
        sources=["1.1.1.1"],
        destinations=["10.0.0.9"],
        first_seen=T0,
    )
    b = _summary(
        id="BG-000002",
        hosts=["host-b"],
        users=["bob"],
        sources=["2.2.2.2"],
        destinations=["10.0.0.8"],
        first_seen=T0 + __import__("datetime").timedelta(minutes=5),
    )
    rel = pair_relationships(a, b, window_key="multi_stage", within_window=None)
    assert "TEMPORAL" in rel["types"]
    assert not meets_minimum(rel)


def test_technique_transition_only_within_family():
    a = _summary(id="BG-000001", techniques=["T1110"], first_seen=T0)
    b = _summary(id="BG-000002", techniques=["T1621"], first_seen=T0)
    rel = pair_relationships(a, b, window_key="multi_stage", within_window=None)
    assert "TECHNIQUE_TRANSITION" in rel["types"]

    c = _summary(
        id="BG-000003", family="execution", techniques=["T1059.001"], first_seen=T0
    )
    rel = pair_relationships(a, c, window_key="multi_stage", within_window=None)
    assert "TECHNIQUE_TRANSITION" not in rel["types"]


def test_tactic_transition_on_progression():
    a = _summary(id="BG-000001", techniques=["T1133"], first_seen=T0)
    b = _summary(id="BG-000002", techniques=["T1110"], first_seen=T0)
    rel = pair_relationships(a, b, window_key="multi_stage", within_window=None)
    assert "TACTIC_TRANSITION" in rel["types"]


def test_edge_strength_is_capped_and_deterministic():
    strength = edge_strength(["SAME_HOST", "SAME_USER", "SAME_SOURCE", "TEMPORAL"])
    assert strength == 0.90
    assert (
        edge_strength(
            [
                "SAME_HOST",
                "SAME_USER",
                "SAME_SOURCE",
                "TEMPORAL",
                "TECHNIQUE_TRANSITION",
            ]
        )
        == 1.0
    )
    # Qualitative signals never inflate strength.
    assert edge_strength(["SAME_USER", "TEMPORAL", "LATERAL_MOVEMENT"]) == 0.40
    assert edge_strength(["TEMPORAL"]) == 0.15


def test_temporal_requires_window():
    a = _summary(id="BG-000001", first_seen=T0)
    b = _summary(
        id="BG-000002", first_seen=T0 + __import__("datetime").timedelta(minutes=200)
    )
    assert not within_window(a["first_seen"], b["first_seen"], "multi_stage")
    rel = pair_relationships(a, b, window_key="multi_stage", within_window=None)
    assert "TEMPORAL" not in rel["types"]
