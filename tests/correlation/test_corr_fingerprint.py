"""Phase 5 fingerprint tests (spec 5.6, 5.7)."""
from backend.correlation.fingerprint import finding_fingerprint


def test_fingerprint_is_sha256_hex():
    fp = finding_fingerprint("TEMPORAL", ["BG-000001", "BG-000002"])
    assert len(fp) == 64
    int(fp, 16)


def test_fingerprint_deterministic_and_uuid_free():
    edges = [
        {"source_group_id": "BG-000001", "target_group_id": "BG-000002",
         "relationship_type": "SAME_USER"},
        {"source_group_id": "BG-000001", "target_group_id": "BG-000002",
         "relationship_type": "TEMPORAL"},
    ]
    a = finding_fingerprint("TEMPORAL", ["BG-000001", "BG-000002"], edges)
    b = finding_fingerprint("TEMPORAL", ["BG-000002", "BG-000001"], edges)
    c = finding_fingerprint("TEMPORAL", ["BG-000002", "BG-000001"], list(reversed(edges)))
    assert a == b == c


def test_fingerprint_sensitive_to_type_members_and_edges():
    base = finding_fingerprint("TEMPORAL", ["BG-000001", "BG-000002"])
    assert base != finding_fingerprint("ENTITY", ["BG-000001", "BG-000002"])
    assert base != finding_fingerprint("TEMPORAL", ["BG-000001", "BG-000003"])
    assert base != finding_fingerprint(
        "TEMPORAL", ["BG-000001", "BG-000002"],
        [{"source_group_id": "BG-000001", "target_group_id": "BG-000002",
          "relationship_type": "SAME_USER"}],
    )