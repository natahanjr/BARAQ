"""Tests for the automated parameter-tuning script (scripts/tune_parameters.py).

Covers the methodology v2 scoring: attack variants are scored against a
separate benign-only corpus, so precision is real, and the seed is
reproducible.
"""

from __future__ import annotations

from scripts.tune_parameters import (
    BENIGN_BUILDERS,
    EXPECTED_RULE,
    _build_attack_sessions,
    _build_benign_session,
    _score,
)


def test_tuner_corpus_fully_detected_with_defaults(db):
    from tests import fixtures
    from tests.fixtures import add_normalized

    for name in EXPECTED_RULE:
        add_normalized(db, getattr(fixtures, name)())
    attack = _build_attack_sessions(seed=20260806, variants=1, corpus_path=None)
    benign = _build_benign_session()
    tp, fp, fn = _score(attack, benign, {}, window_minutes=10)
    assert tp == len(EXPECTED_RULE)
    assert fn == 0
    assert fp == 0
    benign.close()


def test_tuner_override_thresholds_changes_score(db):
    from tests import fixtures
    from tests.fixtures import add_normalized

    for name in EXPECTED_RULE:
        add_normalized(db, getattr(fixtures, name)())

    attack = _build_attack_sessions(seed=20260806, variants=1, corpus_path=None)
    benign = _build_benign_session()

    strict = _score(
        attack,
        benign,
        {"brute_force": {"threshold": 99}},
        window_minutes=10,
    )
    assert strict[0] == len(EXPECTED_RULE) - 1  # brute_force missed
    assert strict[2] == 1

    exact = _score(
        attack,
        benign,
        {"network_recon": {"distinct_ports": 999}},
        window_minutes=10,
    )
    assert exact[2] == 1  # port_scan missed under stricter tuning

    benign.close()


def test_tuner_benign_corpus_fires_nothing_with_defaults():
    benign = _build_benign_session()
    _, fp, _ = _score(_build_attack_sessions(1, 1, None), benign, {}, window_minutes=10)
    assert fp == 0  # no rule may fire on benign-only telemetry
    benign.close()


def test_tuner_randomized_variants_change_scores():
    """Randomized attack variants must be reproducible per seed."""
    a1 = _build_attack_sessions(seed=42, variants=2, corpus_path=None)
    a2 = _build_attack_sessions(seed=42, variants=2, corpus_path=None)
    benign = _build_benign_session()
    s1 = _score(a1, benign, {}, window_minutes=10)
    s2 = _score(a2, benign, {}, window_minutes=10)
    assert s1 == s2  # seeded reproducibility
    benign.close()


def test_tuner_expected_rule_mapping_coverage():
    assert EXPECTED_RULE["brute_force"] == "brute_force"
    assert EXPECTED_RULE["port_scan"] == "network_recon"
    assert len(EXPECTED_RULE) >= 10
    assert len(BENIGN_BUILDERS) >= 2
