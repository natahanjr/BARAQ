"""Phase 6 factor registry tests (spec 6.9, 6.40, 6.41, 6.43)."""
from __future__ import annotations

import backend.config as config
import pytest

from backend.risk.registry import (
    FACTOR_ID_TYPES,
    FACTOR_REGISTRY,
    get_factor,
    list_factors,
    model_version,
    repetition_curve,
)


def test_all_spec_factors_are_registered():
    required = {
        "RF001_EXTERNAL_ACCESS", "RF002_CREDENTIAL_ACCESS",
        "RF003_LATERAL_MOVEMENT", "RF004_PRIVILEGE_ACTIVITY",
        "RF005_EXECUTION", "RF006_MULTI_STAGE_CORRELATION",
        "RF007_REPETITION", "RF008_RECENCY",
    }
    assert required <= set(FACTOR_REGISTRY)
    assert len(FACTOR_REGISTRY) >= 8


def test_registry_weights_track_config():
    for factor_id, definition in FACTOR_REGISTRY.items():
        if factor_id == "RF007_REPETITION":
            continue
        assert definition.weight == float(
            config.RISK_FACTOR_WEIGHTS[factor_id]
        ), factor_id


def test_factor_definition_fields():
    definition = get_factor("RF003_LATERAL_MOVEMENT")
    assert definition.factor_id == "RF003_LATERAL_MOVEMENT"
    assert definition.version == "1.0"
    assert definition.description
    assert definition.source_type == "behavior_group"
    assert definition.decay_policy == "half_life"
    assert definition.maximum_contribution <= config.RISK_MAX_FACTOR_CONTRIBUTION


def test_factor_type_mapping_has_no_gaps():
    for factor_id in FACTOR_REGISTRY:
        assert factor_id in FACTOR_ID_TYPES


def test_repetition_curve_matches_config():
    assert repetition_curve() == tuple(config.RISK_REPETITION_CURVE)


def test_unknown_factor_is_rejected():
    with pytest.raises(KeyError):
        get_factor("SUSPICIOUS_FACTOR")
    with pytest.raises(KeyError):
        get_factor("RF999")


def test_list_factors_is_sorted_and_complete():
    factors = list_factors()
    assert factors == sorted(factors, key=lambda f: f["factor_id"])
    assert len(factors) == len(FACTOR_REGISTRY)
    for entry in factors:
        assert set(entry) == {
            "factor_id", "version", "description", "source_type",
            "weight", "decay_policy", "maximum_contribution",
        }


def test_model_version_is_stable():
    assert model_version() == "1.0.0"
    assert model_version() == config.RISK_MODEL_VERSION