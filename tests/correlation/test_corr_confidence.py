"""Phase 5 confidence tests (spec 5.23, 5.24)."""

from backend import config
from backend.correlation.confidence import confidence


def test_bounded_between_min_and_max():
    for value in (
        confidence(set(), 1, False, False),
        confidence(
            {"SAME_HOST", "SAME_USER", "SAME_SOURCE", "TEMPORAL"}, 2, True, True
        ),
        confidence({"A", "B", "C", "D", "E", "F", "G", "H"}, 9, True, True),
    ):
        assert (
            config.CORRELATION_CONFIDENCE_MIN
            <= value
            <= config.CORRELATION_CONFIDENCE_MAX
        )


def test_canonical_example_is_exactly_0_88():
    # spec 5.70: SAME_USER/SAME_SOURCE/TEMPORAL/DESTINATION_RELATION/
    # LATERAL_MOVEMENT, 4 groups, progression, lateral edge.
    value = confidence(
        {
            "SAME_USER",
            "SAME_SOURCE",
            "TEMPORAL",
            "DESTINATION_RELATION",
            "LATERAL_MOVEMENT",
        },
        chain_length=4,
        has_progression=True,
        has_lateral_edge=True,
    )
    assert value == 0.88


def test_never_summed_from_group_confidences():
    # The confidence is a pure function of the shared relationships - group
    # confidence values are not even an input.
    value = confidence({"SAME_USER", "SAME_SOURCE", "TEMPORAL"}, 2, False, False)
    assert value == 0.50


def test_no_inflation_single_factor_is_base():
    # With the two-member floor, a bare pair never inflates: the result is
    # exactly the deterministic base (well above the clamp floor).
    assert confidence({"SAME_USER"}, 2, False, False) == 0.40
    assert confidence(set(), 1, False, False) >= config.CORRELATION_CONFIDENCE_MIN


def test_formula_deterministic():
    args = (
        {"SAME_USER", "SAME_SOURCE", "TEMPORAL", "DESTINATION_RELATION"},
        3,
        True,
        True,
    )
    assert confidence(*args) == confidence(*args)
