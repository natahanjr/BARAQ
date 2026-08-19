"""Phase 5 correlation confidence (spec 5.23, 5.24).

Deterministic, bounded, and never summed from group confidences (no
inflation - spec 5.24):

    confidence = 0.40
               + 0.10 * (shared factors - 2)      # relationship types
               + 0.10 if tactic progression       # a pair advanced phases
               + 0.05 if chain has >= 3 groups    # multi-stage sequence
               + 0.03 if lateral movement edge    # cross-host movement
               clamp [0.20, 0.90]

The canonical RDP -> lateral example (spec 5.70) shares exactly five
relationship types (SAME_USER, SAME_SOURCE, TEMPORAL, DESTINATION_RELATION,
LATERAL_MOVEMENT), shows progression, is 4 groups long and contains a
lateral edge:

    0.40 + 0.30 + 0.10 + 0.05 + 0.03 = 0.88
"""
from __future__ import annotations

import backend.config as config


def confidence(
    relationship_types: set[str],
    chain_length: int,
    has_progression: bool,
    has_lateral_edge: bool,
) -> float:
    base = config.CORRELATION_CONFIDENCE_BASE
    per_factor = config.CORRELATION_CONFIDENCE_PER_FACTOR
    minimum = config.CORRELATION_MIN_RELATIONSHIPS
    factors = max(len(relationship_types), minimum)

    value = base + per_factor * (factors - minimum)
    if has_progression:
        value += config.CORRELATION_CONFIDENCE_PROGRESSION_BONUS
    if chain_length >= 3:
        value += config.CORRELATION_CONFIDENCE_SEQUENCE_BONUS
    if has_lateral_edge:
        value += config.CORRELATION_CONFIDENCE_LATERAL_BONUS

    value = max(config.CORRELATION_CONFIDENCE_MIN, min(config.CORRELATION_CONFIDENCE_MAX, value))
    return round(value, 4)
