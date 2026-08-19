"""Phase 5 behavioral correlation package.

Correlates behavior groups (Phase 4) into explainable, deterministic
correlation findings. Never an incident, never a risk verdict, never ML
(spec 5.1, 5.69): the layer produces hypotheses with bounded confidence
and mandatory "why correlated" explanations.
"""
from __future__ import annotations

from backend.correlation.contract import (
    BANNED_CORRELATION_PHRASES,
    CORRELATION_TYPES,
    CORRELATION_STATUSES,
    CorrelationFinding,
)
from backend.correlation.engine import correlate, expire_correlations
from backend.correlation.rules import RULES, RULES_VERSION
