"""Phase 5 behavioral correlation package.

Correlates behavior groups (Phase 4) into explainable, deterministic
correlation findings. Never an incident, never a risk verdict, never ML
(spec 5.1, 5.69): the layer produces hypotheses with bounded confidence
and mandatory "why correlated" explanations.
"""

from __future__ import annotations

from backend.correlation.contract import (
    BANNED_CORRELATION_PHRASES as BANNED_CORRELATION_PHRASES,
)
from backend.correlation.contract import (
    CORRELATION_STATUSES as CORRELATION_STATUSES,
)
from backend.correlation.contract import (
    CORRELATION_TYPES as CORRELATION_TYPES,
)
from backend.correlation.contract import (
    CorrelationFinding as CorrelationFinding,
)
from backend.correlation.engine import correlate as correlate
from backend.correlation.engine import expire_correlations as expire_correlations
from backend.correlation.rules import RULES as RULES
from backend.correlation.rules import RULES_VERSION as RULES_VERSION
