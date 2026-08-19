"""Phase 5 candidate generation (spec 5.75, 5.76).

Never an O(n^2) sweep: candidate pairs are partitioned by the indexed
entity keys (host, user, source) and by time. A pair is only examined when
the two groups share at least one entity key and fall inside the maximum
correlation window. Deterministic ordering: (earlier first_seen, earlier
id, later first_seen, later id).
"""
from __future__ import annotations

from datetime import timedelta

from backend.correlation.windows import window_minutes

MAX_WINDOW_KEY = "multi_stage"
ENTITY_KEYS = ("host", "user", "source")


def _values_of(summary: dict, key: str) -> set[str]:
    values = summary.get(key) or summary.get(
        {"host": "hosts", "user": "users", "source": "sources"}[key]
    )
    return {str(v).strip().lower() for v in (values or []) if str(v).strip()}


def candidate_pairs(summaries: list[dict], now=None) -> list[tuple[dict, dict]]:
    """All group pairs sharing an entity key within the max window.

    ``summaries`` must already be sorted by (first_seen, id).
    """
    max_minutes = window_minutes(MAX_WINDOW_KEY)
    max_delta = timedelta(minutes=max_minutes, seconds=60)

    buckets: dict[tuple[str, str], list[int]] = {}
    for index, summary in enumerate(summaries):
        seen_keys: set[tuple[str, str]] = set()
        for key in ENTITY_KEYS:
            for value in _values_of(summary, key):
                bucket_key = (key, value)
                if bucket_key not in seen_keys:
                    buckets.setdefault(bucket_key, []).append(index)
                    seen_keys.add(bucket_key)

    pairs: set[tuple[int, int]] = set()
    for indexes in buckets.values():
        for i in range(len(indexes)):
            for j in range(i + 1, len(indexes)):
                a, b = indexes[i], indexes[j]
                earlier, later = (a, b) if summaries[a]["first_seen"] <= summaries[b]["first_seen"] else (b, a)
                if later - earlier > max_delta:
                    continue
                pairs.add((earlier, later))

    ordered = sorted(pairs, key=lambda p: (
        summaries[p[0]]["first_seen"], summaries[p[0]]["id"],
        summaries[p[1]]["first_seen"], summaries[p[1]]["id"],
    ))
    return [(summaries[a], summaries[b]) for a, b in ordered]
