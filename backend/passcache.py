"""Pass-scoped computation cache shared by the ML and detection pipelines.

A "pass" is one scheduler stage (feature extraction for analyze_events(),
one detection sweep, ...): window aggregates and shared lookups computed
inside a ``with _feature_pass_cache():`` scope are memoized per thread for
the duration of the block, then discarded. Outside a scope every helper is
a transparent passthrough, so direct calls (tests, on-demand scoring) keep
their uncached semantics.

The cache is thread-local: training (background thread) and scoring
(scheduler thread) never share entries.
"""
from __future__ import annotations

import functools
import threading
from contextlib import contextmanager

_FEATURE_CACHE_TLS = threading.local()


@contextmanager
def _feature_pass_cache():
    """Enable the pass-scoped cache for the duration of the block."""
    prev = getattr(_FEATURE_CACHE_TLS, "cache", None)
    _FEATURE_CACHE_TLS.cache = {}
    try:
        yield
    finally:
        _FEATURE_CACHE_TLS.cache = prev


def _cached(key: tuple, compute):
    """Return the cached value for ``key`` or compute-and-store it.

    No-op (always computes) when no pass scope is active.
    """
    cache = getattr(_FEATURE_CACHE_TLS, "cache", None)
    if cache is None:
        return compute()
    if key in cache:
        return cache[key]
    value = compute()
    cache[key] = value
    return value


def _copy(value):
    if isinstance(value, list):
        return list(value)
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, set):
        return set(value)
    return value


def _window_cached(fn):
    """Pass-cache a ``fn(session, *args, **kwargs)`` window helper.

    Keyed by everything except the (unhashable) session. Outside a pass
    scope this is a transparent passthrough.
    """

    @functools.wraps(fn)
    def wrapper(session, *args, **kwargs):
        cache = getattr(_FEATURE_CACHE_TLS, "cache", None)
        if cache is None:
            return fn(session, *args, **kwargs)
        try:
            key = (fn.__name__, args, tuple(sorted(kwargs.items())))
            hash(key)
        except TypeError:
            return fn(session, *args, **kwargs)
        if key in cache:
            return _copy(cache[key])
        value = fn(session, *args, **kwargs)
        cache[key] = value
        return value

    return wrapper
