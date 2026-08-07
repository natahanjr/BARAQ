"""Entity intelligence graph - provider factory + extractor exports.

``get_graph_store()`` returns the configured :class:`GraphStore` backend
(Postgres by default; Neo4j when explicitly enabled, falling back gracefully).
The extractors in :mod:`backend.graph.extract` consume the same interface.

Typical uses::

    from backend.graph import get_graph_store, sync_graph

    store = get_graph_store()
    results = sync_graph(db, store)
    store.graph(db, center_kind="user", center_name="admin")
"""
from __future__ import annotations

import logging

logger = logging.getLogger("sentinel.graph")

_store: "GraphStore | None" = None


def get_graph_store() -> "GraphStore":
    """Return the configured graph store (singleton, lazily initialised).

    Provider resolution: ``SENTINEL_GRAPH_PROVIDER`` in
    ``{"postgres" | "neo4j" | "auto"}``. ``auto`` picks Neo4j only when
    ``SENTINEL_NEO4J_URI`` is set; any Neo4j initialisation failure or
    misconfiguration degrades to the Postgres backend so the platform keeps
    working with no external services.
    """
    global _store
    if _store is not None:
        return _store

    from backend.config import GRAPH_PROVIDER, NEO4J_URI
    from backend.graph.base import GraphProviderUnavailable

    provider = GRAPH_PROVIDER
    if provider == "auto":
        provider = "neo4j" if NEO4J_URI else "postgres"

    if provider == "neo4j":
        from backend.graph.neo4j import Neo4jStore

        try:
            _store = Neo4jStore()
            logging.getLogger("sentinel.graph").info("Entity graph provider: neo4j")
            return _store
        except GraphProviderUnavailable as exc:
            logging.getLogger("sentinel.graph").warning(
                "Neo4j unavailable (%s); falling back to postgres", exc
            )

    from backend.graph.postgres import PostgresStore

    if _store is None:
        _store = PostgresStore()
    logging.getLogger("sentinel.graph").info("Entity graph provider: postgres")
    return _store


from backend.graph.extract import ingest_batch, sync_graph  # noqa: E402,F401