"""Entity intelligence graph - provider interface.

The graph store abstracts *where* entities and their relationships live so
the storage backend can be swapped without touching the API or the
extractor:

* :class:`GraphStore` - abstract interface every backend implements.
* ``backend.graph.postgres.PostgresStore`` - default; reuses the existing
  database (``entity_nodes`` / ``entity_edges`` tables), no extra services.
* ``backend.graph.neo4j.Neo4jStore`` - optional adapter for a running Neo4j
  instance, selected via ``BARAQ_GRAPH_PROVIDER``.

All methods take the SQLAlchemy session first so the Postgres backend can use
it; Neo4j implementations ignore it. Records are plain dicts (see the module
functions in ``backend.graph`` for the canonical shapes).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

logger = logging.getLogger("baraq.graph")


class GraphProviderUnavailable(Exception):
    """Raised when a requested provider cannot be initialised."""


class GraphStore(ABC):
    """Interface for the entity intelligence graph backend."""

    name: str = "abstract"

    @abstractmethod
    def status(self, db) -> dict:
        """Provider health + counts (nodes per kind, edge count)."""

    @abstractmethod
    def upsert_entities(self, db, entities: list[dict]) -> None:
        """Create-or-update entity nodes by (kind, name)."""

    @abstractmethod
    def upsert_edges(self, db, edges: list[dict]) -> None:
        """Create-or-update directional edges by (src, rel, dst)."""

    @abstractmethod
    def get_entity(self, db, kind: str, name: str) -> dict | None:
        """Return a single entity node (with properties) or None."""

    @abstractmethod
    def list_entities(
        self,
        db,
        kind: str | None = None,
        limit: int = 100,
        offset: int = 0,
        min_risk: float = 0.0,
        search: str | None = None,
    ) -> list[dict]:
        """Page through entity nodes, optionally filtered by kind / risk."""

    @abstractmethod
    def graph(
        self,
        db,
        center_kind: str | None = None,
        center_name: str | None = None,
        depth: int = 1,
        limit: int = 250,
    ) -> dict:
        """Return ``{"nodes": [...], "edges": [...]}`` for the UI.

        Without a center, returns the highest-risk subgraph. With a center,
        expands breadth-first up to ``depth`` hops around that entity.
        """

    @abstractmethod
    def stats(self, db) -> dict:
        """Aggregate counters for the command center (entities per kind,
        total edges, highest-risk entities)."""
