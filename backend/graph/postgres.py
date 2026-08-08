"""Postgres-backed entity graph store (default provider).

Stores entities in the existing database via the ``entity_nodes`` /
``entity_edges`` tables. The graph API stays behind :class:`GraphStore` so a
Neo4j provider can be swapped in later via ``SENTINEL_GRAPH_PROVIDER`` without
touching callers.

Upsert semantics (mirrors the Neo4j adapter): on conflict, counters
(``events_count`` / ``alerts_count`` / edge ``weight``) **accumulate** and
``first_seen``/``last_seen`` run to the true min/max so re-syncing a batch
never erases history or double-counts.
"""
from __future__ import annotations

import logging
from sqlalchemy import case, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from backend.config import GRAPH_MAX_EDGES, GRAPH_MAX_NODES
from backend.database.connection import IS_POSTGRES, IS_SQLITE
from backend.database.models import EntityEdge, EntityNode
from backend.graph.base import GraphStore

logger = logging.getLogger("sentinel.graph")

_node_columns = {
    "kind", "name", "display_name", "label", "risk_level", "risk_score",
    "alerts_count", "events_count", "properties", "first_seen", "last_seen",
}
_edge_columns = {
    "src_kind", "src_name", "rel", "dst_kind", "dst_name",
    "weight", "first_seen", "last_seen", "properties",
}

_upsert_cls = pg_insert if IS_POSTGRES else sqlite_insert


def _earliest(existing, incoming):
    """MIN of two nullable datetime columns, keeping the older one."""
    return case(
        (existing.is_(None), incoming),
        (incoming.is_(None), existing),
        (incoming < existing, incoming),
        else_=existing,
    )


def _latest(existing, incoming):
    """MAX of two nullable datetime columns, keeping the newer one."""
    return case(
        (existing.is_(None), incoming),
        (incoming.is_(None), existing),
        (incoming > existing, incoming),
        else_=existing,
    )


def _accumulate(existing, incoming):
    """INCOMING + EXISTING, coalescing NULLs to 0 (portable)."""
    return existing + func.coalesce(incoming, 0)


class PostgresStore(GraphStore):
    name = "postgres"

    def status(self, db) -> dict:
        return self.stats(db)

    # -- mutations --------------------------------------------------------

    def upsert_entities(self, db, entities: list[dict], accumulate: bool = False) -> None:
        """Create-or-update nodes by (kind, name).

        With ``accumulate=False`` every field is replaced with the incoming
        value (full-sync totals). With ``accumulate=True`` (per-batch deltas)
        counters add up and ``first_seen``/``last_seen`` keep the true
        earliest/latest edge so re-syncing never erases history.
        """
        if not entities:
            return
        rows = [{k: v for k, v in e.items() if k in _node_columns} for e in entities]
        stmt = _upsert_cls(EntityNode).values()
        excluded = stmt.excluded
        set_ = {
            "display_name": excluded.display_name,
            "label": excluded.label,
            "risk_level": excluded.risk_level,
            "risk_score": excluded.risk_score,
            "properties": excluded.properties,
        }
        if accumulate:
            set_["alerts_count"] = _accumulate(EntityNode.alerts_count, excluded.alerts_count)
            set_["events_count"] = _accumulate(EntityNode.events_count, excluded.events_count)
            set_["first_seen"] = _earliest(EntityNode.first_seen, excluded.first_seen)
            set_["last_seen"] = _latest(EntityNode.last_seen, excluded.last_seen)
        else:
            set_["alerts_count"] = excluded.alerts_count
            set_["events_count"] = excluded.events_count
            set_["first_seen"] = excluded.first_seen
            set_["last_seen"] = excluded.last_seen
        db.execute(
            stmt.on_conflict_do_update(
                index_elements=["kind", "name"],
                set_=set_,
            ),
            rows,
        )
        db.commit()

    def upsert_edges(self, db, edges: list[dict], accumulate: bool = False) -> None:
        if not edges:
            return
        rows = [{k: v for k, v in e.items() if k in _edge_columns} for e in edges]
        stmt = _upsert_cls(EntityEdge).values()
        excluded = stmt.excluded
        set_: dict = {"properties": excluded.properties}
        if accumulate:
            set_["weight"] = _accumulate(EntityEdge.weight, excluded.weight)
            set_["first_seen"] = _earliest(EntityEdge.first_seen, excluded.first_seen)
            set_["last_seen"] = _latest(EntityEdge.last_seen, excluded.last_seen)
        else:
            set_["weight"] = excluded.weight
            set_["first_seen"] = excluded.first_seen
            set_["last_seen"] = excluded.last_seen
        db.execute(
            stmt.on_conflict_do_update(
                index_elements=["src_kind", "src_name", "rel", "dst_kind", "dst_name"],
                set_=set_,
            ),
            rows,
        )
        db.commit()

    # -- reads ------------------------------------------------------------

    def get_entity(self, db, kind: str, name: str) -> dict | None:
        node = db.scalar(
            select(EntityNode).where(EntityNode.kind == kind, EntityNode.name == name)
        )
        return node.to_dict() if node else None

    def list_entities(
        self,
        db,
        kind: str | None = None,
        limit: int = 100,
        offset: int = 0,
        min_risk: float = 0.0,
        search: str | None = None,
    ) -> list[dict]:
        stmt = select(EntityNode)
        if kind:
            stmt = stmt.where(EntityNode.kind == kind)
        if min_risk > 0:
            stmt = stmt.where(EntityNode.risk_score >= min_risk)
        if search:
            like = f"%{search}%"
            stmt = stmt.where(
                or_(
                    EntityNode.name.ilike(like),
                    EntityNode.display_name.ilike(like),
                    EntityNode.label.ilike(like),
                )
            )
        stmt = (
            stmt.order_by(EntityNode.risk_score.desc(), EntityNode.last_seen.desc())
            .limit(limit)
            .offset(offset)
        )
        return [n.to_dict() for n in db.scalars(stmt).all()]

    def graph(
        self,
        db,
        center_kind: str | None = None,
        center_name: str | None = None,
        depth: int = 1,
        limit: int | None = None,
    ) -> dict:
        """Expand the subgraph around an entity (or the top-risk subgraph).

        Both the node and edge payloads are capped so a busy hub entity
        (thousands of links) can never flood the UI: ``limit`` bounds nodes,
        :data:`GRAPH_MAX_EDGES` bounds edges.
        """
        limit = limit or GRAPH_MAX_NODES
        edge_limit = GRAPH_MAX_EDGES
        nodes: dict[tuple, EntityNode] = {}
        edges: dict[int, EntityEdge] = {}

        def _add(kind: str, name: str) -> None:
            if (kind, name) in nodes:
                return
            node = db.scalar(
                select(EntityNode).where(
                    EntityNode.kind == kind, EntityNode.name == name
                )
            )
            if node:
                nodes[(kind, name)] = node

        def _fetch_nodes(keys: list[tuple[str, str]]) -> None:
            """Bulk-load a list of (kind, name) keys in one query."""
            if not keys:
                return
            conditions = [
                (EntityNode.kind == k) & (EntityNode.name == n) for k, n in keys
            ]
            for node in db.scalars(
                select(EntityNode).where(or_(*conditions))
            ).all():
                nodes[(node.kind, node.name)] = node

        if center_kind and center_name:
            _add(center_kind, center_name)
            frontier = [(center_kind, center_name)]
            seen = set(frontier)
            for _hop in range(max(1, depth)):
                if len(nodes) >= limit or len(edges) >= edge_limit:
                    break
                # One query per hop for the whole frontier (no N+1), SQL-capped
                # so a hub with tens of thousands of links can never flood
                # Python or the UI.
                conditions = []
                for k, n in frontier:
                    conditions.append(
                        (EntityEdge.src_kind == k) & (EntityEdge.src_name == n)
                    )
                    conditions.append(
                        (EntityEdge.dst_kind == k) & (EntityEdge.dst_name == n)
                    )
                rels = db.scalars(
                    select(EntityEdge)
                    .where(or_(*conditions))
                    .order_by(EntityEdge.weight.desc(), EntityEdge.last_seen.desc())
                    .limit(max(1, edge_limit - len(edges)))
                ).all() if conditions else []

                nxt_keys: list[tuple[str, str]] = []
                for e in rels:
                    edges[e.id] = e
                    for ekind, ename in (
                        (e.src_kind, e.src_name),
                        (e.dst_kind, e.dst_name),
                    ):
                        if (ekind, ename) not in seen:
                            seen.add((ekind, ename))
                            nxt_keys.append((ekind, ename))

                # Only fetch as many nodes as the remaining budget allows.
                budget = max(0, limit - len(nodes))
                _fetch_nodes(nxt_keys[:budget])
                frontier = [k for k in nxt_keys[:budget] if k in nodes]
            return {
                "nodes": [n.to_dict() for n in nodes.values()],
                "edges": [e.to_dict() for e in edges.values()],
            }
            return {
                "nodes": [n.to_dict() for n in nodes.values()],
                "edges": [e.to_dict() for e in edges.values()],
            }

        # No center: heavy edges touching the highest-risk nodes.
        top = self.list_entities(db, limit=40, min_risk=20)
        names = {(d["kind"], d["name"]) for d in top}
        edge_rows: list[dict] = []
        if names:
            conditions = []
            for k, n in names:
                conditions.append((EntityEdge.src_kind == k) & (EntityEdge.src_name == n))
                conditions.append((EntityEdge.dst_kind == k) & (EntityEdge.dst_name == n))
            rels = db.scalars(
                select(EntityEdge)
                .where(or_(*conditions))
                .order_by(EntityEdge.weight.desc(), EntityEdge.last_seen.desc())
                .limit(edge_limit)
            ).all()
            edge_rows = [e.to_dict() for e in rels]

        node_ids: set[tuple] = set(names)
        for e in edge_rows:
            node_ids.add((e["source"]["kind"], e["source"]["name"]))
            node_ids.add((e["target"]["kind"], e["target"]["name"]))

        included = []
        for d in self.list_entities(db, limit=limit):
            if (d["kind"], d["name"]) in node_ids:
                included.append(d)
        return {
            "nodes": sorted(
                included, key=lambda d: d["risk_score"], reverse=True
            )[:limit],
            "edges": edge_rows,
        }

    def stats(self, db) -> dict:
        rows = db.execute(
            select(EntityNode.kind, func.count()).group_by(EntityNode.kind)
        ).all()
        by_kind = {k: c for k, c in rows}
        top = db.scalars(
            select(EntityNode).order_by(EntityNode.risk_score.desc()).limit(5)
        ).all()
        return {
            "provider": self.name,
            "total_entities": sum(by_kind.values()),
            "total_edges": db.scalar(select(func.count()).select_from(EntityEdge)) or 0,
            "by_kind": by_kind,
            "top_risk": [n.to_dict() for n in top],
        }