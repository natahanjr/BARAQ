"""Neo4j entity graph adapter (optional; not used unless explicitly enabled).

Selected via ``BARAQ_GRAPH_PROVIDER=neo4j`` (+ ``BARAQ_NEO4J_URI`` /
user / password / database). Implements the same :class:`GraphStore`
interface as the Postgres backend so the API, extractor and UI are
provider-agnostic. Falls back to Postgres when the driver is missing or the
server is unreachable (see ``backend.graph`` factory).
"""

from __future__ import annotations

import logging

from backend.config import (
    GRAPH_MAX_NODES,
    NEO4J_DATABASE,
    NEO4J_PASSWORD,
    NEO4J_URI,
    NEO4J_USER,
)
from backend.graph.base import GraphProviderUnavailable, GraphStore

logger = logging.getLogger("baraq.graph")


class Neo4jStore(GraphStore):
    name = "neo4j"

    def __init__(self) -> None:
        self._driver = None
        try:
            from neo4j import GraphDatabase
        except ImportError as exc:  # pragma: no cover - packaging guard
            raise GraphProviderUnavailable(
                "Neo4j driver not installed (pip install neo4j)"
            ) from exc
        if not NEO4J_URI:
            raise GraphProviderUnavailable("BARAQ_NEO4J_URI is not set")
        self._driver = GraphDatabase.driver(
            NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD), database=NEO4J_DATABASE
        )
        # eager connectivity check so a bad server fails fast at boot
        try:
            self._driver.verify_connectivity()
        except Exception as exc:
            self._driver.close()
            self._driver = None
            raise GraphProviderUnavailable(f"Neo4j unreachable: {exc}") from exc

    # -- helpers ------------------------------------------------------------

    def _run(self, query: str, params: dict | None = None) -> list:
        if not self._driver:
            return []
        with self._driver.session() as session:
            result = session.run(query, params or {})
            return [record.data() for record in result]

    @staticmethod
    def _node_to_dict(n: dict, props: dict | None = None) -> dict:
        rec = dict(n)
        rec["kind"] = (n or {}).get(":LABEL", "")
        rec["properties"] = props or {}
        return rec

    # -- minimal interface (Postgres is the reference implementation) -------

    def status(self, db) -> dict:
        if not self._driver:
            return {
                "provider": self.name,
                "nodes": 0,
                "edges": 0,
                "error": "unavailable",
            }
        try:
            nodes = (
                self._run("MATCH (n) RETURN count(n) AS c")[0].get("c", 0)
                if self._run("MATCH (n) RETURN count(n) AS c")
                else 0
            )
            edges = self._run("MATCH ()-[r]->() RETURN count(r) AS c")[0].get("c", 0)
        except Exception as exc:
            return {"provider": self.name, "nodes": 0, "edges": 0, "error": str(exc)}
        return {"provider": self.name, "nodes": nodes, "edges": edges}

    def upsert_entities(self, db, entities: list[dict]) -> None:
        if not self._driver:
            return
        for e in entities:
            self._run(
                "MERGE (n:Entity {kind: $kind, name: $name}) "
                "SET n += COALESCE($props, {}) RETURN n",
                {
                    "kind": e.get("kind"),
                    "name": e.get("name"),
                    "props": {
                        "risk_score": e.get("risk_score", 0.0),
                        "risk_level": e.get("risk_level", "LOW"),
                        "alerts_count": e.get("alerts_count", 0),
                        "events_count": e.get("events_count", 0),
                    },
                },
            )

    def upsert_edges(self, db, edges: list[dict]) -> None:
        if not self._driver:
            return
        for e in edges:
            self._run(
                "MATCH (a:Entity {kind: $sk, name: $sn}), (b:Entity {kind: $dk, name: $dn}) "
                "MERGE (a)-[r:REL {type: $rel}]->(b) "
                "ON CREATE SET r.weight = 1 "
                "ON MATCH SET r.weight = r.weight + 1",
                {
                    "sk": e.get("src_kind"),
                    "sn": e.get("src_name"),
                    "dk": e.get("dst_kind"),
                    "dn": e.get("dst_name"),
                    "rel": e.get("rel"),
                    "weight": int(e.get("weight", 1)),
                },
            )

    def get_entity(self, db, kind: str, name: str) -> dict | None:
        rows = self._run(
            "MATCH (n:Entity {kind: $kind, name: $name}) RETURN n",
            {"kind": kind, "name": name},
        )
        if not rows:
            return None
        n = rows[0].get("n")
        return {
            "kind": n.get("kind"),
            "name": n.get("name"),
            "risk_score": n.get("risk_score", 0.0),
            "risk_level": n.get("risk_level", "LOW"),
            "properties": {},
        }

    def list_entities(
        self, db, kind=None, limit=100, offset=0, min_risk=0.0, search=None
    ):
        q = "MATCH (n:Entity)"
        p: dict = {}
        if kind:
            q += " WHERE n.kind = $kind"
            p["kind"] = kind
        if min_risk > 0:
            q += (
                " AND n.risk_score >= $min_risk"
                if kind
                else " WHERE n.risk_score >= $min_risk"
            )
            p["min_risk"] = min_risk
        q += " RETURN n ORDER BY n.risk_score DESC LIMIT $limit"
        p["limit"] = limit
        rows = self._run(q, p)
        return [
            {
                "kind": r["n"].get("kind"),
                "name": r["n"].get("name"),
                "risk_score": r["n"].get("risk_score", 0.0),
                "risk_level": r["n"].get("risk_level", "LOW"),
            }
            for r in rows
        ]

    def graph(self, db, center_kind=None, center_name=None, depth=1, limit=None):
        if not center_kind or not center_name:
            return {
                "nodes": self.list_entities(db, limit=limit or GRAPH_MAX_NODES),
                "edges": [],
            }
        rows = self._run(
            "MATCH (c:Entity {kind: $k, name: $n})-[r*1..$d]-(x:Entity) "
            "UNWIND r AS rr "
            "RETURN DISTINCT startNode(rr) AS a, type(rr) AS rel, endNode(rr) AS b",
            {"k": center_kind, "n": center_name, "d": depth},
        )
        node_keys = {(center_kind, center_name)}
        edges = []
        for r in rows:
            a, b = r.get("a"), r.get("b")
            node_keys.add((a.get("kind"), a.get("name")))
            node_keys.add((b.get("kind"), b.get("name")))
            edges.append(
                {
                    "source": {"kind": a.get("kind"), "name": a.get("name")},
                    "rel": r.get("rel"),
                    "target": {"kind": b.get("kind"), "name": b.get("name")},
                }
            )
        return {
            "nodes": [self.get_entity(db, k, n) for k, n in node_keys],
            "edges": edges,
        }

    def stats(self, db) -> dict:
        s = self.status(db)
        return {
            "provider": self.name,
            "total_entities": s.get("nodes", 0),
            "total_edges": s.get("edges", 0),
            "by_kind": {},
            "top_risk": [],
        }
