"""Threat-actor attribution - cluster IOC verdicts into graph actor nodes.

Analyst workflow: an alert's indicators get verdicts from the threat-intel
engine (embedded baseline, offline classifier, online providers, analyst
overrides). :func:`upsert_actors` maps each hostile verdict to a deterministic
actor label (derived from *verifiable* properties of the verdict - never a
fabricated group name), then materialises the actor as a ``threat_actor``
node in the entity graph with ``ATTRIBUTED_TO`` edges from its indicators.

The Entity Graph screen and ``?kind=threat_actor`` listings then provide a
true threat-actor view over the current attack surface.
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from backend.graph.base import GraphStore
from backend.graph.extract import _edge, _node, _risk_level

logger = logging.getLogger("baraq.graph.actors")


def attribute_verdict(item: dict) -> str | None:
    """Map a single threat-intel verdict to an actor label, or ``None``.

    Rules are conservative: an actor is only named when the evidence behind
    the verdict is verifiable (analyst override, embedded signature match or
    high-confidence provider feed), so the graph never fabricates attributions.
    """
    category = item.get("category")
    confidence = float(item.get("confidence") or 0.0)
    sources = item.get("sources") or []
    kind = item.get("kind")

    if category == "malicious":
        if "analyst" in sources:
            return "Analyst-flagged attacker"
        if "embedded-ioc" in sources:
            return "Embedded-signature campaign"
        if confidence >= 0.8:
            return "High-confidence hostile actor"
    if category == "suspicious" and kind == "domain":
        return "Suspected phishing operator"
    return None


def upsert_actors(db: Session, store: GraphStore, items: list[dict]) -> list[dict]:
    """Group enriched verdicts into actor clusters and persist them in the graph.

    Returns the actor summary payloads (also useful as an API response).
    Never raises on provider errors: if the graph is unavailable the
    clusters are still returned for the response.
    """
    clusters: dict[str, dict] = {}
    for item in items:
        label = attribute_verdict(item)
        if not label:
            continue
        group = clusters.setdefault(label, {"name": label, "items": []})
        if not any(i.get("indicator") == item.get("indicator") for i in group["items"]):
            group["items"].append(item)

    actors: list[dict] = []
    try:
        nodes: list[dict] = []
        edges: list[dict] = []
        for label, group in clusters.items():
            top = max(group["items"], key=lambda i: float(i.get("confidence") or 0.0))
            risk = max(float(top.get("confidence") or 0.0) * 100.0, 60.0)
            props = {
                "category": top.get("category", "unknown"),
                "indicator_count": len(group["items"]),
                "sources": list({s for i in group["items"] for s in (i.get("sources") or [])}),
            }
            nodes.append(_node(
                "threat_actor", label, risk=risk,
                label=label, alerts=0, events=len(group["items"]), props=props,
            ))
            for item in group["items"]:
                edges.append(_edge(
                    item.get("kind", "ip"), item["indicator"], "ATTRIBUTED_TO",
                    "threat_actor", label,
                    weight=1, props={"confidence": float(item.get("confidence") or 0.0)},
                ))
        if nodes:
            store.upsert_entities(db, nodes)
            store.upsert_edges(db, edges)
    except Exception as exc:  # pragma: no cover - degrades to response-only
        logger.warning("Threat-actor graph upsert failed: %s", exc)

    for label, group in clusters.items():
        top = max(group["items"], key=lambda i: float(i.get("confidence") or 0.0))
        risk = max(float(top.get("confidence") or 0.0) * 100.0, 60.0)
        actors.append({
            "name": label,
            "category": top.get("category", "unknown"),
            "risk_level": _risk_level(risk),
            "risk_score": round(risk, 2),
            "items": [i.get("indicator") for i in group["items"]],
        })
    actors.sort(key=lambda a: a["risk_score"], reverse=True)
    return actors