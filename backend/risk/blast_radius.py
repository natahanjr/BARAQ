"""Blast radius analysis — automated calculation of impact scope."""
import logging
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger("baraq.blast_radius")


class BlastRadiusResult(BaseModel):
    entity: str
    entity_type: str
    direct_connections: int
    total_exposed: int
    risk_level: str
    risk_score: float
    exposed_entities: list[dict] = []
    attack_paths: list[str] = []


class BlastRadiusAnalyzer:
    def __init__(self, graph_store=None):
        self._graph = graph_store

    def calculate(self, entity: str, entity_type: str, connections: list[dict]) -> BlastRadiusResult:
        direct = len(connections)
        total = direct
        for conn in connections:
            total += len(conn.get("second_degree", []))
        if total > 50:
            risk_level = "critical"
        elif total > 20:
            risk_level = "high"
        elif total > 5:
            risk_level = "medium"
        else:
            risk_level = "low"
        risk_score = min(total / 50.0 * 100, 100.0)
        paths = []
        for conn in connections:
            target = conn.get("target", "")
            rel = conn.get("relationship", "connected_to")
            paths.append(f"{entity} --[{rel}]--> {target}")
        return BlastRadiusResult(
            entity=entity, entity_type=entity_type,
            direct_connections=direct, total_exposed=total,
            risk_level=risk_level, risk_score=round(risk_score, 1),
            exposed_entities=connections, attack_paths=paths,
        )

    def user_blast_radius(self, username: str, hosts: list[str], processes: list[str], ips: list[str]) -> BlastRadiusResult:
        connections = []
        for h in hosts:
            connections.append({"target": h, "relationship": "logged_into", "type": "host"})
        for p in processes:
            connections.append({"target": p, "relationship": "executed", "type": "process"})
        for ip in ips:
            connections.append({"target": ip, "relationship": "connected_to", "type": "ip"})
        return self.calculate(username, "user", connections)

    def host_blast_radius(self, hostname: str, users: list[str], processes: list[str], network: list[str]) -> BlastRadiusResult:
        connections = []
        for u in users:
            connections.append({"target": u, "relationship": "has_user", "type": "user"})
        for p in processes:
            connections.append({"target": p, "relationship": "runs", "type": "process"})
        for n in network:
            connections.append({"target": n, "relationship": "connects_to", "type": "ip"})
        return self.calculate(hostname, "host", connections)
