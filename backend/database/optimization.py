"""Query optimization suite — indexes, slow query detection, and recommendations."""
import logging
import time
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger("baraq.db.optimization")


class SlowQuery(BaseModel):
    query: str
    duration_ms: float
    timestamp: str = ""


class OptimizationRecommendation(BaseModel):
    table: str
    issue: str
    recommendation: str
    priority: str


RECOMMENDED_INDEXES = [
    {"table": "alerts", "columns": ["status", "severity", "created_at"], "name": "idx_alerts_status_severity_created"},
    {"table": "alerts", "columns": ["host"], "name": "idx_alerts_host"},
    {"table": "alerts", "columns": ["user"], "name": "idx_alerts_user"},
    {"table": "alerts", "columns": ["mitre_tactic"], "name": "idx_alerts_mitre_tactic"},
    {"table": "alerts", "columns": ["risk_score"], "name": "idx_alerts_risk_score"},
    {"table": "events", "columns": ["timestamp"], "name": "idx_events_timestamp"},
    {"table": "events", "columns": ["host"], "name": "idx_events_host"},
    {"table": "events", "columns": ["event_type"], "name": "idx_events_type"},
    {"table": "endpoints", "columns": ["health_status"], "name": "idx_endpoints_health"},
    {"table": "audit_log", "columns": ["created_at"], "name": "idx_audit_created"},
    {"table": "entity_risk", "columns": ["entity_type", "risk_score"], "name": "idx_entity_risk_type_score"},
    {"table": "incidents", "columns": ["status", "created_at"], "name": "idx_incidents_status_created"},
]


class QueryOptimizer:
    def __init__(self):
        self._slow_queries: list[SlowQuery] = []

    def record_slow_query(self, query: str, duration_ms: float):
        if duration_ms > 100:
            self._slow_queries.append(SlowQuery(query=query, duration_ms=duration_ms))

    def get_slow_queries(self, threshold_ms: float = 100) -> list[SlowQuery]:
        return [q for q in self._slow_queries if q.duration_ms >= threshold_ms]

    def get_recommendations(self) -> list[OptimizationRecommendation]:
        recs = []
        for idx in RECOMMENDED_INDEXES:
            recs.append(OptimizationRecommendation(
                table=idx["table"],
                issue="Missing recommended index",
                recommendation=f"CREATE INDEX {idx['name']} ON {idx['table']} ({', '.join(idx['columns'])})",
                priority="medium",
            ))
        return recs

    def get_recommended_indexes(self) -> list[dict]:
        return RECOMMENDED_INDEXES
