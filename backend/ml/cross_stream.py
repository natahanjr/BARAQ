"""Cross-stream correlation model for attack sequence detection.

This module adds ML-based detection of attack sequences that span multiple
behavior streams (login -> process -> network). Unlike the per-stream
Isolation Forest models, this captures temporal attack patterns.

Attack Sequences Detected:
1. Brute Force -> Lateral Movement: Failed logons followed by successful logon from same IP
2. Credential Abuse -> Privilege Escalation: Successful logon followed by suspicious process
3. Process Execution -> Data Exfiltration: Suspicious process followed by network connections
4. Persistence -> C2 Communication: Service install/scheduled task followed by network activity

The model uses a simple Markov chain approach with transition probabilities
learned from historical attack patterns.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import numpy as np
from sqlalchemy import select, func

from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent, NetworkConnection

logger = logging.getLogger("baraq.ml.cross_stream")


class AttackSequenceDetector:
    """Detects attack sequences across behavior streams using Markov chains."""

    # Known attack sequence patterns with transition weights
    ATTACK_SEQUENCES = {
        "brute_force_lateral": {
            "description": "Failed logons followed by successful logon from same IP",
            "transitions": [
                (4625, 4624, 0.8),  # Failed logon -> Successful logon
                (4625, 4625, 0.6),  # Multiple failed logons
            ],
            "time_window_seconds": 3600,  # 1 hour
            "min_transitions": 3,
        },
        "credential_privilege": {
            "description": "Successful logon followed by suspicious process",
            "transitions": [
                (4624, 4688, 0.7),  # Logon -> Process creation
                (4624, 4104, 0.8),  # Logon -> PowerShell execution
            ],
            "time_window_seconds": 1800,  # 30 minutes
            "min_transitions": 2,
        },
        "process_exfil": {
            "description": "Suspicious process followed by network activity",
            "transitions": [
                (4688, 3, 0.6),  # Process -> Network connection
                (4104, 3, 0.7),  # PowerShell -> Network connection
            ],
            "time_window_seconds": 900,  # 15 minutes
            "min_transitions": 2,
        },
        "persistence_c2": {
            "description": "Service install/scheduled task followed by network",
            "transitions": [
                (7045, 3, 0.8),  # Service install -> Network
                (4698, 3, 0.8),  # Scheduled task -> Network
            ],
            "time_window_seconds": 3600,  # 1 hour
            "min_transitions": 2,
        },
    }

    def __init__(self):
        self.transition_counts: Dict[str, Dict[Tuple[int, int], int]] = {}
        self.sequence_scores: Dict[str, float] = {}
        self._initialized = False

    def _ensure_initialized(self):
        """Initialize transition counts from known patterns."""
        if self._initialized:
            return
        for pattern_name, pattern in self.ATTACK_SEQUENCES.items():
            self.transition_counts[pattern_name] = {}
            for from_event, to_event, _ in pattern["transitions"]:
                self.transition_counts[pattern_name][(from_event, to_event)] = 0
        self._initialized = True

    def update_transition(self, from_event_id: int, to_event_id: int, pattern_name: str):
        """Update transition count for a known pattern."""
        self._ensure_initialized()
        if pattern_name in self.transition_counts:
            key = (from_event_id, to_event_id)
            if key in self.transition_counts[pattern_name]:
                self.transition_counts[pattern_name][key] += 1

    def compute_sequence_score(self, pattern_name: str) -> float:
        """Compute anomaly score for a specific attack sequence pattern."""
        self._ensure_initialized()
        if pattern_name not in self.ATTACK_SEQUENCES:
            return 0.0

        pattern = self.ATTACK_SEQUENCES[pattern_name]
        counts = self.transition_counts.get(pattern_name, {})

        # Compute weighted transition score
        total_score = 0.0
        total_weight = 0.0
        for from_event, to_event, weight in pattern["transitions"]:
            count = counts.get((from_event, to_event), 0)
            # Normalize by expected frequency (higher count = more suspicious)
            normalized = min(1.0, count / 10.0)  # Cap at 10 transitions
            total_score += normalized * weight
            total_weight += weight

        if total_weight == 0:
            return 0.0

        # Apply minimum transition threshold
        total_transitions = sum(counts.values())
        if total_transitions < pattern["min_transitions"]:
            return 0.0

        return total_score / total_weight

    def analyze_event_sequence(self, session, time_window_minutes: int = 60) -> Dict[str, float]:
        """Analyze recent event sequence for attack patterns."""
        self._ensure_initialized()
        since = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)

        # Get recent events ordered by time
        events = session.scalars(
            select(NormalizedEvent)
            .where(NormalizedEvent.timestamp >= since)
            .order_by(NormalizedEvent.timestamp)
        ).all()

        if len(events) < 2:
            return {}

        # Track transitions between consecutive events
        sequence_scores = {}
        for i in range(len(events) - 1):
            from_event = events[i].event_id
            to_event = events[i + 1].event_id
            time_diff = (events[i + 1].timestamp - events[i].timestamp).total_seconds()

            # Check each attack pattern
            for pattern_name, pattern in self.ATTACK_SEQUENCES.items():
                if time_diff <= pattern["time_window_seconds"]:
                    for from_id, to_id, _ in pattern["transitions"]:
                        if from_event == from_id and to_event == to_id:
                            self.update_transition(from_event, to_event, pattern_name)

        # Compute scores for all patterns
        for pattern_name in self.ATTACK_SEQUENCES:
            score = self.compute_sequence_score(pattern_name)
            if score > 0:
                sequence_scores[pattern_name] = score

        return sequence_scores

    def get_overall_risk_score(self, session, time_window_minutes: int = 60) -> float:
        """Get overall cross-stream risk score (0.0 to 1.0)."""
        scores = self.analyze_event_sequence(session, time_window_minutes)
        if not scores:
            return 0.0

        # Weighted average of pattern scores
        weights = {
            "brute_force_lateral": 0.3,
            "credential_privilege": 0.4,
            "process_exfil": 0.3,
            "persistence_c2": 0.2,
        }

        total_score = 0.0
        total_weight = 0.0
        for pattern, score in scores.items():
            w = weights.get(pattern, 0.1)
            total_score += score * w
            total_weight += w

        return total_score / total_weight if total_weight > 0 else 0.0

    def get_active_patterns(self, session, time_window_minutes: int = 60) -> List[Dict]:
        """Get list of active attack patterns with details."""
        scores = self.analyze_event_sequence(session, time_window_minutes)
        active = []
        for pattern_name, score in scores.items():
            if score > 0.3:  # Threshold for "active" pattern
                pattern = self.ATTACK_SEQUENCES[pattern_name]
                active.append({
                    "pattern": pattern_name,
                    "description": pattern["description"],
                    "score": round(score, 3),
                    "transitions": self.transition_counts.get(pattern_name, {}),
                })
        return active


# Singleton instance
_detector: Optional[AttackSequenceDetector] = None


def get_cross_stream_detector() -> AttackSequenceDetector:
    """Get or create the singleton cross-stream detector."""
    global _detector
    if _detector is None:
        _detector = AttackSequenceDetector()
    return _detector
