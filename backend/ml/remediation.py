"""Automated remediation suggestions from false negative reports.

Analyzes FN (false negative) reports to generate actionable remediation
suggestions for improving ML detection accuracy.

Workflow:
1. FN reports collected (attacks the ML missed)
2. Pattern analysis: what features were present, what was missing
3. Rule/feature recommendations generated
4. Prioritized action items for analysts
"""

from __future__ import annotations

import logging
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime

import numpy as np

logger = logging.getLogger("baraq.ml.remediation")


@dataclass
class FNReport:
    """A false negative report (attack missed by ML)."""
    report_id: str
    event_id: int
    timestamp: str
    attack_type: str
    mitre_technique: str = ""
    features_present: list[str] = field(default_factory=list)
    features_missing: list[str] = field(default_factory=list)
    ml_score: float = 0.0
    threshold: float = 0.5
    stream: str = "login"
    severity: str = "high"


@dataclass
class RemediationAction:
    """A suggested remediation action."""
    action_id: str
    priority: int  # 1=highest
    category: str  # "feature", "threshold", "training", "rule"
    title: str
    description: str
    estimated_impact: str  # "high", "medium", "low"
    effort: str  # "low", "medium", "high"
    mitre_technique: str = ""
    related_fns: list[str] = field(default_factory=list)


class RemediationEngine:
    """Analyzes FN patterns and generates remediation suggestions."""

    def __init__(self):
        self._fn_reports: list[FNReport] = []
        self._action_counter = 0

    def add_fn_report(self, report: FNReport):
        """Add a false negative report."""
        self._fn_reports.append(report)

    def analyze_patterns(self) -> dict:
        """Analyze patterns across all FN reports."""
        if not self._fn_reports:
            return {"total_fns": 0, "patterns": {}}

        # Attack type distribution
        attack_types = Counter(r.attack_type for r in self._fn_reports)

        # MITRE technique distribution
        mitre_techniques = Counter(r.mitre_technique for r in self._fn_reports if r.mitre_technique)

        # Stream distribution
        streams = Counter(r.stream for r in self._fn_reports)

        # Feature analysis
        all_present = []
        all_missing = []
        for r in self._fn_reports:
            all_present.extend(r.features_present)
            all_missing.extend(r.features_missing)

        present_freq = Counter(all_present).most_common(10)
        missing_freq = Counter(all_missing).most_common(10)

        # Score distribution
        scores = [r.ml_score for r in self._fn_reports]
        thresholds = [r.threshold for r in self._fn_reports]
        margin_analysis = [
            {"score": s, "threshold": t, "margin": t - s}
            for s, t in zip(scores, thresholds)
        ]

        # Severity distribution
        severities = Counter(r.severity for r in self._fn_reports)

        return {
            "total_fns": len(self._fn_reports),
            "attack_types": dict(attack_types),
            "mitre_techniques": dict(mitre_techniques),
            "streams": dict(streams),
            "top_present_features": present_freq,
            "top_missing_features": missing_freq,
            "score_stats": {
                "mean": round(float(np.mean(scores)), 4) if scores else 0.0,
                "std": round(float(np.std(scores)), 4) if scores else 0.0,
                "min": round(float(np.min(scores)), 4) if scores else 0.0,
                "max": round(float(np.max(scores)), 4) if scores else 0.0,
            },
            "margin_stats": {
                "mean_margin": round(float(np.mean([m["margin"] for m in margin_analysis])), 4),
                "max_margin": round(float(np.max([m["margin"] for m in margin_analysis])), 4) if margin_analysis else 0.0,
            },
            "severities": dict(severities),
        }

    def generate_remediations(self) -> list[RemediationAction]:
        """Generate prioritized remediation actions based on FN analysis."""
        patterns = self.analyze_patterns()
        if patterns["total_fns"] == 0:
            return []

        actions = []
        self._action_counter = 0

        # 1. Threshold adjustment suggestions
        margin_stats = patterns.get("margin_stats", {})
        mean_margin = margin_stats.get("mean_margin", 0)
        if mean_margin > 0.05:
            actions.append(self._create_action(
                priority=1,
                category="threshold",
                title="Lower anomaly threshold",
                description=(
                    f"FN events have mean margin of {mean_margin:.3f} below threshold. "
                    f"Consider lowering threshold by {mean_margin * 0.5:.3f} to capture more attacks."
                ),
                estimated_impact="high",
                effort="low",
            ))

        # 2. Feature engineering suggestions
        missing_features = patterns.get("top_missing_features", [])
        if missing_features:
            top_missing = [f[0] for f in missing_features[:3]]
            actions.append(self._create_action(
                priority=2,
                category="feature",
                title="Add missing feature extractors",
                description=(
                    f"FN events consistently lack these features: {', '.join(top_missing)}. "
                    f"Consider adding feature extractors for these signals."
                ),
                estimated_impact="high",
                effort="medium",
            ))

        # 3. Training data augmentation
        attack_types = patterns.get("attack_types", {})
        if attack_types:
            rare_attacks = [k for k, v in attack_types.items() if v <= 2]
            if rare_attacks:
                actions.append(self._create_action(
                    priority=3,
                    category="training",
                    title="Augment training data for rare attack types",
                    description=(
                        f"These attack types appear infrequently in training: {', '.join(rare_attacks)}. "
                        f"Generate synthetic samples or import from public datasets."
                    ),
                    estimated_impact="medium",
                    effort="medium",
                ))

        # 4. Stream-specific model improvements
        streams = patterns.get("streams", {})
        for stream, count in streams.items():
            if count >= 3:
                actions.append(self._create_action(
                    priority=3,
                    category="training",
                    title=f"Retrain {stream} stream model",
                    description=(
                        f"{count} FNs occurred in the {stream} stream. "
                        f"Consider retraining with extended window or higher contamination."
                    ),
                    estimated_impact="medium",
                    effort="low",
                ))

        # 5. MITRE-based rule coverage gaps
        mitre_techniques = patterns.get("mitre_techniques", {})
        if mitre_techniques:
            top_techniques = sorted(mitre_techniques.items(), key=lambda x: -x[1])[:3]
            for technique, count in top_techniques:
                if count >= 2:
                    actions.append(self._create_action(
                        priority=2,
                        category="rule",
                        title=f"Add detection rule for {technique}",
                        description=(
                            f"MITRE technique {technique} was missed {count} times. "
                            f"Consider adding a dedicated detection rule or correlation rule."
                        ),
                        estimated_impact="high",
                        effort="medium",
                        mitre_technique=technique,
                    ))

        # 6. Score calibration
        score_stats = patterns.get("score_stats", {})
        if score_stats.get("mean", 0) > 0.3:
            actions.append(self._create_action(
                priority=2,
                category="threshold",
                title="Improve score calibration",
                description=(
                    f"FN events have mean ML score of {score_stats['mean']:.3f} "
                    f"(std={score_stats['std']:.3f}). Consider recalibrating anomaly scores."
                ),
                estimated_impact="medium",
                effort="medium",
            ))

        # Sort by priority
        actions.sort(key=lambda a: a.priority)
        return actions

    def _create_action(self, **kwargs) -> RemediationAction:
        self._action_counter += 1
        return RemediationAction(
            action_id=f"REM-{self._action_counter:04d}",
            **kwargs,
        )

    def get_summary(self) -> dict:
        """Get summary of FN analysis and remediation suggestions."""
        patterns = self.analyze_patterns()
        actions = self.generate_remediations()

        return {
            "fn_summary": patterns,
            "remediation_actions": [
                {
                    "id": a.action_id,
                    "priority": a.priority,
                    "category": a.category,
                    "title": a.title,
                    "description": a.description,
                    "impact": a.estimated_impact,
                    "effort": a.effort,
                }
                for a in actions
            ],
            "total_actions": len(actions),
            "high_priority_count": sum(1 for a in actions if a.priority <= 2),
        }
