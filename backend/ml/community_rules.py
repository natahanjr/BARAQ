"""Community rule contribution framework.

Enables external contributors to submit detection rules (Sigma, YAML correlation,
or Python native) with validation, review workflow, and approval pipeline.

Workflow:
1. Contributor submits rule via API/file
2. Automated validation (syntax, schema, required fields)
3. Peer review queue (analyst approval)
4. Approved rules auto-integrated into detection engine
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

import yaml

logger = logging.getLogger("baraq.ml.community_rules")


class RuleStatus(str, Enum):
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    DEPRECATED = "deprecated"


class RuleType(str, Enum):
    SIGMA = "sigma"
    CORRELATION_YAML = "correlation_yaml"
    PYTHON_NATIVE = "python_native"


@dataclass
class ContributedRule:
    """A community-contributed detection rule."""
    rule_id: str
    rule_type: RuleType
    title: str
    description: str
    content: str  # Raw rule content (YAML or Python)
    author: str
    author_org: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    severity: str = "medium"
    confidence: float = 0.5
    status: RuleStatus = RuleStatus.PENDING
    submitted_at: str = ""
    reviewed_at: str = ""
    reviewer: str = ""
    review_notes: str = ""
    validation_errors: list[str] = field(default_factory=list)
    validation_warnings: list[str] = field(default_factory=list)
    fingerprint: str = ""

    def __post_init__(self):
        if not self.submitted_at:
            self.submitted_at = datetime.now(UTC).isoformat()
        if not self.fingerprint:
            self.fingerprint = self._compute_fingerprint()

    def _compute_fingerprint(self) -> str:
        content_hash = hashlib.sha256(self.content.encode()).hexdigest()[:12]
        return f"CR-{self.rule_type.value[:3].upper()}-{content_hash}"


class RuleValidator:
    """Validates contributed rules against schema and best practices."""

    REQUIRED_FIELDS_SIGMA = {"title", "detection"}
    REQUIRED_FIELDS_CORRELATION = {"name", "description", "stages", "window_minutes"}
    SEVERITY_LEVELS = {"low", "medium", "high", "critical"}
    MAX_RULE_SIZE = 50_000  # 50KB max

    def validate_sigma(self, content: str) -> tuple[bool, list[str], list[str]]:
        """Validate a Sigma rule."""
        errors = []
        warnings = []

        if len(content) > self.MAX_RULE_SIZE:
            errors.append(f"Rule exceeds max size ({len(content)} > {self.MAX_RULE_SIZE})")
            return False, errors, warnings

        try:
            rule = yaml.safe_load(content)
        except yaml.YAMLError as e:
            errors.append(f"YAML parse error: {e}")
            return False, errors, warnings

        if not isinstance(rule, dict):
            errors.append("Rule must be a YAML mapping")
            return False, errors, warnings

        # Check required fields
        missing = self.REQUIRED_FIELDS_SIGMA - set(rule.keys())
        if missing:
            errors.append(f"Missing required fields: {missing}")

        # Validate level
        level = rule.get("level", "").lower()
        if level and level not in self.SEVERITY_LEVELS:
            warnings.append(f"Non-standard severity level: {level}")

        # Validate detection section
        detection = rule.get("detection")
        if detection and not isinstance(detection, (dict, list)):
            errors.append("'detection' must be a mapping or sequence")

        # Check for MITRE tags
        tags = rule.get("tags", [])
        if not tags:
            warnings.append("No MITRE ATT&CK tags found")

        return len(errors) == 0, errors, warnings

    def validate_correlation(self, content: str) -> tuple[bool, list[str], list[str]]:
        """Validate a correlation rule YAML."""
        errors = []
        warnings = []

        try:
            rule = yaml.safe_load(content)
        except yaml.YAMLError as e:
            errors.append(f"YAML parse error: {e}")
            return False, errors, warnings

        if not isinstance(rule, dict):
            errors.append("Rule must be a YAML mapping")
            return False, errors, warnings

        missing = self.REQUIRED_FIELDS_CORRELATION - set(rule.keys())
        if missing:
            errors.append(f"Missing required fields: {missing}")

        # Validate stages
        stages = rule.get("stages", [])
        if not isinstance(stages, list) or len(stages) < 2:
            errors.append("Correlation rule must have at least 2 stages")

        # Validate window
        window = rule.get("window_minutes")
        if window is not None:
            if not isinstance(window, (int, float)) or window <= 0:
                errors.append("window_minutes must be a positive number")
            elif window > 1440:
                warnings.append("Window > 24 hours is unusually large")

        return len(errors) == 0, errors, warnings

    def validate_python_native(self, content: str) -> tuple[bool, list[str], list[str]]:
        """Validate a Python native rule (syntax check only)."""
        errors = []
        warnings = []

        if len(content) > self.MAX_RULE_SIZE:
            errors.append(f"Rule exceeds max size ({len(content)} > {self.MAX_RULE_SIZE})")
            return False, errors, warnings

        try:
            compile(content, "<community_rule>", "exec")
        except SyntaxError as e:
            errors.append(f"Python syntax error: {e}")
            return False, errors, warnings

        # Check for required class
        if "class" not in content:
            warnings.append("No class definition found; rules should inherit from BaseRule")

        if "BaseRule" not in content and "Detector" not in content:
            warnings.append("Rule doesn't inherit from BaseRule or Detector")

        return len(errors) == 0, errors, warnings


class CommunityRuleManager:
    """Manages the lifecycle of community-contributed rules."""

    def __init__(self, storage_dir: str | Path | None = None):
        self.validator = RuleValidator()
        self._rules: dict[str, ContributedRule] = {}
        self._storage_dir = Path(storage_dir) if storage_dir else None

    def submit_rule(
        self,
        rule_type: RuleType,
        title: str,
        description: str,
        content: str,
        author: str,
        author_org: str = "",
        mitre_tactic: str = "",
        mitre_technique: str = "",
        severity: str = "medium",
    ) -> ContributedRule:
        """Submit a new community rule for review."""
        rule = ContributedRule(
            rule_id="",
            rule_type=rule_type,
            title=title,
            description=description,
            content=content,
            author=author,
            author_org=author_org,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            severity=severity,
        )

        # Validate
        if rule_type == RuleType.SIGMA:
            valid, errors, warnings = self.validator.validate_sigma(content)
        elif rule_type == RuleType.CORRELATION_YAML:
            valid, errors, warnings = self.validator.validate_correlation(content)
        elif rule_type == RuleType.PYTHON_NATIVE:
            valid, errors, warnings = self.validator.validate_python_native(content)
        else:
            valid, errors, warnings = False, [f"Unknown rule type: {rule_type}"], []

        rule.validation_errors = errors
        rule.validation_warnings = warnings

        if not valid:
            rule.status = RuleStatus.REJECTED
            rule.review_notes = f"Auto-rejected: {'; '.join(errors)}"
        else:
            rule.status = RuleStatus.PENDING

        rule.rule_id = rule.fingerprint
        self._rules[rule.rule_id] = rule

        logger.info(
            "Rule submitted: %s by %s (valid=%s, errors=%d, warnings=%d)",
            rule.rule_id, author, valid, len(errors), len(warnings),
        )

        return rule

    def review_rule(
        self,
        rule_id: str,
        reviewer: str,
        approved: bool,
        notes: str = "",
    ) -> ContributedRule | None:
        """Review and approve/reject a submitted rule."""
        rule = self._rules.get(rule_id)
        if rule is None:
            return None

        if rule.status not in (RuleStatus.PENDING, RuleStatus.UNDER_REVIEW):
            logger.warning("Rule %s cannot be reviewed (status=%s)", rule_id, rule.status)
            return rule

        rule.reviewer = reviewer
        rule.reviewed_at = datetime.now(UTC).isoformat()
        rule.review_notes = notes

        if approved:
            rule.status = RuleStatus.APPROVED
            self._persist_rule(rule)
        else:
            rule.status = RuleStatus.REJECTED

        logger.info("Rule %s %s by %s", rule_id, "approved" if approved else "rejected", reviewer)
        return rule

    def _persist_rule(self, rule: ContributedRule):
        """Persist an approved rule to disk."""
        if self._storage_dir is None:
            return

        self._storage_dir.mkdir(parents=True, exist_ok=True)
        if rule.rule_type == RuleType.SIGMA:
            out_path = self._storage_dir / f"{rule.rule_id}.yml"
        elif rule.rule_type == RuleType.CORRELATION_YAML:
            out_path = self._storage_dir / f"{rule.rule_id}.yml"
        else:
            out_path = self._storage_dir / f"{rule.rule_id}.py"

        out_path.write_text(rule.content, encoding="utf-8")
        logger.info("Persisted approved rule to %s", out_path)

    def get_rule(self, rule_id: str) -> ContributedRule | None:
        return self._rules.get(rule_id)

    def list_rules(self, status: RuleStatus | None = None) -> list[ContributedRule]:
        rules = list(self._rules.values())
        if status is not None:
            rules = [r for r in rules if r.status == status]
        return sorted(rules, key=lambda r: r.submitted_at, reverse=True)

    def get_pending_review(self) -> list[ContributedRule]:
        return self.list_rules(RuleStatus.PENDING)

    def get_statistics(self) -> dict:
        total = len(self._rules)
        by_status = {}
        for rule in self._rules.values():
            by_status[rule.status.value] = by_status.get(rule.status.value, 0) + 1
        by_type = {}
        for rule in self._rules.values():
            by_type[rule.rule_type.value] = by_type.get(rule.rule_type.value, 0) + 1

        return {
            "total_submitted": total,
            "by_status": by_status,
            "by_type": by_type,
            "approval_rate": round(by_status.get("approved", 0) / max(total, 1), 4),
        }
