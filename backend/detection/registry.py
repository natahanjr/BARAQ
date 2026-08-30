"""Detector interface + registry (Phase 2).

Every detector implements ``evaluate(event, context) -> DETECTION | None``
and is as close as possible to a pure function. Detectors must never:

* create alerts / incidents
* modify entity risk
* execute SOAR
* modify unrelated database records

Versioning from day one: a detector bump (``version``) means detection
behavior changed; the version travels with every detection.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from backend.detection.context import DetectionContext
from backend.detection.contract import DETECTION
from backend.telemetry.contract import EVENT


class Detector(ABC):
    """Base class for all v2 detectors."""

    id: str = ""
    version: str = "1.0.0"
    name: str = ""
    description: str = ""
    enabled: bool = True
    #: Canonical event types this detector consumes (empty = any).
    supported_event_types: tuple[str, ...] = ()

    @abstractmethod
    def evaluate(
        self, event: EVENT, context: DetectionContext | None = None
    ) -> DETECTION | None:
        """Evaluate one canonical EVENT; return a DETECTION or None.

        Deterministic: same event + same context -> same output.
        """
        raise NotImplementedError

    def supports(self, event: EVENT) -> bool:
        return (
            not self.supported_event_types
            or event.event_type in self.supported_event_types
        )

    def describe(self) -> dict:
        return {
            "detector_id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "enabled": self.enabled,
            "supported_event_types": list(self.supported_event_types),
        }


class Registry:
    """Ordered detector registry. Deterministic iteration order."""

    def __init__(self) -> None:
        self._detectors: dict[str, Detector] = {}

    def register(self, detector: Detector) -> None:
        if detector.id in self._detectors:
            raise ValueError(f"detector {detector.id} already registered")
        self._detectors[detector.id] = detector

    def get(self, detector_id: str) -> Detector | None:
        return self._detectors.get(detector_id)

    def all(self) -> list[Detector]:
        return list(self._detectors.values())

    def enabled_detectors(self) -> list[Detector]:
        return [d for d in self._detectors.values() if d.enabled]


def build_default_registry() -> Registry:
    """Registry with the Phase 2 initial detector set (D001-D005)."""
    from backend.detection.detectors.d001_external_rdp import ExternalRDPDetector
    from backend.detection.detectors.d002_brute_force import BruteForceDetector
    from backend.detection.detectors.d003_suspicious_powershell import (
        SuspiciousPowerShellDetector,
    )
    from backend.detection.detectors.d004_python_writable_path import (
        PythonWritablePathDetector,
    )
    from backend.detection.detectors.d005_ransomware_behavior import (
        RansomwareBehaviorDetector,
    )

    registry = Registry()
    for detector in (
        ExternalRDPDetector(),
        BruteForceDetector(),
        SuspiciousPowerShellDetector(),
        PythonWritablePathDetector(),
        RansomwareBehaviorDetector(),
    ):
        registry.register(detector)
    return registry


#: Process-wide default registry (lazy, deterministic).
_registry: Registry | None = None


def default_registry() -> Registry:
    global _registry
    if _registry is None:
        _registry = build_default_registry()
    return _registry
