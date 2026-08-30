"""Detector registry tests (Phase 2)."""

from __future__ import annotations

from backend.detection.registry import Registry, default_registry
from tests.detection.helpers import event


def test_default_registry_has_five_detectors_in_order():
    registry = default_registry()
    ids = [d.id for d in registry.all()]
    assert ids == ["D001", "D002", "D003", "D004", "D005"]
    assert all(d.version for d in registry.all())
    assert all(d.enabled for d in registry.all())


def test_registry_duplicate_raises():
    registry = Registry()
    from backend.detection.detectors.d001_external_rdp import ExternalRDPDetector

    registry.register(ExternalRDPDetector())
    try:
        registry.register(ExternalRDPDetector())
        raise AssertionError("duplicate registration must raise")
    except ValueError:
        pass


def test_detector_supports_event_type():
    registry = default_registry()
    auth_event = event(
        event_type="authentication",
        action="logon",
        facts={"logon_type": 10},
        network={"src_ip": "203.0.113.5"},
    )
    process_event = event(
        event_type="process", action="process_start", process={"name": "python.exe"}
    )
    file_event = event(event_type="file", action="file_modify")

    d001 = registry.get("D001")
    d002 = registry.get("D002")
    d003 = registry.get("D003")
    d005 = registry.get("D005")
    assert d001.supports(auth_event)
    assert not d001.supports(process_event)
    assert d002.supports(auth_event)
    assert not d002.supports(process_event)
    assert d003.supports(process_event)
    assert not d003.supports(auth_event)
    assert d005.supports(file_event)  # empty = any
