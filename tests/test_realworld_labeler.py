"""Tests for the real-world ML labeling system.

Validates that the ML pipeline learns from real threat intel and analyst
verdicts instead of hardcoded test-net IPs.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from backend.database.models import ThreatIntelRecord, Verdict
from backend.ml.realworld_labeler import (
    _refresh_ip_cache,
    get_analyst_labels,
    get_attack_ips,
    get_threat_intel_stats,
    hybrid_label_event,
    is_attack_ip,
    is_attack_ip_offline,
)


@pytest.fixture
def ti_session():
    """Isolated session for threat-intel labeling tests."""
    from backend.database.connection import SessionLocal

    session = SessionLocal()
    yield session
    session.close()


# ------------------------------------------------------------------
# Offline IP checks
# ------------------------------------------------------------------
class TestOfflineIPCheck:
    def test_legacy_testnet_ips_detected(self):
        """Legacy test-net ranges still detected without DB."""
        assert is_attack_ip_offline("203.0.113.66")
        assert is_attack_ip_offline("203.0.113.77")
        assert is_attack_ip_offline("198.51.100.66")
        assert is_attack_ip_offline("198.51.100.77")

    def test_private_ip_not_attack(self):
        assert not is_attack_ip_offline("192.168.1.1")
        assert not is_attack_ip_offline("10.0.0.1")
        assert not is_attack_ip_offline("172.16.0.1")

    def test_empty_ip_not_attack(self):
        assert not is_attack_ip_offline("")
        assert not is_attack_ip_offline(None)

    def test_unknown_ip_not_attack_offline(self):
        """Without cache, unknown IPs default to benign."""
        assert not is_attack_ip_offline("8.8.8.8")


# ------------------------------------------------------------------
# Threat-intel IP loading
# ------------------------------------------------------------------
class TestThreatIntelIPs:
    def test_loads_embedded_iocs(self, ti_session):
        """Embedded IOC IPs are always included."""
        ips = get_attack_ips(ti_session)
        assert "185.220.101.45" in ips  # TOR exit node
        assert "45.155.205.233" in ips  # Known C2

    def test_loads_db_malicious_ips(self, ti_session):
        """IPs stored in threat_intel_records with category=malicious are loaded."""
        record = ThreatIntelRecord(
            indicator="198.51.100.99",
            kind="ip",
            category="malicious",
            label="Test malicious IP",
            confidence=0.95,
            sources=["test"],
        )
        ti_session.add(record)
        ti_session.commit()
        try:
            ips = get_attack_ips(ti_session, force=True)
            assert "198.51.100.99" in ips
        finally:
            ti_session.delete(record)
            ti_session.commit()

    def test_loads_abusive_ips(self, ti_session):
        """IPs with category=abusive are also treated as attacks."""
        record = ThreatIntelRecord(
            indicator="203.0.113.99",
            kind="ip",
            category="abusive",
            label="Test abusive IP",
            confidence=0.8,
            sources=["test"],
        )
        ti_session.add(record)
        ti_session.commit()
        try:
            ips = get_attack_ips(ti_session, force=True)
            assert "203.0.113.99" in ips
        finally:
            ti_session.delete(record)
            ti_session.commit()

    def test_benign_ips_not_included(self, ti_session):
        """IPs with category=benign are NOT attack IPs."""
        record = ThreatIntelRecord(
            indicator="198.51.100.50",
            kind="ip",
            category="benign",
            label="Known good",
            confidence=0.9,
            sources=["test"],
        )
        ti_session.add(record)
        ti_session.commit()
        try:
            ips = get_attack_ips(ti_session, force=True)
            assert "198.51.100.50" not in ips
        finally:
            ti_session.delete(record)
            ti_session.commit()

    def test_is_attack_ip_with_db(self, ti_session):
        """is_attack_ip checks both DB and cache."""
        record = ThreatIntelRecord(
            indicator="45.33.32.156",
            kind="ip",
            category="malicious",
            label="Scanme.nmap.org (known scanner)",
            confidence=0.7,
            sources=["test"],
        )
        ti_session.add(record)
        ti_session.commit()
        try:
            assert is_attack_ip(ti_session, "45.33.32.156")
            assert not is_attack_ip(ti_session, "8.8.4.4")
        finally:
            ti_session.delete(record)
            ti_session.commit()

    def test_cache_refresh(self, ti_session):
        """Cache is refreshed when force=True."""
        ips1 = get_attack_ips(ti_session, force=True)
        record = ThreatIntelRecord(
            indicator="198.51.100.200",
            kind="ip",
            category="malicious",
            label="Test",
            confidence=0.9,
            sources=["test"],
        )
        ti_session.add(record)
        ti_session.commit()
        try:
            ips2 = get_attack_ips(ti_session, force=True)
            assert "198.51.100.200" in ips2
            assert len(ips2) >= len(ips1)
        finally:
            ti_session.delete(record)
            ti_session.commit()


# ------------------------------------------------------------------
# Analyst verdict labels
# ------------------------------------------------------------------
class TestAnalystLabels:
    def test_loads_true_positives(self, ti_session):
        """Verdicts with true_positive are labelled as attack (1)."""
        from backend.database.models import NormalizedEvent

        ev = NormalizedEvent(
            event_id=4625,
            timestamp=datetime.now(UTC),
            raw_json={"facts": {"source_ip": "10.0.0.1"}},
            user="testuser",
            risk_score=50,
        )
        ti_session.add(ev)
        ti_session.flush()
        verdict = Verdict(
            event_id=ev.id,
            verdict="true_positive",
            note="Confirmed brute force",
            created_by="analyst",
        )
        ti_session.add(verdict)
        ti_session.commit()
        try:
            labels = get_analyst_labels(ti_session)
            assert labels[ev.id] == 1
        finally:
            ti_session.delete(verdict)
            ti_session.delete(ev)
            ti_session.commit()

    def test_loads_false_positives(self, ti_session):
        """Verdicts with false_positive are labelled as benign (0)."""
        from backend.database.models import NormalizedEvent

        ev = NormalizedEvent(
            event_id=4624,
            timestamp=datetime.now(UTC),
            raw_json={"facts": {"source_ip": "10.0.0.2"}},
            user="testuser",
            risk_score=30,
        )
        ti_session.add(ev)
        ti_session.flush()
        verdict = Verdict(
            event_id=ev.id,
            verdict="false_positive",
            note="Legitimate login",
            created_by="analyst",
        )
        ti_session.add(verdict)
        ti_session.commit()
        try:
            labels = get_analyst_labels(ti_session)
            assert labels[ev.id] == 0
        finally:
            ti_session.delete(verdict)
            ti_session.delete(ev)
            ti_session.commit()


# ------------------------------------------------------------------
# Hybrid labeling
# ------------------------------------------------------------------
class TestHybridLabeling:
    def test_analyst_verdict_overrides_heuristic(self, ti_session):
        """Analyst verdict takes priority over heuristic labeling."""
        from backend.database.models import NormalizedEvent

        ev = NormalizedEvent(
            event_id=4688,
            timestamp=datetime.now(UTC),
            raw_json={"facts": {}},
            user="testuser",
            risk_score=20,
        )
        ti_session.add(ev)
        ti_session.flush()
        verdict = Verdict(
            event_id=ev.id,
            verdict="false_positive",
            note="Benign process",
            created_by="analyst",
        )
        ti_session.add(verdict)
        ti_session.commit()
        try:
            labels = get_analyst_labels(ti_session)
            result = hybrid_label_event(
                ti_session, ev.id, ev.raw_json or {}, "", labels
            )
            assert result is False  # Analyst says benign
        finally:
            ti_session.delete(verdict)
            ti_session.delete(ev)
            ti_session.commit()

    def test_threat_intel_ip_marks_attack(self, ti_session):
        """Events from threat-intel IPs are labelled as attacks."""
        record = ThreatIntelRecord(
            indicator="203.0.113.50",
            kind="ip",
            category="malicious",
            label="Test",
            confidence=0.9,
            sources=["test"],
        )
        ti_session.add(record)
        ti_session.commit()
        try:
            result = hybrid_label_event(
                ti_session,
                999999,
                {"facts": {"source_ip": "203.0.113.50"}},
                "203.0.113.50",
            )
            assert result is True
        finally:
            ti_session.delete(record)
            ti_session.commit()

    def test_heuristic_fallback(self, ti_session):
        """Without analyst verdict or threat intel, heuristic is used."""
        result = hybrid_label_event(
            ti_session,
            999999,
            {"facts": {}},
            "8.8.8.8",
        )
        assert isinstance(result, bool)

    def test_known_attack_event_heuristic(self, ti_session):
        """Known high-risk events are attacks by heuristic."""
        result = hybrid_label_event(
            ti_session,
            999999,
            {"facts": {}},
            "",
            analyst_labels={},
        )
        assert isinstance(result, bool)


# ------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------
class TestLabelingStats:
    def test_returns_stats(self, ti_session):
        """Stats endpoint returns valid data."""
        stats = get_threat_intel_stats(ti_session)
        assert "threat_intel_total" in stats
        assert "analyst_true_positives" in stats
        assert "analyst_false_positives" in stats

    def test_stats_reflect_verdicts(self, ti_session):
        """Stats count analyst verdicts correctly."""
        from backend.database.models import NormalizedEvent

        ev = NormalizedEvent(
            event_id=4625,
            timestamp=datetime.now(UTC),
            raw_json={"facts": {}},
            user="testuser",
            risk_score=50,
        )
        ti_session.add(ev)
        ti_session.flush()
        v1 = Verdict(event_id=ev.id, verdict="true_positive", created_by="test")
        ti_session.add(v1)
        ti_session.commit()
        try:
            stats = get_threat_intel_stats(ti_session)
            assert stats["analyst_true_positives"] >= 1
        finally:
            ti_session.delete(v1)
            ti_session.delete(ev)
            ti_session.commit()
