"""Tests for the C2 beaconing rule's traffic-shape classification.

The rule previously fired on total bytes alone, which flagged a 4.9 GB browser
download as "possible C2 beacon or bulk exfiltration". These tests pin the
distinction: repetition of small transfers is beaconing, a few large transfers
is bulk transfer, and ordinary heavy-use programs are not incidents.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from backend.database.connection import SessionLocal
from backend.database.models import NetworkConnection
from backend.detection.rules.c2_beacon import (
    BENIGN_BULK_PROCESSES,
    BULK_BYTES_THRESHOLD,
    C2BeaconRule,
)


def _conn(process: str, remote: str, sent: int, recv: int, duration: float) -> NetworkConnection:
    return NetworkConnection(
        pid=4242,
        process=process,
        local_ip="10.0.0.5",
        local_port=50000,
        remote_ip=remote,
        remote_port=443,
        state="Established",
        bytes_sent=sent,
        bytes_recv=recv,
        duration_seconds=duration,
        observed_at=datetime.now(UTC) - timedelta(minutes=1),
    )


@pytest.fixture()
def session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()


def test_browser_downloading_is_not_a_beacon(session):
    """One big transfer to a CDN: high volume, no repetition -> not an alert."""
    session.add(_conn("firefox.exe", "142.250.202.226", 4_000_000_000, 900_000_000, 2100.0))
    session.commit()

    findings = C2BeaconRule(session, min_connections=3).evaluate(60)
    assert findings == [], "a 4.9 GB browser download must not alert"


def test_many_large_transfers_from_a_browser_are_suppressed(session):
    """Even 5 x 1 GB from Firefox is browsing, not an incident."""
    for _ in range(5):
        session.add(_conn("firefox.exe", "142.250.202.226", 1_000_000_000, 0, 600.0))
    session.commit()

    findings = C2BeaconRule(session, min_connections=3).evaluate(60)
    assert findings == [], "bulk transfer from a known bulk app must be suppressed"


def test_repeated_small_transfers_are_a_beacon(session):
    """Many small connections to one host: the classic beacon shape."""
    for _ in range(12):
        session.add(_conn("svchost.exe", "203.0.113.77", 100_000, 20_000, 300.0))
    session.commit()

    findings = C2BeaconRule(session).evaluate(60)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "beacon" in findings[0].evidence.lower()
    assert "svchost.exe" in findings[0].evidence


def test_bulk_transfer_from_an_unknown_binary_is_low_not_high(session):
    """Volume alone, from a program we do not recognise, is informational."""
    for _ in range(4):
        session.add(_conn("unknowntool.exe", "45.33.32.156", 80_000_000, 0, 400.0))
    session.commit()

    findings = C2BeaconRule(session).evaluate(60)
    assert len(findings) == 1
    assert findings[0].severity == "low", "volume alone must not page anyone"
    assert findings[0].confidence <= 0.5


def test_benign_bulk_list_covers_the_observed_offenders():
    """The programs that produced the real false positives are all listed."""
    for process in ("firefox.exe", "msedge.exe", "Telegram.exe", "Discord.exe", "svchost.exe"):
        assert process.lower() in BENIGN_BULK_PROCESSES


def test_below_connection_floor_does_not_alert(session):
    """Repetition is required: a handful of small transfers is not a beacon."""
    for _ in range(3):
        session.add(_conn("beaconish.exe", "203.0.113.88", 1_000, 500, 300.0))
    session.commit()

    findings = C2BeaconRule(session, min_connections=8).evaluate(60)
    assert findings == []


def test_bulk_threshold_is_far_above_a_normal_transfer(session):
    """The bulk path needs real exfil-scale volume, not 5 MB."""
    assert BULK_BYTES_THRESHOLD >= 100_000_000


def test_powershell_bulk_transfer_is_still_caught(session):
    """The real-exfil case: ~24 MB leaving powershell.exe to an external host.

    Raising the ordinary bulk bar to 250 MB silenced this genuine detection -
    the same volume is benign from a browser but not from an interpreter, so
    interpreters get their own much lower bar and a medium severity.
    """
    for i in range(4):
        session.add(
            _conn(
                "powershell.exe",
                "203.0.113.55",
                4_000_000 + i * 100_000,
                1_000_000 + i * 50_000,
                900.0 + i * 60.0,
            )
        )
    session.commit()

    findings = C2BeaconRule(session).evaluate(60)
    assert len(findings) == 1, "a 24 MB PowerShell exfiltration must be detected"
    assert findings[0].severity == "medium"
    assert "powershell.exe" in findings[0].evidence


def test_powershell_bulk_is_not_suppressed_by_the_benign_list(session):
    """Interpreter traffic is judged on shape, never on the benign-app list."""
    assert "powershell.exe" not in BENIGN_BULK_PROCESSES
    assert "firefox.exe" in BENIGN_BULK_PROCESSES
