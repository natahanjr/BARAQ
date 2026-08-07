"""Tests for the tamper-evident audit hash chain (backend.audit)."""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import sessionmaker

from backend.audit import log_action, verify_chain
from backend.database.models import AuditLog, Base


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def test_chain_grows_and_verifies(db):
    for i in range(3):
        log_action(db, "admin", f"test.action{i}", "user", str(i), f"detail {i}", "127.0.0.1")
    result = verify_chain(db)
    assert result["ok"] is True
    assert result["checked"] == 3
    rows = db.query(AuditLog).order_by(AuditLog.id).all()
    assert rows[0].prev_hash == "0" * 64
    assert rows[1].prev_hash == rows[0].hash
    assert rows[2].prev_hash == rows[1].hash
    assert all(r.hash and len(r.hash) == 64 for r in rows)


def test_tampering_detected(db):
    log_action(db, "admin", "create", "user", "1", "original", "127.0.0.1")
    log_action(db, "admin", "update", "user", "2", "second", "127.0.0.1")
    # Attacker edits a historical detail.
    victim = db.query(AuditLog).filter(AuditLog.action == "create").first()
    victim.detail = "tampered!"
    db.commit()
    result = verify_chain(db)
    assert result["ok"] is False
    assert result["broken_at"] == victim.id  # the tampered entry itself breaks


def test_deletion_detected(db):
    for i in range(3):
        log_action(db, "admin", f"del.test{i}", "user", str(i), f"d{i}", "127.0.0.1")
    # Delete the middle entry.
    db.execute(delete(AuditLog).where(AuditLog.action == "del.test1"))
    db.commit()
    result = verify_chain(db)
    assert result["ok"] is False
    assert result["broken_at"] is not None


def test_empty_chain_is_valid(db):
    result = verify_chain(db)
    assert result["ok"] is True
    assert result["checked"] == 0


def test_genesis_prev_hash(db):
    entry = log_action(db, "root", "bootstrap", "system", "", "first ever", "::1")
    assert entry is not None
    assert entry.prev_hash == "0" * 64
