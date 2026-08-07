"""Tests for background ML training (non-blocking API behaviour)."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "sentinel-dev-admin"}) as c:
        yield c


def test_ml_train_async_returns_immediately_and_status_reports_training(client):
    resp = client.post("/api/system/ml/train", params={"async_mode": "true", "hours": 24})
    assert resp.status_code == 200
    body = resp.json()
    assert body["scheduled"] is True
    assert body["training"] is True

    # The background job must finish and /ml/status must reflect it.
    deadline = time.time() + 30
    training = True
    while training and time.time() < deadline:
        time.sleep(0.5)
        training = client.get("/api/system/ml/status").json()["training"]
    assert training is False, "background training did not finish within 30s"

    status = client.get("/api/system/ml/status").json()
    assert "training" in status
    assert status["ready"] is not None


def test_ml_train_sync_path(client):
    resp = client.post("/api/system/ml/train", params={"async_mode": "false"})
    assert resp.status_code == 200
    assert resp.json()["status"] in ("ok", "insufficient-data", "not-enough-data", "sklearn-not-installed")