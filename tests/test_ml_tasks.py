"""Tests for ML training tasks."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from backend.ml.tasks import _bulk_train, training_active


class TestBulkTrain:
    def test_training_active_returns_false_when_not_locked(self):
        """Test that training_active returns False when no training is running."""
        assert training_active() is False

    def test_bulk_train_returns_insufficient_data_with_empty_session(self):
        """Test that bulk_train handles empty data gracefully."""
        mock_session = MagicMock()
        mock_session.execute.return_value.all.return_value = []

        result = _bulk_train(mock_session, hours=24)
        assert result["status"] == "insufficient-data"
        assert result["trained"] is False

    def test_bulk_train_handles_none_raw_json(self):
        """Test that bulk_train handles None raw_json values."""
        mock_session = MagicMock()
        mock_event = MagicMock()
        mock_event.id = 1
        mock_event.event_id = 4624
        mock_event.timestamp = MagicMock()
        mock_event.timestamp.isoformat.return_value = "2021-01-01T00:00:00"
        mock_event.raw_json = None
        mock_event.user = "testuser"

        mock_session.execute.return_value.all.return_value = [mock_event]

        # This should not raise an exception
        result = _bulk_train(mock_session, hours=24)
        assert result["status"] in ("insufficient-data", "ok")

    def test_bulk_train_handles_invalid_json_string(self):
        """Test that bulk_train handles invalid JSON strings gracefully."""
        mock_session = MagicMock()
        mock_event = MagicMock()
        mock_event.id = 1
        mock_event.event_id = 4624
        mock_event.timestamp = MagicMock()
        mock_event.timestamp.isoformat.return_value = "2021-01-01T00:00:00"
        mock_event.raw_json = "not valid json"
        mock_event.user = "testuser"

        mock_session.execute.return_value.all.return_value = [mock_event]

        # This should not raise an exception
        result = _bulk_train(mock_session, hours=24)
        assert result["status"] in ("insufficient-data", "ok")

    def test_bulk_train_handles_dict_raw_json(self):
        """Test that bulk_train handles dict raw_json values."""
        mock_session = MagicMock()
        mock_event = MagicMock()
        mock_event.id = 1
        mock_event.event_id = 4624
        mock_event.timestamp = MagicMock()
        mock_event.timestamp.isoformat.return_value = "2021-01-01T00:00:00"
        mock_event.raw_json = {"facts": {"logon_type": 2}}
        mock_event.user = "testuser"

        mock_session.execute.return_value.all.return_value = [mock_event]

        # This should not raise an exception
        result = _bulk_train(mock_session, hours=24)
        assert result["status"] in ("insufficient-data", "ok")
