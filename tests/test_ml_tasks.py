"""Tests for ML training tasks."""

from __future__ import annotations

from unittest.mock import MagicMock

from backend.ml.tasks import _bulk_train, training_active


def _mock_session(events: list) -> MagicMock:
    """Mock session where only the normalized-event query yields rows.

    ``MLAnomalyDetector.train`` issues several aggregate queries; the mock must
    answer the auxiliary ones with empty result sets instead of replaying the
    event rows (a 7-column NetworkConnection aggregate would otherwise be fed
    event mocks).
    """
    session = MagicMock()

    def _execute(statement, *args, **kwargs):
        result = MagicMock()
        rendered = str(statement)
        if "network_connections" in rendered:
            result.all.return_value = []
        else:
            result.all.return_value = events
        return result

    session.execute.side_effect = _execute
    return session


class TestBulkTrain:
    def test_training_active_returns_false_when_not_locked(self):
        """Test that training_active returns False when no training is running."""
        assert training_active() is False

    def test_bulk_train_returns_insufficient_data_with_empty_session(self):
        """Test that bulk_train handles empty data gracefully."""
        mock_session = _mock_session([])

        result = _bulk_train(mock_session, hours=24)
        assert result["status"] == "insufficient-data"
        assert result["trained"] is False

    def test_bulk_train_handles_none_raw_json(self):
        """Test that bulk_train handles None raw_json values."""
        mock_event = MagicMock()
        mock_event.id = 1
        mock_event.event_id = 4624
        mock_event.timestamp = MagicMock()
        mock_event.timestamp.isoformat.return_value = "2021-01-01T00:00:00"
        mock_event.raw_json = None
        mock_event.user = "testuser"

        mock_session = _mock_session([mock_event])

        # This should not raise an exception
        result = _bulk_train(mock_session, hours=24)
        assert result["status"] in ("insufficient-data", "ok")

    def test_bulk_train_handles_invalid_json_string(self):
        """Test that bulk_train handles invalid JSON strings gracefully."""
        mock_event = MagicMock()
        mock_event.id = 1
        mock_event.event_id = 4624
        mock_event.timestamp = MagicMock()
        mock_event.timestamp.isoformat.return_value = "2021-01-01T00:00:00"
        mock_event.raw_json = "not valid json"
        mock_event.user = "testuser"

        mock_session = _mock_session([mock_event])

        # This should not raise an exception
        result = _bulk_train(mock_session, hours=24)
        assert result["status"] in ("insufficient-data", "ok")

    def test_bulk_train_handles_dict_raw_json(self):
        """Test that bulk_train handles dict raw_json values."""
        mock_event = MagicMock()
        mock_event.id = 1
        mock_event.event_id = 4624
        mock_event.timestamp = MagicMock()
        mock_event.timestamp.isoformat.return_value = "2021-01-01T00:00:00"
        mock_event.raw_json = {"facts": {"logon_type": 2}}
        mock_event.user = "testuser"

        mock_session = _mock_session([mock_event])

        # This should not raise an exception
        result = _bulk_train(mock_session, hours=24)
        assert result["status"] in ("insufficient-data", "ok")
