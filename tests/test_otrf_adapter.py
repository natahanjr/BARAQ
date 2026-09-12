"""Integration tests for the OTRF Security-Datasets adapter."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from backend.ml.dataset_adapters.security_datasets import SecurityDatasetsAdapter


@pytest.fixture
def adapter():
    return SecurityDatasetsAdapter()


@pytest.fixture
def sample_ocsf_event():
    return {
        "time": "2021-09-01T12:00:00Z",
        "category_name": "authentication",
        "class_name": "Authentication",
        "activity_id": 1,
        "category_uid": 2,
        "class_uid": 0,
        "user": {"name": "testuser"},
        "source": {"ip": "192.168.1.100"},
        "host": {"name": "WORKSTATION01"},
        "message": "Successful logon",
        "logon_type": 10,
    }


@pytest.fixture
def sample_attack_event():
    return {
        "time": "2021-09-01T12:00:00Z",
        "category_name": "authentication",
        "class_name": "Failed Logon",
        "activity_id": 2,
        "category_uid": 2,
        "user": {"name": "admin"},
        "source": {"ip": "203.0.113.66"},
        "host": {"name": "DC01"},
        "attack": {
            "scenario": "credential_access",
            "technique_id": "T1110",
        },
        "logon_type": 3,
        "Sub_Status": 5,
    }


class TestSecurityDatasetsAdapter:
    def test_parse_event_returns_normalized(self, adapter, sample_ocsf_event):
        result = adapter.parse_event(sample_ocsf_event)
        assert result is not None
        assert result["event_id"] == 4624
        assert result["host"] == "WORKSTATION01"
        assert result["user"] == "testuser"
        assert result["source_ip"] == "192.168.1.100"
        assert result["label"] == 0  # benign

    def test_parse_attack_event(self, adapter, sample_attack_event):
        result = adapter.parse_event(sample_attack_event)
        assert result is not None
        assert result["event_id"] == 4625  # Failed logon
        assert result["label"] == 1  # attack
        assert result["attack_chain"] == "credential_access"

    def test_parse_returns_none_for_invalid(self, adapter):
        assert adapter.parse_event(None) is None
        assert adapter.parse_event("not a dict") is None
        assert adapter.parse_event({}) is None

    def test_iter_events_from_directory(self, adapter):
        with tempfile.TemporaryDirectory() as tmpdir:
            event = {
                "time": "2021-09-01T12:00:00Z",
                "category_name": "process_activity",
                "class_name": "Process Creation",
                "activity_id": 1,
                "user": {"name": "admin"},
                "process": {
                    "executable": "cmd.exe",
                    "command_line": "whoami",
                    "parent_process": "explorer.exe",
                },
            }
            filepath = Path(tmpdir) / "test.json"
            filepath.write_text(json.dumps(event))

            events = list(adapter.iter_events(Path(tmpdir)))
            assert len(events) == 1
            assert events[0]["class_name"] == "Process Creation"

    def test_iter_events_handles_empty_file(self, adapter):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "empty.json"
            filepath.write_text("")
            events = list(adapter.iter_events(Path(tmpdir)))
            assert len(events) == 0

    def test_parse_network_event(self, adapter):
        event = {
            "time": "2021-09-01T12:00:00Z",
            "category_name": "network_activity",
            "class_name": "Network Connection",
            "activity_id": 1,
            "source": {"ip": "10.0.0.1"},
            "destination": {"ip": "8.8.8.8", "port": 443},
            "network": {"transport": "tcp", "bytes": 1024},
        }
        result = adapter.parse_event(event)
        assert result is not None
        assert result["event_id"] == 3
        assert result["source_ip"] == "10.0.0.1"

    def test_parse_csv_event(self, adapter):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_content = (
                "time,category_name,class_name,activity_id,user\n"
                "2021-09-01T12:00:00Z,authentication,Authentication,1,admin\n"
            )
            filepath = Path(tmpdir) / "test.csv"
            filepath.write_text(csv_content)
            events = list(adapter.iter_events(Path(tmpdir)))
            assert len(events) >= 1
