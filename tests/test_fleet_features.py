"""Tests for fleet features."""
from backend.fleet.log_fetch import LogFetchManager, LogFetchRequest
from backend.fleet.config_profiles import ConfigProfileManager


def test_log_fetch_create():
    mgr = LogFetchManager()
    req = mgr.create_request(LogFetchRequest(host_id="host-01", log_type="sysmon"))
    assert req.host_id == "host-01"


def test_log_fetch_complete():
    mgr = LogFetchManager()
    mgr.create_request(LogFetchRequest(host_id="host-01"))
    result = mgr.complete_request("host-01", ["line1", "line2"])
    assert result.total_lines == 2
    assert result.status == "completed"


def test_config_profile_default():
    mgr = ConfigProfileManager()
    profile = mgr.get_profile("default")
    assert profile is not None
    assert "telemetry_interval_seconds" in profile.settings


def test_config_create_and_assign():
    mgr = ConfigProfileManager()
    mgr.create_profile("high_security", {"log_level": "DEBUG"})
    mgr.assign_host("high_security", "PC-01")
    host_profile = mgr.get_host_profile("PC-01")
    assert host_profile.name == "high_security"


def test_config_delete_non_default():
    mgr = ConfigProfileManager()
    mgr.create_profile("temp", {})
    assert mgr.delete_profile("temp") is True
    assert mgr.delete_profile("default") is False
