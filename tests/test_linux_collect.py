"""Linux collector record shapes (pure parsing; subprocess mocked)."""
import re
from datetime import datetime, timedelta, timezone

import pytest

from scripts.linux_collect import (
    _ACCEPTED_SSH,
    _FAILED_SSH,
    collect_auth,
    collect_connections,
    collect_processes,
)


@pytest.fixture
def fake_authlog(tmp_path, monkeypatch):
    path = tmp_path / "auth.log"
    content = (
        "Aug  9 10:01:02 box sshd[1234]: Failed password for invalid user root "
        "from 203.0.113.9 port 55314 ssh2\n"
        "Aug  9 10:02:11 box sshd[1234]: Accepted publickey for alice "
        "from 198.51.100.7 port 44322 ssh2\n"
        "Aug  9 10:03:00 box sshd[1234]: Failed password for root "
        "from 198.51.100.50 port 50000 ssh2\n"
    )
    path.write_text(content, encoding="utf-8")
    monkeypatch.setenv("BARAQ_AUTH_LOG", str(path))
    fixed_now = datetime(2026, 8, 9, 10, 5, 0).astimezone()

    class _FixedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            if tz is not None:
                return fixed_now.astimezone(tz)
            return fixed_now

    monkeypatch.setattr("scripts.linux_collect.datetime", _FixedClock)
    return path


def test_auth_failure_regex():
    m = _FAILED_SSH.search(
        "Aug  9 10:01:02 box sshd[1234]: Failed password for invalid user "
        "root from 203.0.113.9 port 55314 ssh2"
    )
    assert m and m.group("user") == "root" and m.group("ip") == "203.0.113.9"
    assert _ACCEPTED_SSH.search("Aug  9 10:02:11 box sshd[1234]: Accepted publickey"
                                " for alice from 198.51.100.7 port 44322 ssh2")


def test_collect_auth_shapes(fake_authlog):
    records = collect_auth()
    failures = [r for r in records if r["event_id"] == 4625]
    successes = [r for r in records if r["event_id"] == 4624]
    assert len(failures) == 2
    assert len(successes) == 1
    assert failures[0]["network"]["source_ip"] == "203.0.113.9"
    assert failures[0]["user"]["name"] == "root"
    assert successes[0]["user"]["name"] == "alice"


def test_collect_connections(monkeypatch):
    out = (
        "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        "ESTAB 0 0 10.0.0.5:54321 203.0.113.44:443 users:((\"curl\",pid=901))\n"
        "ESTAB 0 0 10.0.0.5:54322 198.51.100.3:22 users:((\"ssh\",pid=555))\n"
        "LISTEN 0 0 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1))\n"
    )
    monkeypatch.setattr(
        "scripts.linux_collect._run", lambda cmd, timeout=15: out
    )
    records = collect_connections()
    assert len(records) == 2  # LISTEN skipped
    assert records[0]["event_id"] == 3
    assert records[0]["network"]["remote_ip"] == "203.0.113.44"
    assert records[1]["process"]["name"].startswith("users:")


def test_collect_processes_delta(monkeypatch, tmp_path):
    monkeypatch.setattr("scripts.linux_collect.STATE_DIR", str(tmp_path))
    first = "  1     0 systemd /sbin/init\n  42    1 bash /bin/bash\n"
    second = "  1     0 systemd /sbin/init\n  42    1 bash /bin/bash\n  99    1 ncat /usr/bin/ncat -e /bin/sh\n"
    calls = {"n": 0}

    def fake_run(cmd, timeout=15):
        calls["n"] += 1
        return second if calls["n"] > 1 else first

    monkeypatch.setattr("scripts.linux_collect._run", fake_run)
    r1 = collect_processes()
    assert r1 == []  # first run: baseline, no deltas
    r2 = collect_processes()
    assert len(r2) == 1
    assert r2[0]["event_id"] == 4688
    assert r2[0]["process"]["name"] == "ncat"
    assert "command_line" in r2[0]["process"]