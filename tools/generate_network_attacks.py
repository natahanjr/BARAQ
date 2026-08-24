"""Generate REAL network-attack telemetry for ML supervised training.

Why this script exists
----------------------
The ML network-stream supervised classifier only trains when the labelled
window contains remote IPs inside ``_NET_ATTACK_PREFIXES``
(``backend/ml/anomaly.py``: 203.0.113.x / 198.51.100.x TEST-NET ranges).
Without such samples the threshold falls back to the CFAR boundary (~0.97)
and network attacks are never flagged.

This script performs *real* attack techniques - TCP port scanning (T1046)
and periodic C2-style beaconing (T1071) - against RFC 5737 TEST-NET
documentation ranges. These prefixes are reserved for documentation and are
not routable on the internet, so no real host is ever contacted.

Each connection attempt is held in SYN_SENT long enough (Windows TCP
timeout ~21 s) for the 15 s network collector snapshot (psutil
``net_connections``) to observe it, persist a NetworkConnection row, and
feed the per-remote-IP flow buckets the ML model learns from.

Usage
-----
    venv\\Scripts\\python tools\\generate_network_attacks.py [--seconds 240]

The BARAQ server must be running (its scheduler persists the rows). After
the run completes, trigger a retrain:

    POST /api/system/ml/train?force=true&hours=24   (admin API key)
"""
from __future__ import annotations

import argparse
import socket
import time

#: RFC 5737 TEST-NET documentation ranges - labelled *attack* by the ML layer.
SCAN_TARGETS = [
    "203.0.113.7",
    "203.0.113.55",
    "203.0.113.120",
    "198.51.100.9",
    "198.51.100.200",
    "198.51.100.44",
]

#: Ports probed per target - mimics an attacker enumerating services.
SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 9090, 27017,
]

#: C2-style beacon targets: periodic connect attempts on a single port.
BEACON_TARGETS = [
    ("203.0.113.10", 443),
    ("203.0.113.30", 8443),
    ("198.51.100.77", 53),
]

_POLL_CYCLE = 15  # backend collector interval (seconds)


def _hold_syn_sent(targets: list[tuple[str, int]], hold_seconds: float) -> None:
    """Open many sockets to the targets and hold them (SYN_SENT) for a while.

    Non-blocking connects stay in SYN_SENT until the OS retransmit timer
    expires (~21 s on Windows), so every 15 s collector snapshot observes
    them and persists a NetworkConnection row per (target, port).
    """
    socks: list[socket.socket] = []
    for host, port in targets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            s.connect_ex((host, port))
            socks.append(s)
        except OSError:
            continue
    deadline = time.monotonic() + hold_seconds
    try:
        while time.monotonic() < deadline:
            time.sleep(1)
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=240,
                        help="total run duration (default 240)")
    args = parser.parse_args()

    total = args.seconds
    started = time.monotonic()
    round_no = 0

    print(f"BARAQ real network-attack generator (T1046 scan + T1071 beacon)")
    print(f"targets (TEST-NET documentation ranges, non-routable): "
          f"{', '.join(SCAN_TARGETS)}")
    print(f"duration: {total}s; collector polls every {_POLL_CYCLE}s\n")

    while time.monotonic() - started < total:
        round_no += 1
        # Port scan wave: every target x many ports.
        _hold_syn_sent([(h, p) for h in SCAN_TARGETS for p in SCAN_PORTS], _POLL_CYCLE * 2)
        # Beacon wave: periodic single-port check-ins.
        _hold_syn_sent(BEACON_TARGETS, _POLL_CYCLE * 2)
        elapsed = time.monotonic() - started
        print(f"round {round_no}: wave done at {elapsed:.0f}s/{total}s "
              f"({len(SCAN_TARGETS)} scan targets x {len(SCAN_PORTS)} ports + "
              f"{len(BEACON_TARGETS)} beacons)")

    print("\nDone. Attack rows are in the DB; trigger retrain now:")

    print('  POST /api/system/ml/train?force=true&hours=24  (admin key)')


if __name__ == "__main__":
    main()