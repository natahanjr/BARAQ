"""SentinelSOC remote agent - collect and ship telemetry to a central server.

Run on any Windows host (including the server itself) to form a 2-3 host
fleet:

    python scripts/agent.py --server http://central:8000 --key <agent-key> --interval 15

The agent runs the same collector set as the server, stamps every record
with the local hostname, and POSTs it to ``POST /api/ingest``. The server
validates the ``X-Agent-Key`` header, attributes the records to the agent,
and runs the full detection pipeline centrally.
"""
from __future__ import annotations

import argparse
import json
import logging
import socket
import time
import urllib.request

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-7s | %(message)s")
logger = logging.getLogger("sentinel.agent")


def collect() -> list[dict]:
    from backend.collectors import CollectorManager

    host = socket.gethostname()
    records = []
    for record in CollectorManager().collect():
        record["host"] = host
        records.append(record)
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelSOC remote telemetry agent")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="Central SentinelSOC API")
    parser.add_argument("--key", default="sentinel-agent-dev", help="Agent key (X-Agent-Key)")
    parser.add_argument("--interval", type=int, default=15, help="Collection interval (seconds)")
    args = parser.parse_args()

    host = socket.gethostname()
    logger.info("SentinelSOC agent starting (host=%s, server=%s)", host, args.server)
    while True:
        try:
            records = collect()
            if records:
                url = args.server.rstrip("/") + "/api/ingest"
                payload = json.dumps({"records": records, "host": host}).encode("utf-8")
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-Agent-Key": args.key,
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    result = json.loads(resp.read().decode("utf-8"))
                logger.info(
                    "Shipped %d records -> %s alerts",
                    result.get("collected", 0), result.get("alerts_created", 0),
                )
            else:
                logger.debug("No records collected")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Agent cycle failed: %s", exc)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()